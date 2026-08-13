import secrets
import string
from functools import wraps

import frappe
from frappe import _
from frappe.utils import add_to_date, get_datetime, now_datetime

OTP_DOCTYPE = "TP OTP"

MAX_PURPOSE_LENGTH = 140

# Guest-facing verification failures are deliberately indistinguishable from
# one another. Reporting "no such OTP" separately from "wrong code" lets an
# unauthenticated caller enumerate which recipients have a pending OTP and
# what state it is in.
GENERIC_FAILURE = {"verified": False, "reason": "invalid_or_expired"}

# The form_dict field @rate_limit is pointed at. Always overwritten, never read
# from the request, so a caller cannot nominate their own bucket.
RATE_LIMIT_FIELD = "tp_rate_limit_key"

# The caps themselves live here rather than at each decorator, because
# rate_limit_bucket has to enforce the same numbers itself off the request path
# (see there). Declared once so the two enforcement points cannot drift apart.
GENERATE_LIMIT = 5
VERIFY_LIMIT = 10
RATE_LIMIT_WINDOW = 10 * 60

# Bucket for any recipient that could not be canonicalized. Neither a valid
# phone number nor a valid email address, so it can never collide with a real
# recipient's quota; parking every unusable spelling in one shared bucket is
# what stops a caller from minting fresh quota by varying the garbage.
INVALID_RECIPIENT = "invalid"

# The channels an OTP can be delivered over, and where each one's endpoints
# live. Keys are the values stored in TP OTP.channel, so they are also what
# other apps name a channel by.
OTP_CHANNELS = {
    "SMS": {"module": "telephony.twilio.sms", "recipient_field": "phone_number"},
    "Email": {"module": "telephony.email_otp", "recipient_field": "email"},
}


_DUMMY_HASH = None


def generate_otp_code(length: int) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def equalize_verify_cost():
    """Spend a KDF round on the paths that never reach a real comparison.

    GENERIC_FAILURE makes every failure look alike in the *body*, but not in
    the clock: only the wrong-code path runs pbkdf2 (~29k rounds), so without
    this a guest can tell "no live OTP for this recipient" from "there is one"
    purely by response latency — recovering what the generic reason hides.

    This does not make verification constant-time: the wrong-code path also
    writes the incremented attempt count, which the others do not. It closes
    the KDF-sized gap, which is the part big enough to measure over a network.
    """
    global _DUMMY_HASH

    from passlib.hash import pbkdf2_sha256

    if _DUMMY_HASH is None:
        _DUMMY_HASH = pbkdf2_sha256.hash("timing-equalizer")

    pbkdf2_sha256.verify("", _DUMMY_HASH)


def clean_purpose(purpose: str) -> str:
    """Purpose is caller-supplied and used as a query filter, so bound it."""
    purpose = (purpose or "").strip() or "Verification"
    if len(purpose) > MAX_PURPOSE_LENGTH:
        frappe.throw(
            _("Purpose cannot be longer than {0} characters.").format(
                MAX_PURPOSE_LENGTH
            )
        )
    return purpose


def enforce_rate_limit(bucket, limit, seconds):
    """Apply the cap ``@rate_limit`` skips when there is no HTTP request.

    ``frappe.rate_limiter.rate_limit`` returns early unless ``frappe.request``
    is set, so on a background job, the scheduler or a bench console the
    decorator is inert and the endpoint runs uncapped. That was harmless while
    the endpoints were reachable only over HTTP, but ``send_otp`` / ``verify_otp``
    are called from server code — a queued job is the natural place for an app
    to dispatch OTPs, and it is exactly where the cap would have vanished.

    Counted in its own ``tp-otp-rl:`` namespace rather than the decorator's
    ``rl:``. The two never both run for one call (this one only fires when the
    decorator declines to), and sharing a key would mean reproducing frappe's
    internal key format, which is not ours to depend on.

    ``make_key`` prefixes the site, so the counter is per-site like every other
    cache entry. The window is opened by the increment that creates the key
    rather than by a read-then-write: two callers arriving together would both
    see no key and both reset it, handing out an extra window each time.
    """
    key = frappe.cache.make_key(f"tp-otp-rl:{bucket}:{seconds}")

    count = frappe.cache.incrby(key, 1)
    if count == 1:
        frappe.cache.expire(key, seconds)

    if count > limit:
        frappe.throw(
            _(
                "You hit the rate limit because of too many requests."
                " Please try after sometime."
            ),
            frappe.RateLimitExceededError,
        )


def rate_limit_bucket(field, normalizer, scope, limit, seconds):
    """Publish a canonical, endpoint-scoped rate-limit key into ``form_dict``.

    ``@rate_limit`` cannot be pointed straight at the caller's field, for two
    independent reasons:

    1. It buckets on ``frappe.form_dict[key]`` verbatim, so ``+911234500001``,
       ``+91 1234500001`` and ``+91-1234500001`` are three buckets for one
       recipient — a formatting loop would walk straight past the send cap.
    2. Its cache key is ``rl:{form_dict.cmd}:{identity}:{seconds}``, and only
       ``/api/v1`` populates ``cmd``. Over ``/api/v2`` it renders as ``None``,
       so two endpoints sharing a key field and a window collide on a single
       counter — failed verifies would eat the resend quota and vice versa.

    So normalize the value, qualify it with a per-endpoint ``scope``, and point
    ``@rate_limit`` at the field written here instead of at the raw one.

    ``normalizer`` runs on unvalidated input and must not throw. Anything it
    cannot canonicalize lands in the shared ``INVALID_RECIPIENT`` bucket — the
    endpoint's own validation rejects it a moment later, and the limiter still
    has a non-empty key to work with (with ``ip_based=False`` an empty one makes
    ``rate_limit`` throw its own "Either key or IP flag is required" instead).

    The value is coerced to ``str`` first. The normalizers open on ``.strip()``,
    and form_dict does not always hold strings: a JSON request body preserves
    types, and ``call_channel_endpoint`` writes whatever its caller passed. An
    ``int`` phone number would otherwise raise ``AttributeError`` out of a
    decorator documented as never throwing, before the endpoint's own validation
    could reject it cleanly.

    ``limit`` and ``seconds`` must match the ``@rate_limit`` below it, because
    this enforces them itself on the paths that decorator opts out of — see
    ``enforce_rate_limit``. Both read the module-level constants so they move
    together.

    Must be applied *above* ``@rate_limit`` so it runs first.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            normalized = normalizer(frappe.cstr(frappe.form_dict.get(field)))
            # Only rewrite the caller's field if they actually sent it; the
            # bucket is set unconditionally so the limiter is never keyless.
            if field in frappe.form_dict:
                frappe.form_dict[field] = normalized
            bucket = f"{scope}:{normalized or INVALID_RECIPIENT}"
            frappe.form_dict[RATE_LIMIT_FIELD] = bucket

            # @rate_limit below is inert without a request, so stand in for it.
            if not frappe.request:
                enforce_rate_limit(bucket, limit, seconds)

            return fn(*args, **kwargs)

        return wrapper

    return decorator


def consume_pending_otps(recipient, channel, purpose, max_attempts) -> int:
    """Expire outstanding OTPs for this recipient and return attempts already
    spent against them.

    ``verify_otp_record`` only ever reads the newest unverified row, and
    ``attempts`` lives on that row. Without carrying the count forward, each
    ``generate_otp`` call would hand out a fresh ``otp_max_attempts`` budget
    against the same short code space. Carrying forward only from *live* rows
    means the budget still resets naturally once the window lapses.

    Once that carried budget is spent, refuse rather than issue another code.
    The new row would start at the cap *and* carry a fresh ``expires_at``, so
    each resend pushed the lockout a full window further out while billing for
    a code that could never verify — a user who responds to being locked out by
    retrying, which is the normal response, kept themselves locked out forever.
    Refusing leaves the live row's expiry untouched, so the lockout drains on
    its own no matter how often it is retried.

    This does make "locked out" distinguishable from "not", unlike the uniform
    GENERIC_FAILURE on the verify side. That is accepted: reaching this state
    requires ``max_attempts`` failed verifies against a live OTP, which a caller
    can only arrange for a recipient they are already able to target, so it
    reveals nothing they could not have caused themselves.
    """
    # Locked, like the read in verify_otp_record and for the same reason: this
    # is a read-modify-write. Two concurrent generates — a double-tapped "resend"
    # — would otherwise both read the same live rows, both expire them and both
    # insert, leaving two live OTPs. verify_otp_record only ever reads the newest,
    # so the code the user was told about first could never verify, while still
    # spending the newer row's attempt budget.
    # Through the query builder rather than frappe.get_all, which has no way to
    # ask for the lock.
    otp = frappe.qb.DocType(OTP_DOCTYPE)
    pending = (
        frappe.qb.from_(otp)
        .select(otp.name, otp.attempts)
        .where(
            (otp.recipient == recipient)
            & (otp.channel == channel)
            & (otp.purpose == purpose)
            & (otp.is_verified == 0)
            & (otp.expires_at > now_datetime())
        )
        .for_update()
        .run(as_dict=True)
    )
    if not pending:
        return 0

    spent_attempts = sum(row.attempts or 0 for row in pending)
    if spent_attempts >= max_attempts:
        frappe.throw(
            _("Too many incorrect attempts. Please try again later."),
            frappe.ValidationError,
        )

    already_expired = add_to_date(now_datetime(), seconds=-1)
    for row in pending:
        # Expired rather than deleted — the row is an audit record.
        frappe.db.set_value(
            OTP_DOCTYPE, row.name, "expires_at", already_expired, update_modified=False
        )

    return spent_attempts


def create_otp_record(
    recipient,
    channel,
    purpose,
    otp,
    expiry_seconds,
    max_attempts,
    notification_log=None,
):
    from passlib.hash import pbkdf2_sha256

    spent_attempts = consume_pending_otps(recipient, channel, purpose, max_attempts)

    doc = frappe.get_doc(
        {
            "doctype": OTP_DOCTYPE,
            "recipient": recipient,
            "channel": channel,
            "purpose": purpose,
            "otp_hash": pbkdf2_sha256.hash(otp),
            "attempts": spent_attempts,
            "expires_at": add_to_date(now_datetime(), seconds=expiry_seconds),
            "notification_log": notification_log,
        }
    )
    doc.insert(ignore_permissions=True)
    return doc


def verify_otp_record(recipient, channel, otp, purpose, max_attempts):
    from passlib.hash import pbkdf2_sha256

    otp_name = frappe.db.get_value(
        OTP_DOCTYPE,
        {
            "recipient": recipient,
            "channel": channel,
            "purpose": purpose,
            "is_verified": 0,
        },
        "name",
        order_by="creation desc",
    )
    if not otp_name:
        equalize_verify_cost()
        return dict(GENERIC_FAILURE)

    # Locked: reading and incrementing `attempts` is a read-modify-write, so
    # concurrent verifies would otherwise share a stale count and collectively
    # exceed otp_max_attempts.
    otp_doc = frappe.get_doc(OTP_DOCTYPE, otp_name, for_update=True)

    if get_datetime(otp_doc.expires_at) < now_datetime():
        equalize_verify_cost()
        return dict(GENERIC_FAILURE)

    if otp_doc.attempts >= max_attempts:
        equalize_verify_cost()
        return dict(GENERIC_FAILURE)

    if not pbkdf2_sha256.verify(otp, otp_doc.otp_hash):
        otp_doc.attempts += 1
        otp_doc.save(ignore_permissions=True)
        return dict(GENERIC_FAILURE)

    otp_doc.is_verified = 1
    otp_doc.verified_at = now_datetime()
    otp_doc.save(ignore_permissions=True)

    return {"verified": True}


# --- Entry points for other apps ------------------------------------------
#
# telephony.email_otp and telephony.twilio.sms are the *HTTP* API: one module
# per channel, each whitelisted, guest-callable and keyed on its own recipient
# field. An app that verifies a recipient as part of its own document flow has
# a channel and a recipient rather than a request — and has already run its own
# permission checks — so it calls send_otp / verify_otp below instead of
# reaching into a channel module directly.


def get_otp_channel(channel: str) -> dict:
    """Resolve a channel name against OTP_CHANNELS.

    The name selects a module to import, and callers pass it straight through
    from their own request handlers, so it is never taken on trust.
    """
    if channel not in OTP_CHANNELS:
        frappe.throw(
            _("{0} is not a supported OTP channel. Use one of: {1}.").format(
                channel, ", ".join(OTP_CHANNELS)
            )
        )

    return OTP_CHANNELS[channel]


def call_channel_endpoint(channel: str, method: str, recipient: str, **kwargs):
    """Call a channel's OTP endpoint the way an HTTP request to it would.

    Those endpoints take their per-recipient rate-limit bucket from
    ``frappe.form_dict[recipient_field]`` (see ``rate_limit_bucket``), which a
    server-side caller has no reason to have populated. Left unset it
    normalizes to ``""``, so every recipient would land in the shared
    ``INVALID_RECIPIENT`` bucket and share a single site-wide
    5-per-10-minutes counter: the first five sends in a window would lock out
    every other recipient, and no recipient would be capped on their own.

    So publish the recipient there first, exactly as the request parser would,
    and let the endpoint's own normalizer canonicalize it in place.

    Both keys are then put back the way they were found. form_dict belongs to
    the caller's request, and this is borrowing it:

    - Frappe writes the whole of form_dict into Error Log metadata on any
      unhandled exception (``get_error_metadata``), redacting only keys that
      look like credentials — ``email`` and ``phone_number`` are not among them.
      A caller whose own request never carried the recipient (lending posts a
      Loan Lead name and a medium, nothing more) would otherwise have that
      lead's email address or phone number persisted to Error Log by any later,
      unrelated failure in the same request.
    - Anything downstream that reads ``form_dict[field]`` — including the
      caller's own parameter of that name — would otherwise see the OTP
      recipient in place of what the request actually sent.

    Resolved through ``frappe.get_attr`` at call time rather than imported at
    module scope, because the channel modules import this one.
    """
    config = get_otp_channel(channel)
    field = config["recipient_field"]
    endpoint = frappe.get_attr(f"{config['module']}.{method}")

    borrowed = {}
    for key in (field, RATE_LIMIT_FIELD):
        if key in frappe.form_dict:
            borrowed[key] = frappe.form_dict[key]

    frappe.form_dict[field] = recipient
    try:
        return endpoint(**{field: recipient}, **kwargs)
    finally:
        for key in (field, RATE_LIMIT_FIELD):
            if key in borrowed:
                frappe.form_dict[key] = borrowed[key]
            else:
                frappe.form_dict.pop(key, None)


def send_otp(recipient: str, channel: str, purpose: str = "Verification") -> dict:
    """Generate an OTP and deliver it to ``recipient`` over ``channel``.

    Returns ``{"sent": True, "expires_in": <seconds>}``. Raises if the channel
    is not supported or is switched off in TP OTP Settings, the recipient is
    unusable, the attempt budget for an outstanding code is already spent, the
    rate limit is hit, or delivery fails — the code itself is never returned, on
    any path. There is no falsy return: either it sent, or it raised.

    ``purpose`` scopes the OTP: a code is only ever matched against the
    recipient, channel and purpose it was issued for. Callers verifying a
    specific record should name it in the purpose, otherwise a code issued for
    one record verifies any other record sharing that recipient.
    """
    return call_channel_endpoint(channel, "generate_otp", recipient, purpose=purpose)


def verify_otp(
    recipient: str, channel: str, otp: str, purpose: str = "Verification"
) -> dict:
    """Verify an OTP previously sent to ``recipient`` over ``channel``.

    Returns ``{"verified": True}``, or ``GENERIC_FAILURE`` for a code that is
    wrong, expired, already used, out of attempts or never issued — the reason
    is deliberately uniform, see the note on ``GENERIC_FAILURE``.

    A wrong code is a return value, not an exception, and callers must keep it
    that way: the failed attempt is recorded against the OTP, and that count is
    what enforces ``otp_max_attempts``. Raising on the result would roll the
    increment back with the rest of the request and leave the cap toothless.

    A *failed verification* is the only thing that comes back as a value. The
    call still raises for anything that is not an attempt at all: an unsupported
    channel, a channel switched off in TP OTP Settings, a recipient that is not
    a usable address or number, or the rate limit. Callers must handle both —
    treating a raise as "wrong code" reports a misconfigured channel to the user
    as a failed OTP.
    """
    return call_channel_endpoint(
        channel, "verify_otp", recipient, otp=otp, purpose=purpose
    )
