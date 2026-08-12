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


def generate_otp_code(length: int) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


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


def normalize_form_field(field, normalizer):
    """Canonicalize ``field`` in ``form_dict`` before the rate limiter reads it.

    ``frappe.rate_limit`` derives its bucket from ``frappe.form_dict[key]``
    verbatim, so without this ``+911234500001``, ``+91 1234500001`` and
    ``+91-1234500001`` are three separate buckets for one recipient — which
    makes the send cap bypassable with a formatting loop.

    Must be applied *above* ``@rate_limit`` so it runs first.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            raw = frappe.form_dict.get(field)
            if raw:
                frappe.form_dict[field] = normalizer(raw)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def consume_pending_otps(recipient, channel, purpose) -> int:
    """Expire outstanding OTPs for this recipient and return attempts already
    spent against them.

    ``verify_otp_record`` only ever reads the newest unverified row, and
    ``attempts`` lives on that row. Without carrying the count forward, each
    ``generate_otp`` call would hand out a fresh ``otp_max_attempts`` budget
    against the same short code space. Carrying forward only from *live* rows
    means the budget still resets naturally once the window lapses.
    """
    pending = frappe.get_all(
        OTP_DOCTYPE,
        filters={
            "recipient": recipient,
            "channel": channel,
            "purpose": purpose,
            "is_verified": 0,
            "expires_at": (">", now_datetime()),
        },
        fields=["name", "attempts"],
    )
    if not pending:
        return 0

    already_expired = add_to_date(now_datetime(), seconds=-1)
    for row in pending:
        # Expired rather than deleted — the row is an audit record.
        frappe.db.set_value(
            OTP_DOCTYPE, row.name, "expires_at", already_expired, update_modified=False
        )

    return sum(row.attempts or 0 for row in pending)


def create_otp_record(
    recipient, channel, purpose, otp, expiry_seconds, notification_log=None
):
    from passlib.hash import pbkdf2_sha256

    spent_attempts = consume_pending_otps(recipient, channel, purpose)

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
        return dict(GENERIC_FAILURE)

    # Locked: reading and incrementing `attempts` is a read-modify-write, so
    # concurrent verifies would otherwise share a stale count and collectively
    # exceed otp_max_attempts.
    otp_doc = frappe.get_doc(OTP_DOCTYPE, otp_name, for_update=True)

    if get_datetime(otp_doc.expires_at) < now_datetime():
        return dict(GENERIC_FAILURE)

    if otp_doc.attempts >= max_attempts:
        return dict(GENERIC_FAILURE)

    if not pbkdf2_sha256.verify(otp, otp_doc.otp_hash):
        otp_doc.attempts += 1
        otp_doc.save(ignore_permissions=True)
        return dict(GENERIC_FAILURE)

    otp_doc.is_verified = 1
    otp_doc.verified_at = now_datetime()
    otp_doc.save(ignore_permissions=True)

    return {"verified": True}
