import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import now_datetime

from telephony.otp import (
    clean_purpose,
    create_otp_record,
    generate_otp_code,
    normalize_form_field,
    verify_otp_record,
)

from .twilio_handler import Twilio

# TP SMS Log is readable by TP Agent and retained for 90 days, so writing the
# rendered OTP body there would undo hashing the code in TP OTP. Keep the
# routing metadata (to/from/sid/status) and drop the body.
REDACTED_MESSAGE = "[redacted]"

# Named savepoint for the send attempt, so the failure path can discard its own
# partial work without touching writes the caller made before calling in.
SEND_SAVEPOINT = "tp_dispatch_sms"

ASCII_DIGITS = frozenset("0123456789")

# Stand-in for "no cap" when send_sms_rate_limit_per_hour is explicitly 0.
UNLIMITED_SENDS = 10**9

# Mirrors the field default, for sites whose settings have never been saved.
DEFAULT_SEND_SMS_LIMIT = 60


def clean_phone_number(phone_number: str) -> str:
    """Canonicalize to a single E.164-shaped string: ``+`` then ASCII digits.

    Every spelling of one number has to collapse to one string, because this
    value is both the ``TP OTP.recipient`` lookup key and the rate-limit
    bucket. Keeping the caller's ``+`` verbatim was not enough: ``91…`` and
    ``+91…`` stayed distinct, so one number still had two OTP rows and two
    quotas. Digits are extracted and a single ``+`` is re-attached, so all of
    ``+91 79-7739 6938``, ``917977396938`` and ``+917977396938`` agree.

    Deliberately not ``str.isdigit()``: that is true for non-ASCII digits
    (fullwidth ``０-９``, Arabic-Indic ``٠-٩``, …), which would survive as a
    distinct Python string while MariaDB's default ``utf8mb4_unicode_ci``
    collation compares them equal to their ASCII form — letting a caller land
    on another recipient's row while holding a rate-limit bucket of their own.

    No country code is inferred: telephony is a library and the caller's
    dialling context is unknown, so a national-format number stays national
    and Twilio rejects it, exactly as before.
    """
    digits = "".join(c for c in (phone_number or "") if c in ASCII_DIGITS)
    # "" rather than a bare "+", so the emptiness checks downstream still fire.
    return f"+{digits}" if digits else ""


def get_sms_settings():
    settings = frappe.get_cached_doc("TP OTP Settings")
    if not settings.enabled:
        frappe.throw(_("Please enable SMS in TP OTP Settings to send SMS."))
    return settings


def create_sms_log(to, from_number, message, purpose, status, sid=None, error=None):
    log = frappe.get_doc(
        {
            "doctype": "TP SMS Log",
            "to": to,
            "from": from_number,
            "message": REDACTED_MESSAGE if purpose == "OTP" else message,
            "purpose": purpose,
            "status": status,
            "sid": sid,
            "error": error,
            "sent_by": frappe.session.user if frappe.session.user != "Guest" else None,
            "sent_at": now_datetime(),
        }
    )
    log.insert(ignore_permissions=True)
    return log


def dispatch_sms(to, message, purpose="General"):
    """Send an SMS via Twilio and log the result."""
    settings = get_sms_settings()
    # NOTE: Twilio.connect() re-reads TP Twilio Settings uncached and decrypts
    # api_secret on every call — one extra query plus a KDF per SMS.
    twilio = Twilio.connect()
    if not twilio:
        frappe.throw(_("Please enable and configure TP Twilio Settings to send SMS."))

    to = clean_phone_number(to)
    from_number = settings.sms_from_number

    # Scoped to a savepoint so the failure path below can discard its own
    # partial work without rolling back whatever the caller had already done.
    frappe.db.savepoint(SEND_SAVEPOINT)

    try:
        message_obj = twilio.twilio_client.messages.create(
            to=to, from_=from_number, body=message
        )
    except Exception as e:
        # The Failed row is the audit trail for this attempt, and it has to
        # outlive the exception below — so commit it deliberately, after
        # undoing anything this function itself wrote.
        frappe.db.rollback(save_point=SEND_SAVEPOINT)
        create_sms_log(to, from_number, message, purpose, "Failed", error=str(e))
        # Pass an explicit message: with none, log_error falls back to
        # get_traceback(with_context=True), which renders every frame's locals
        # into Error Log — including `message`, the rendered OTP body. That
        # would leak in cleartext exactly what create_sms_log just redacted.
        frappe.log_error(
            title="Failed to send SMS via Twilio",
            message=f"to={to} error={type(e).__name__}: {e}",
        )
        frappe.db.commit()  # nosemgrep: deliberate, see comment above
        # The raw Twilio error carries account SIDs, the configured from-number
        # and endpoint URLs; generate_otp is guest-callable, so keep it out.
        frappe.throw(_("Could not send the SMS. Please try again later."))

    frappe.db.release_savepoint(SEND_SAVEPOINT)

    return create_sms_log(
        to, from_number, message, purpose, "Sent", sid=message_obj.sid
    )


def get_send_sms_limit():
    """Per-hour cap for send_sms, read at request time.

    A hardcoded number would either be too low for a site doing bulk
    notifications or too high to protect the Twilio balance of one that isn't,
    so this is configurable, with 0 meaning no limit. ``rate_limit`` accepts a
    callable for exactly this.
    """
    limit = frappe.get_cached_value(
        "TP OTP Settings", "TP OTP Settings", "send_sms_rate_limit_per_hour"
    )

    # None is not 0. A Single holds no value for a field until the doc is first
    # saved, so on an existing site this reads None until someone opens the
    # form — treating that as "unlimited" would silently leave every such site
    # uncapped. Only an explicit 0 opts out.
    if limit is None:
        return DEFAULT_SEND_SMS_LIMIT

    # The limiter has no "unlimited", so use a ceiling no single client will
    # reach within one window.
    return limit or UNLIMITED_SENDS


@frappe.whitelist(methods=["POST"])
@rate_limit(limit=get_send_sms_limit, seconds=60 * 60)
def send_sms(to: str, message: str):
    """Send a plain SMS. Restricted to telephony agents/managers.

    Unlike the OTP endpoints this is rate limited per client rather than per
    recipient: the risk here is total spend on arbitrary numbers, not repeated
    hammering of one number.
    """
    # Defer to the DocType's permissions so the role set stays configurable.
    frappe.has_permission("TP SMS Log", "create", throw=True)

    log = dispatch_sms(to, message, purpose="General")
    return {"name": log.name, "status": log.status}


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@normalize_form_field("phone_number", clean_phone_number)
@rate_limit(key="phone_number", limit=5, seconds=10 * 60)
def generate_otp(phone_number: str, purpose: str = "Verification"):
    """Generate an OTP and send it over SMS to the given phone number."""
    settings = get_sms_settings()
    phone_number = clean_phone_number(phone_number)
    if not phone_number:
        frappe.throw(_("Please provide a valid phone number."))

    purpose = clean_purpose(purpose)
    otp = generate_otp_code(settings.otp_length)
    expiry_seconds = settings.otp_expiry_in_seconds

    message = settings.otp_message_template.format(
        otp=otp, expiry_minutes=max(1, expiry_seconds // 60)
    )

    # Record first, so a user can never hold a code with no record to verify
    # against. Note the failure path in dispatch_sms commits its Failed audit
    # row, which persists this record too; it is unusable and expires on its
    # own, which is the safer direction to fail in.
    otp_doc = create_otp_record(phone_number, "SMS", purpose, otp, expiry_seconds)
    log = dispatch_sms(phone_number, message, purpose="OTP")
    otp_doc.db_set("notification_log", log.name, update_modified=False)

    return {"sent": True, "expires_in": expiry_seconds}


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@normalize_form_field("phone_number", clean_phone_number)
@rate_limit(key="phone_number", limit=10, seconds=10 * 60)
def verify_otp(phone_number: str, otp: str, purpose: str = "Verification"):
    """Verify an OTP previously sent to the given phone number."""
    settings = get_sms_settings()
    phone_number = clean_phone_number(phone_number)
    if not phone_number:
        frappe.throw(_("Please provide a valid phone number."))

    return verify_otp_record(
        phone_number, "SMS", otp, clean_purpose(purpose), settings.otp_max_attempts
    )
