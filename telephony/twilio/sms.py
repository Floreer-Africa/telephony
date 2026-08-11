import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import now_datetime

from telephony.otp import create_otp_record, generate_otp_code, verify_otp_record

from .twilio_handler import Twilio

SMS_ALLOWED_ROLES = {"System Manager", "TP Manager", "TP Agent"}


def clean_phone_number(phone_number: str) -> str:
    """Strip everything except digits and a leading `+`."""
    phone_number = (phone_number or "").strip()
    return "".join(c for c in phone_number if c.isdigit() or c == "+")


def get_sms_settings():
    settings = frappe.get_cached_doc("TP SMS Settings")
    if not settings.enabled:
        frappe.throw(_("Please enable TP SMS Settings to send SMS."))
    return settings


def create_sms_log(to, from_number, message, purpose, status, sid=None, error=None):
    log = frappe.get_doc(
        {
            "doctype": "TP SMS Log",
            "to": to,
            "from": from_number,
            "message": message,
            "purpose": purpose,
            "status": status,
            "sid": sid,
            "error": error,
            "sent_by": frappe.session.user if frappe.session.user != "Guest" else None,
            "sent_at": now_datetime(),
        }
    )
    log.insert(ignore_permissions=True)
    frappe.db.commit()  # nosemgrep
    return log


def dispatch_sms(to, message, purpose="General"):
    """Send an SMS via Twilio and log the result."""
    settings = get_sms_settings()
    twilio = Twilio.connect()
    if not twilio:
        frappe.throw(_("Please enable and configure TP Twilio Settings to send SMS."))

    to = clean_phone_number(to)
    from_number = settings.sms_from_number

    try:
        message_obj = twilio.twilio_client.messages.create(
            to=to, from_=from_number, body=message
        )
    except Exception as e:
        create_sms_log(to, from_number, message, purpose, "Failed", error=str(e))
        frappe.log_error(title=_("Failed to send SMS via Twilio"))
        frappe.throw(_("Failed to send SMS: {0}").format(str(e)))

    return create_sms_log(
        to, from_number, message, purpose, "Sent", sid=message_obj.sid
    )


@frappe.whitelist(methods=["POST"])
def send_sms(to: str, message: str):
    """Send a plain SMS. Restricted to telephony agents/managers."""
    if not SMS_ALLOWED_ROLES & set(frappe.get_roles()):
        frappe.throw(_("Not permitted"), frappe.PermissionError)

    log = dispatch_sms(to, message, purpose="General")
    return {"name": log.name, "status": log.status}


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@rate_limit(key="phone_number", limit=5, seconds=10 * 60)
def generate_otp(phone_number: str, purpose: str = "Verification"):
    """Generate an OTP and send it over SMS to the given phone number."""
    settings = get_sms_settings()
    phone_number = clean_phone_number(phone_number)
    if not phone_number:
        frappe.throw(_("Please provide a valid phone number."))

    otp = generate_otp_code(settings.otp_length or 6)
    expiry_seconds = settings.otp_expiry_in_seconds or 300

    template = (
        settings.otp_message_template
        or "Your OTP is {otp}. It is valid for {expiry_minutes} minutes."
    )
    message = template.format(otp=otp, expiry_minutes=max(1, expiry_seconds // 60))

    log = dispatch_sms(phone_number, message, purpose="OTP")
    create_otp_record(
        phone_number, "SMS", purpose, otp, expiry_seconds, notification_log=log.name
    )

    response = {"sent": True, "expires_in": expiry_seconds}
    if frappe.conf.developer_mode:
        response["otp"] = otp
    return response


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@rate_limit(key="phone_number", limit=10, seconds=10 * 60)
def verify_otp(phone_number: str, otp: str, purpose: str = "Verification"):
    """Verify an OTP previously sent to the given phone number."""
    settings = get_sms_settings()
    phone_number = clean_phone_number(phone_number)
    return verify_otp_record(
        phone_number, "SMS", otp, purpose, settings.otp_max_attempts or 5
    )
