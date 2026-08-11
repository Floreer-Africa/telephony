import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import validate_email_address

from telephony.otp import create_otp_record, generate_otp_code, verify_otp_record


def get_email_otp_settings():
    settings = frappe.get_cached_doc("TP SMS Settings")
    if not settings.enable_email_otp:
        frappe.throw(_("Please enable Email OTP in TP SMS Settings."))
    return settings


def dispatch_email_otp(email, message, subject):
    frappe.sendmail(recipients=[email], subject=subject, message=message)


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(key="email", limit=5, seconds=10 * 60)
def generate_otp(email: str, purpose: str = "Verification"):
    """Generate an OTP and send it over email to the given address."""
    settings = get_email_otp_settings()
    email = validate_email_address(email, throw=True)

    otp = generate_otp_code(settings.otp_length or 6)
    expiry_seconds = settings.otp_expiry_in_seconds or 300

    template = (
        settings.otp_message_template
        or "Your OTP is {otp}. It is valid for {expiry_minutes} minutes."
    )
    message = template.format(otp=otp, expiry_minutes=max(1, expiry_seconds // 60))
    subject = settings.email_otp_subject or "Your verification code"

    dispatch_email_otp(email, message, subject)
    create_otp_record(email, "Email", purpose, otp, expiry_seconds)

    response = {"sent": True, "expires_in": expiry_seconds}
    if frappe.conf.developer_mode:
        response["otp"] = otp
    return response


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(key="email", limit=10, seconds=10 * 60)
def verify_otp(email: str, otp: str, purpose: str = "Verification"):
    """Verify an OTP previously sent to the given email address."""
    settings = get_email_otp_settings()
    email = validate_email_address(email, throw=True)
    return verify_otp_record(
        email, "Email", otp, purpose, settings.otp_max_attempts or 5
    )
