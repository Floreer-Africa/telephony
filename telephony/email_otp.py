import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import split_emails, validate_email_address

from telephony.otp import (
    clean_purpose,
    create_otp_record,
    generate_otp_code,
    normalize_form_field,
    verify_otp_record,
)


def clean_email(email: str) -> str:
    """Canonicalize for storage *and* for rate-limit bucketing, so that case
    variants of one address cannot each claim their own quota."""
    return (email or "").strip().lower()


def validate_single_email(email: str) -> str:
    """Require exactly one address.

    ``frappe.utils.validate_email_address`` parses with ``getaddresses()`` and
    returns the addresses re-joined, so ``"a@x.com, b@y.com"`` passes. That
    would land two addresses in a single ``TP OTP.recipient`` and produce a
    malformed ``To:`` header, since ``sendmail`` does not re-split a list item.
    """
    email = clean_email(email)
    if not email:
        frappe.throw(_("Please provide a valid email address."))

    if len(split_emails(email)) > 1:
        frappe.throw(_("Please provide a single email address."))

    return validate_email_address(email, throw=True)


def get_email_otp_settings():
    settings = frappe.get_cached_doc("TP OTP Settings")
    if not settings.enable_email_otp:
        frappe.throw(_("Please enable Email OTP in TP OTP Settings."))
    return settings


def dispatch_email_otp(email, message, subject):
    frappe.sendmail(recipients=[email], subject=subject, message=message)


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@normalize_form_field("email", clean_email)
@rate_limit(key="email", limit=5, seconds=10 * 60)
def generate_otp(email: str, purpose: str = "Verification"):
    """Generate an OTP and send it over email to the given address."""
    settings = get_email_otp_settings()
    email = validate_single_email(email)

    purpose = clean_purpose(purpose)
    otp = generate_otp_code(settings.otp_length)
    expiry_seconds = settings.otp_expiry_in_seconds

    message = settings.otp_message_template.format(
        otp=otp, expiry_minutes=max(1, expiry_seconds // 60)
    )
    subject = settings.email_otp_subject

    # Record first, mirroring the SMS flow: the mail is queued in this same
    # transaction, so a failure rolls both back together.
    create_otp_record(email, "Email", purpose, otp, expiry_seconds)
    dispatch_email_otp(email, message, subject)

    return {"sent": True, "expires_in": expiry_seconds}


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@normalize_form_field("email", clean_email)
@rate_limit(key="email", limit=10, seconds=10 * 60)
def verify_otp(email: str, otp: str, purpose: str = "Verification"):
    """Verify an OTP previously sent to the given email address."""
    settings = get_email_otp_settings()
    email = validate_single_email(email)

    return verify_otp_record(
        email, "Email", otp, clean_purpose(purpose), settings.otp_max_attempts
    )
