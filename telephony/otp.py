import secrets
import string

import frappe
from frappe.utils import add_to_date, get_datetime, now_datetime


def generate_otp_code(length: int) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def create_otp_record(
    recipient, channel, purpose, otp, expiry_seconds, notification_log=None
):
    from passlib.hash import pbkdf2_sha256

    doc = frappe.get_doc(
        {
            "doctype": "TP SMS OTP",
            "recipient": recipient,
            "channel": channel,
            "purpose": purpose,
            "otp_hash": pbkdf2_sha256.hash(otp),
            "expires_at": add_to_date(now_datetime(), seconds=expiry_seconds),
            "sms_log": notification_log,
        }
    )
    doc.insert(ignore_permissions=True)
    frappe.db.commit()  # nosemgrep
    return doc


def verify_otp_record(recipient, channel, otp, purpose, max_attempts):
    from passlib.hash import pbkdf2_sha256

    otp_name = frappe.db.get_value(
        "TP SMS OTP",
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
        return {"verified": False, "reason": "not_found"}

    otp_doc = frappe.get_doc("TP SMS OTP", otp_name)

    if get_datetime(otp_doc.expires_at) < now_datetime():
        return {"verified": False, "reason": "expired"}

    if otp_doc.attempts >= max_attempts:
        return {"verified": False, "reason": "max_attempts_exceeded"}

    if not pbkdf2_sha256.verify(otp, otp_doc.otp_hash):
        otp_doc.attempts += 1
        otp_doc.save(ignore_permissions=True)
        frappe.db.commit()  # nosemgrep
        return {"verified": False, "reason": "incorrect_otp"}

    otp_doc.is_verified = 1
    otp_doc.verified_at = now_datetime()
    otp_doc.save(ignore_permissions=True)
    frappe.db.commit()  # nosemgrep

    return {"verified": True}
