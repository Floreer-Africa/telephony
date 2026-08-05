# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and Contributors
# See license.txt

import time
from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase

EXTRA_TEST_RECORD_DEPENDENCIES = []
IGNORE_TEST_RECORD_DEPENDENCIES = []

TEST_SMS_FROM_NUMBER = "+15005550006"


class IntegrationTestTPSMSOTP(IntegrationTestCase):
    """Integration tests for TP SMS OTP, exercising the SMS and Email OTP flows end-to-end
    with the actual Twilio/email dispatch mocked out."""

    def setUp(self):
        super().setUp()
        self._original_sms_settings = frappe.get_doc("TP SMS Settings").as_dict()
        self.addCleanup(self._cleanup)

        doc = frappe.get_doc("TP SMS Settings")
        doc.enabled = 1
        doc.enable_email_otp = 1
        doc.sms_from_number = TEST_SMS_FROM_NUMBER
        doc.otp_length = 6
        doc.otp_expiry_in_seconds = 300
        doc.otp_max_attempts = 2
        doc.flags.ignore_validate = True
        doc.save(ignore_permissions=True)
        frappe.clear_cache(doctype="TP SMS Settings")

    def _cleanup(self):
        frappe.db.delete(
            "TP SMS OTP",
            {
                "recipient": [
                    "in",
                    [
                        "+911234500001",
                        "+911234500002",
                        "+911234500003",
                        "test-otp@example.com",
                    ],
                ]
            },
        )
        frappe.db.delete("TP SMS Log", {"to": ["like", "+91123450%"]})

        original = self._original_sms_settings
        frappe.db.set_single_value(
            "TP SMS Settings",
            {
                "enabled": original.get("enabled"),
                "enable_email_otp": original.get("enable_email_otp"),
                "sms_from_number": original.get("sms_from_number"),
                "otp_length": original.get("otp_length"),
                "otp_expiry_in_seconds": original.get("otp_expiry_in_seconds"),
                "otp_max_attempts": original.get("otp_max_attempts"),
                "otp_message_template": original.get("otp_message_template"),
                "email_otp_subject": original.get("email_otp_subject"),
            },
        )
        frappe.clear_cache(doctype="TP SMS Settings")
        frappe.db.commit()  # nosemgrep

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_sms_otp_generate_and_verify(self, mock_generate_code, mock_dispatch_sms):
        from telephony.twilio.sms import create_sms_log, generate_otp, verify_otp

        mock_dispatch_sms.side_effect = lambda to, message, purpose="OTP": create_sms_log(
            to, TEST_SMS_FROM_NUMBER, message, purpose, "Sent", sid="SM_test"
        )

        phone = "+911234500001"
        result = generate_otp(phone_number=phone, purpose="Verification")
        self.assertTrue(result["sent"])
        mock_dispatch_sms.assert_called_once()

        wrong = verify_otp(phone_number=phone, otp="000000", purpose="Verification")
        self.assertEqual(wrong, {"verified": False, "reason": "incorrect_otp"})

        correct = verify_otp(phone_number=phone, otp="123456", purpose="Verification")
        self.assertEqual(correct, {"verified": True})

        # a verified OTP cannot be replayed
        replay = verify_otp(phone_number=phone, otp="123456", purpose="Verification")
        self.assertEqual(replay, {"verified": False, "reason": "not_found"})

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="654321")
    def test_sms_otp_max_attempts(self, mock_generate_code, mock_dispatch_sms):
        from telephony.twilio.sms import create_sms_log, generate_otp, verify_otp

        mock_dispatch_sms.side_effect = lambda to, message, purpose="OTP": create_sms_log(
            to, TEST_SMS_FROM_NUMBER, message, purpose, "Sent", sid="SM_test"
        )

        phone = "+911234500002"
        generate_otp(phone_number=phone, purpose="Login")

        # otp_max_attempts is set to 2 in setUp
        for _ in range(2):
            result = verify_otp(phone_number=phone, otp="000000", purpose="Login")
            self.assertEqual(result["reason"], "incorrect_otp")

        locked_out = verify_otp(phone_number=phone, otp="654321", purpose="Login")
        self.assertEqual(locked_out, {"verified": False, "reason": "max_attempts_exceeded"})

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="111222")
    def test_sms_otp_expiry(self, mock_generate_code, mock_dispatch_sms):
        from telephony.twilio.sms import create_sms_log, generate_otp, verify_otp

        mock_dispatch_sms.side_effect = lambda to, message, purpose="OTP": create_sms_log(
            to, TEST_SMS_FROM_NUMBER, message, purpose, "Sent", sid="SM_test"
        )

        phone = "+911234500003"
        frappe.db.set_single_value("TP SMS Settings", "otp_expiry_in_seconds", 1)
        frappe.clear_cache(doctype="TP SMS Settings")

        generate_otp(phone_number=phone, purpose="Login")
        time.sleep(2)

        expired = verify_otp(phone_number=phone, otp="111222", purpose="Login")
        self.assertEqual(expired, {"verified": False, "reason": "expired"})

    @patch("telephony.email_otp.dispatch_email_otp")
    @patch("telephony.email_otp.generate_otp_code", return_value="999888")
    def test_email_otp_generate_verify_and_channel_isolation(
        self, mock_generate_code, mock_dispatch_email
    ):
        from telephony.email_otp import generate_otp as generate_email_otp
        from telephony.email_otp import verify_otp as verify_email_otp
        from telephony.otp import verify_otp_record

        email = "test-otp@example.com"
        result = generate_email_otp(email=email, purpose="Verification")
        self.assertTrue(result["sent"])
        mock_dispatch_email.assert_called_once()

        # an OTP created on the Email channel must not be found when checked against SMS
        cross_channel = verify_otp_record(email, "SMS", "999888", "Verification", 5)
        self.assertEqual(cross_channel, {"verified": False, "reason": "not_found"})

        correct = verify_email_otp(email=email, otp="999888", purpose="Verification")
        self.assertEqual(correct, {"verified": True})

    def test_send_sms_requires_telephony_role(self):
        from telephony.twilio.sms import send_sms

        original_user = frappe.session.user
        try:
            frappe.set_user("Guest")
            with self.assertRaises(frappe.PermissionError):
                send_sms(to="+911234500001", message="hi")
        finally:
            frappe.set_user(original_user)
