# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and Contributors
# See license.txt

from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase

EXTRA_TEST_RECORD_DEPENDENCIES = []
IGNORE_TEST_RECORD_DEPENDENCIES = []


class IntegrationTestTPSMSSettings(IntegrationTestCase):
    """Integration tests for TP SMS Settings."""

    def setUp(self):
        super().setUp()
        self._original_twilio_enabled = frappe.db.get_single_value("TP Twilio Settings", "enabled")
        self._original_sms_settings = frappe.get_doc("TP SMS Settings").as_dict()
        self.addCleanup(self._restore_settings)

    def _restore_settings(self):
        frappe.db.set_single_value("TP Twilio Settings", "enabled", self._original_twilio_enabled)
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
        frappe.clear_cache(doctype="TP Twilio Settings")
        frappe.clear_cache(doctype="TP SMS Settings")
        frappe.db.commit()  # nosemgrep

    def test_throws_when_twilio_not_enabled(self):
        frappe.db.set_single_value("TP Twilio Settings", "enabled", 0)
        frappe.clear_cache(doctype="TP Twilio Settings")

        doc = frappe.get_doc("TP SMS Settings")
        doc.enabled = 1
        doc.sms_from_number = "+15005550006"
        with self.assertRaises(frappe.ValidationError):
            doc.save(ignore_permissions=True)

    def test_throws_when_number_not_on_twilio_account(self):
        frappe.db.set_single_value("TP Twilio Settings", "enabled", 1)
        frappe.clear_cache(doctype="TP Twilio Settings")

        with patch("telephony.twilio.twilio_handler.Twilio") as MockTwilio:
            MockTwilio.return_value.get_phone_numbers.return_value = ["+10000000000"]

            doc = frappe.get_doc("TP SMS Settings")
            doc.enabled = 1
            doc.sms_from_number = "+15005550006"
            with self.assertRaises(frappe.ValidationError):
                doc.save(ignore_permissions=True)

    def test_saves_when_number_matches_twilio_account(self):
        frappe.db.set_single_value("TP Twilio Settings", "enabled", 1)
        frappe.clear_cache(doctype="TP Twilio Settings")

        with patch("telephony.twilio.twilio_handler.Twilio") as MockTwilio:
            MockTwilio.return_value.get_phone_numbers.return_value = ["+15005550006"]

            doc = frappe.get_doc("TP SMS Settings")
            doc.enabled = 1
            doc.sms_from_number = "+15005550006"
            doc.save(ignore_permissions=True)

        self.assertEqual(frappe.db.get_single_value("TP SMS Settings", "enabled"), 1)

    def test_enable_email_otp_does_not_require_twilio(self):
        frappe.db.set_single_value("TP Twilio Settings", "enabled", 0)
        frappe.clear_cache(doctype="TP Twilio Settings")

        doc = frappe.get_doc("TP SMS Settings")
        doc.enabled = 0
        doc.enable_email_otp = 1
        doc.save(ignore_permissions=True)  # should not throw, Email OTP has no Twilio dependency

        self.assertEqual(frappe.db.get_single_value("TP SMS Settings", "enable_email_otp"), 1)
