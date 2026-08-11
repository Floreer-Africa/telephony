# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document

# A 4-digit code is already only 10k combinations; anything shorter is not
# worth rate-limiting around.
MIN_OTP_LENGTH = 4


class TPOTPSettings(Document):
    def validate(self):
        self.validate_otp_params()

        if not self.enabled:
            return

        twilio_settings = frappe.get_cached_doc("TP Twilio Settings")
        if not twilio_settings.enabled:
            frappe.throw(_("Please enable and configure TP Twilio Settings first."))

        self.validate_sms_from_number(twilio_settings)

    def validate_otp_params(self):
        """Guard the OTP knobs, since weak values here silently weaken every
        OTP the site issues."""
        if self.otp_length < MIN_OTP_LENGTH:
            frappe.throw(
                _("OTP Length must be at least {0}.").format(MIN_OTP_LENGTH),
                frappe.ValidationError,
            )

        if self.otp_expiry_in_seconds < 1:
            frappe.throw(
                _("OTP Expiry (in seconds) must be at least 1."),
                frappe.ValidationError,
            )

        if self.otp_max_attempts < 1:
            frappe.throw(
                _("OTP Max Attempts must be at least 1."), frappe.ValidationError
            )

        if "{otp}" not in (self.otp_message_template or ""):
            frappe.throw(
                _("OTP Message Template must contain the {otp} placeholder."),
                frappe.ValidationError,
            )

    def validate_sms_from_number(self, twilio_settings):
        from telephony.twilio.twilio_handler import Twilio

        twilio = Twilio(settings=twilio_settings)
        if self.sms_from_number not in twilio.get_phone_numbers():
            frappe.throw(
                _("{0} is not a phone number on the connected Twilio account.").format(
                    self.sms_from_number
                )
            )
