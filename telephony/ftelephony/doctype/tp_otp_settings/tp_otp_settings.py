# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document

# A 4-digit code is already only 10k combinations; anything shorter is not
# worth rate-limiting around.
MIN_OTP_LENGTH = 4

# The only placeholders generate_otp supplies to otp_message_template. Probe
# values only — used to prove the template renders before it is saved.
TEMPLATE_PLACEHOLDERS = {"otp": "000000", "expiry_minutes": 5}


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

        # The template is rendered with str.format() on a guest-callable path, so
        # an unknown placeholder or a stray brace would surface as a KeyError /
        # ValueError out of generate_otp. Fail here, where an admin can see it.
        try:
            self.otp_message_template.format(**TEMPLATE_PLACEHOLDERS)
        except (KeyError, IndexError) as e:
            frappe.throw(
                _("OTP Message Template has an unknown placeholder: {0}.").format(
                    str(e)
                ),
                frappe.ValidationError,
            )
        except ValueError as e:
            frappe.throw(
                _("OTP Message Template is malformed: {0}.").format(str(e)),
                frappe.ValidationError,
            )

    def validate_sms_from_number(self, twilio_settings):
        from telephony.twilio.twilio_handler import Twilio

        twilio = Twilio(settings=twilio_settings)
        try:
            available_numbers = twilio.get_phone_numbers()
        except Exception:
            # A live API call in validate() must not be able to wedge the doc.
            # Without this, a network or credential failure raises a raw
            # traceback and the form cannot be saved at all — not even to set
            # enabled = 0 and back out.
            frappe.log_error(title=_("Could not list Twilio phone numbers"))
            frappe.throw(
                _(
                    "Could not reach Twilio to confirm {0}. Check the Twilio"
                    " credentials and connectivity, or disable SMS to save."
                ).format(self.sms_from_number)
            )

        if self.sms_from_number not in available_numbers:
            frappe.throw(
                _("{0} is not a phone number on the connected Twilio account.").format(
                    self.sms_from_number
                )
            )
