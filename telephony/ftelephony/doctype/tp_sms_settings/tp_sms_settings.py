# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document


class TPSMSSettings(Document):
    def validate(self):
        if not self.enabled:
            return

        twilio_settings = frappe.get_cached_doc("TP Twilio Settings")
        if not twilio_settings.enabled:
            frappe.throw(_("Please enable and configure TP Twilio Settings first."))

        self.validate_sms_from_number(twilio_settings)

    def validate_sms_from_number(self, twilio_settings):
        from telephony.twilio.twilio_handler import Twilio

        twilio = Twilio(settings=twilio_settings)
        if self.sms_from_number not in twilio.get_phone_numbers():
            frappe.throw(
                _("{0} is not a phone number on the connected Twilio account.").format(
                    self.sms_from_number
                )
            )
