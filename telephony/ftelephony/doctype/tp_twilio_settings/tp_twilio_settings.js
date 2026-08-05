// Copyright (c) 2025, Frappe Technologies Pvt. Ltd. and contributors
// For license information, please see license.txt

frappe.ui.form.on("TP Twilio Settings", {
	refresh(frm) {
		frm.add_custom_button(__("OTP"), () => show_otp_dialog());
	},
});

function show_otp_dialog() {
	frappe.call({
		method: "frappe.client.get_value",
		args: {
			doctype: "TP SMS Settings",
			fieldname: ["enabled"],
		},
	}).then((r) => {
		const current = r.message || {};

		const dialog = new frappe.ui.Dialog({
			title: __("OTP"),
			fields: [
				{
					fieldname: "sms",
					fieldtype: "Check",
					label: __("SMS"),
					default: current.enabled,
				},
			],
			primary_action_label: __("Save"),
			primary_action: (values) => {
				frappe.call({
					method: "frappe.client.set_value",
					args: {
						doctype: "TP SMS Settings",
						name: "TP SMS Settings",
						fieldname: {
							enabled: values.sms ? 1 : 0,
						},
					},
					freeze: true,
				}).then(() => {
					frappe.show_alert({ message: __("OTP settings updated"), indicator: "green" });
					dialog.hide();
				});
			},
		});

		dialog.show();
	});
}
