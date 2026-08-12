# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and Contributors
# See license.txt

from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils import add_to_date, now_datetime

from telephony.ftelephony.doctype.tp_otp_settings.tp_otp_settings import TPOTPSettings
from telephony.ftelephony.doctype.tp_twilio_settings.tp_twilio_settings import (
    TPTwilioSettings,
)
from telephony.otp import GENERIC_FAILURE
from telephony.twilio.sms import REDACTED_MESSAGE

EXTRA_TEST_RECORD_DEPENDENCIES = []
IGNORE_TEST_RECORD_DEPENDENCIES = []

TEST_SMS_FROM_NUMBER = "+15005550006"

PHONE_VERIFY = "+911234500001"
PHONE_ATTEMPTS = "+911234500002"
PHONE_EXPIRY = "+911234500003"
PHONE_BUDGET = "+911234500004"
PHONE_RESET = "+911234500005"
PHONE_NORMALIZE = "+911234500006"
PHONE_REDACT = "+911234500007"
TEST_EMAIL = "test-otp@example.com"

TEST_RECIPIENTS = [
    PHONE_VERIFY,
    PHONE_ATTEMPTS,
    PHONE_EXPIRY,
    PHONE_BUDGET,
    PHONE_RESET,
    PHONE_NORMALIZE,
    PHONE_REDACT,
    TEST_EMAIL,
]


class IntegrationTestTPOTP(IntegrationTestCase):
    """Integration tests for TP OTP, exercising the SMS and Email OTP flows
    end-to-end with the actual Twilio/email dispatch mocked out."""

    def setUp(self):
        super().setUp()

        # TP OTP Settings.validate() confirms sms_from_number against the live
        # Twilio account. These tests never reach Twilio, so stub that one
        # check rather than skipping validation wholesale — the OTP parameter
        # validation still runs.
        patcher = patch.object(
            TPOTPSettings, "validate_sms_from_number", return_value=None
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        # TP Twilio Settings.validate() authenticates against the live Twilio
        # API and on_update() provisions API keys there; neither is reachable
        # from tests. Stub both so change_settings can drive the doc normally.
        for method in ("validate_twilio_account", "on_update"):
            twilio_patcher = patch.object(TPTwilioSettings, method, return_value=None)
            twilio_patcher.start()
            self.addCleanup(twilio_patcher.stop)

        # validate() also requires TP Twilio Settings to be enabled.
        twilio_settings = self.change_settings("TP Twilio Settings", {"enabled": 1})
        twilio_settings.__enter__()
        self.addCleanup(twilio_settings.__exit__, None, None, None)
        frappe.clear_cache(doctype="TP Twilio Settings")

        settings = self.change_settings(
            "TP OTP Settings",
            {
                "enabled": 1,
                "enable_email_otp": 1,
                "sms_from_number": TEST_SMS_FROM_NUMBER,
                "otp_length": 6,
                "otp_expiry_in_seconds": 300,
                "otp_max_attempts": 2,
            },
        )
        settings.__enter__()
        self.addCleanup(settings.__exit__, None, None, None)
        frappe.clear_cache(doctype="TP OTP Settings")

        self.addCleanup(self._delete_test_records)

    def _delete_test_records(self):
        frappe.db.delete("TP OTP", {"recipient": ["in", TEST_RECIPIENTS]})
        frappe.db.delete("TP SMS Log", {"to": ["in", TEST_RECIPIENTS]})

    def _log_sent_sms(self, to, message, purpose="OTP"):
        """Stand in for dispatch_sms, but still write a real TP SMS Log so the
        redaction behaviour under test is exercised."""
        from telephony.twilio.sms import create_sms_log

        return create_sms_log(
            to, TEST_SMS_FROM_NUMBER, message, purpose, "Sent", sid="SM_test"
        )

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_sms_otp_generate_and_verify(self, mock_generate_code, mock_dispatch_sms):
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        result = generate_otp(phone_number=PHONE_VERIFY, purpose="Verification")
        self.assertTrue(result["sent"])
        mock_dispatch_sms.assert_called_once()

        wrong = verify_otp(
            phone_number=PHONE_VERIFY, otp="000000", purpose="Verification"
        )
        self.assertEqual(wrong, GENERIC_FAILURE)

        correct = verify_otp(
            phone_number=PHONE_VERIFY, otp="123456", purpose="Verification"
        )
        self.assertEqual(correct, {"verified": True})

        # a verified OTP cannot be replayed
        replay = verify_otp(
            phone_number=PHONE_VERIFY, otp="123456", purpose="Verification"
        )
        self.assertEqual(replay, GENERIC_FAILURE)

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_generate_response_never_carries_the_code(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """The response is returned to unauthenticated callers, so it must not
        echo the OTP back under any site configuration."""
        from telephony.twilio.sms import generate_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        result = generate_otp(phone_number=PHONE_VERIFY, purpose="Verification")
        self.assertNotIn("otp", result)
        self.assertEqual(set(result), {"sent", "expires_in"})

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="654321")
    def test_sms_otp_max_attempts(self, mock_generate_code, mock_dispatch_sms):
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_ATTEMPTS, purpose="Login")

        # otp_max_attempts is set to 2 in setUp
        for _ in range(2):
            result = verify_otp(
                phone_number=PHONE_ATTEMPTS, otp="000000", purpose="Login"
            )
            self.assertEqual(result, GENERIC_FAILURE)

        locked_out = verify_otp(
            phone_number=PHONE_ATTEMPTS, otp="654321", purpose="Login"
        )
        self.assertEqual(locked_out, GENERIC_FAILURE)

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="222333")
    def test_regenerating_otp_does_not_reset_attempt_budget(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """Requesting a fresh OTP must not hand out a new attempt budget while
        the previous one is still live, else the max-attempts cap is toothless."""
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_BUDGET, purpose="Login")
        for _ in range(2):
            verify_otp(phone_number=PHONE_BUDGET, otp="000000", purpose="Login")

        # budget exhausted
        self.assertEqual(
            verify_otp(phone_number=PHONE_BUDGET, otp="222333", purpose="Login"),
            GENERIC_FAILURE,
        )

        generate_otp(phone_number=PHONE_BUDGET, purpose="Login")
        self.assertEqual(
            verify_otp(phone_number=PHONE_BUDGET, otp="222333", purpose="Login"),
            GENERIC_FAILURE,
        )

        carried = frappe.db.get_value(
            "TP OTP",
            {"recipient": PHONE_BUDGET, "is_verified": 0},
            "attempts",
            order_by="creation desc",
        )
        self.assertEqual(carried, 2)

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="333444")
    def test_attempt_budget_resets_once_window_lapses(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """The carry-forward above must not become a permanent lockout: once the
        previous OTP is no longer live, a fresh request starts clean."""
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_RESET, purpose="Login")
        for _ in range(2):
            verify_otp(phone_number=PHONE_RESET, otp="000000", purpose="Login")

        # otp_expiry_in_seconds is 300 in setUp
        with self.freeze_time(add_to_date(now_datetime(), seconds=301)):
            generate_otp(phone_number=PHONE_RESET, purpose="Login")
            self.assertEqual(
                verify_otp(phone_number=PHONE_RESET, otp="333444", purpose="Login"),
                {"verified": True},
            )

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="111222")
    def test_sms_otp_expiry(self, mock_generate_code, mock_dispatch_sms):
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_EXPIRY, purpose="Login")

        # otp_expiry_in_seconds is 300 in setUp
        with self.freeze_time(add_to_date(now_datetime(), seconds=301)):
            expired = verify_otp(
                phone_number=PHONE_EXPIRY, otp="111222", purpose="Login"
            )

        self.assertEqual(expired, GENERIC_FAILURE)

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_otp_body_is_not_written_to_sms_log(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """TP SMS Log is readable by TP Agent and kept for 90 days, so storing
        the rendered code there would defeat hashing it in TP OTP."""
        from telephony.twilio.sms import generate_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_REDACT, purpose="Verification")

        logged = frappe.db.get_value("TP SMS Log", {"to": PHONE_REDACT}, "message")
        self.assertEqual(logged, REDACTED_MESSAGE)
        self.assertNotIn("123456", logged)

    def test_general_sms_body_is_retained_in_log(self):
        """Redaction is scoped to OTP traffic; ordinary sends stay auditable."""
        from telephony.twilio.sms import create_sms_log

        log = create_sms_log(
            PHONE_REDACT, TEST_SMS_FROM_NUMBER, "hello there", "General", "Sent"
        )
        self.assertEqual(log.message, "hello there")

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_rate_limit_key_is_normalized(self, mock_generate_code, mock_dispatch_sms):
        """frappe.rate_limit buckets on form_dict[key] verbatim, so the key has
        to be canonical or the send cap is bypassable by reformatting."""
        from telephony.twilio.sms import generate_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        self.addCleanup(frappe.form_dict.pop, "phone_number", None)
        frappe.form_dict["phone_number"] = "+91 12345-00006"

        generate_otp(phone_number="+91 12345-00006", purpose="Verification")

        self.assertEqual(frappe.form_dict["phone_number"], PHONE_NORMALIZE)

    @patch("telephony.email_otp.dispatch_email_otp")
    @patch("telephony.email_otp.generate_otp_code", return_value="999888")
    def test_email_otp_generate_verify_and_channel_isolation(
        self, mock_generate_code, mock_dispatch_email
    ):
        from telephony.email_otp import generate_otp as generate_email_otp
        from telephony.email_otp import verify_otp as verify_email_otp
        from telephony.otp import verify_otp_record

        result = generate_email_otp(email=TEST_EMAIL, purpose="Verification")
        self.assertTrue(result["sent"])
        mock_dispatch_email.assert_called_once()

        # an OTP created on the Email channel must not be found when checked
        # against SMS
        cross_channel = verify_otp_record(
            TEST_EMAIL, "SMS", "999888", "Verification", 5
        )
        self.assertEqual(cross_channel, GENERIC_FAILURE)

        correct = verify_email_otp(
            email=TEST_EMAIL, otp="999888", purpose="Verification"
        )
        self.assertEqual(correct, {"verified": True})

    @patch("telephony.email_otp.dispatch_email_otp")
    @patch("telephony.email_otp.generate_otp_code", return_value="999888")
    def test_email_otp_is_case_insensitive(
        self, mock_generate_code, mock_dispatch_email
    ):
        """Case variants must resolve to one recipient, both for storage and for
        rate-limit bucketing."""
        from telephony.email_otp import generate_otp as generate_email_otp
        from telephony.email_otp import verify_otp as verify_email_otp

        generate_email_otp(email="Test-OTP@Example.COM", purpose="Verification")

        stored = frappe.db.get_value(
            "TP OTP", {"recipient": TEST_EMAIL, "channel": "Email"}, "recipient"
        )
        self.assertEqual(stored, TEST_EMAIL)

        correct = verify_email_otp(
            email=TEST_EMAIL, otp="999888", purpose="Verification"
        )
        self.assertEqual(correct, {"verified": True})

    @patch("telephony.email_otp.dispatch_email_otp")
    def test_email_otp_rejects_multiple_addresses(self, mock_dispatch_email):
        """validate_email_address() accepts a comma-separated list and returns
        it re-joined, which would store two addresses as one recipient."""
        from telephony.email_otp import generate_otp as generate_email_otp

        with self.assertRaises(frappe.ValidationError):
            generate_email_otp(
                email=f"{TEST_EMAIL}, other@example.com", purpose="Verification"
            )

        mock_dispatch_email.assert_not_called()

    @patch("telephony.email_otp.dispatch_email_otp")
    def test_email_otp_rejects_newline_separated_addresses(self, mock_dispatch_email):
        """A newline is the separator that slips past a split_emails() count:
        split_emails collapses \\n to a space before splitting, while
        validate_email_address turns it into a comma and returns both."""
        from telephony.email_otp import generate_otp as generate_email_otp

        for separator in ("\n", "\r"):
            with self.assertRaises(frappe.ValidationError):
                generate_email_otp(
                    email=f"{TEST_EMAIL}{separator}other@example.com",
                    purpose="Verification",
                )

        mock_dispatch_email.assert_not_called()

    def test_email_otp_is_redacted_from_the_email_queue(self):
        """Email Queue keeps the rendered body for 30 days, so the queued OTP
        must not outlive its own expiry in cleartext."""
        import inspect

        from telephony.email_otp import dispatch_email_otp

        with patch("frappe.sendmail") as mock_sendmail:
            dispatch_email_otp(TEST_EMAIL, "Your OTP is 123456.", "Code")

        _, kwargs = mock_sendmail.call_args
        self.assertTrue(kwargs.get("redact_message_after_send"))
        # guard against the kwarg being silently dropped by a frappe upgrade
        self.assertIn(
            "redact_message_after_send", inspect.signature(frappe.sendmail).parameters
        )

    def test_clean_phone_number_rejects_non_ascii_digits(self):
        """str.isdigit() is true for fullwidth/Arabic-Indic digits, which
        MariaDB's utf8mb4_unicode_ci then compares equal to their ASCII form —
        so they must not survive normalization."""
        from telephony.twilio.sms import clean_phone_number

        # fullwidth ９１ and Arabic-Indic ٩١ both pass str.isdigit()
        self.assertEqual(clean_phone_number("+９１1234500001"), "+1234500001")
        self.assertEqual(clean_phone_number("+٩١1234500001"), "+1234500001")
        self.assertEqual(clean_phone_number("+91 12345-00001"), "+911234500001")

    @patch("telephony.twilio.sms.Twilio")
    def test_dispatch_sms_success_writes_redacted_sent_log(self, MockTwilio):
        """Exercises the real dispatch_sms, which every other test mocks out."""
        from telephony.twilio.sms import dispatch_sms

        client = MockTwilio.connect.return_value.twilio_client
        client.messages.create.return_value = frappe._dict(sid="SM_ok")

        log = dispatch_sms(PHONE_REDACT, "Your OTP is 123456.", purpose="OTP")

        self.assertEqual(log.status, "Sent")
        self.assertEqual(log.sid, "SM_ok")
        self.assertEqual(log.message, REDACTED_MESSAGE)

    @patch("telephony.twilio.sms.Twilio")
    def test_dispatch_sms_failure_is_generic_and_audited(self, MockTwilio):
        """The raised message must not carry Twilio internals, and the Failed
        row must still be written."""
        from telephony.twilio.sms import dispatch_sms

        client = MockTwilio.connect.return_value.twilio_client
        client.messages.create.side_effect = Exception(
            "HTTP 401 error: ACfakeaccountsid https://api.twilio.com/2010-04-01"
        )

        # The deliberate commit would otherwise break test isolation.
        with patch("frappe.db.commit") as mock_commit:
            with self.assertRaises(frappe.ValidationError) as ctx:
                dispatch_sms(PHONE_REDACT, "Your OTP is 123456.", purpose="OTP")
            mock_commit.assert_called_once()

        raised = str(ctx.exception)
        self.assertNotIn("ACfakeaccountsid", raised)
        self.assertNotIn("api.twilio.com", raised)

        failed = frappe.db.get_value(
            "TP SMS Log",
            {"to": PHONE_REDACT, "status": "Failed"},
            ["message", "error"],
            as_dict=True,
        )
        self.assertIsNotNone(failed)
        self.assertEqual(failed.message, REDACTED_MESSAGE)

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_rate_limit_actually_throttles_sends(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """The limiter is inert without frappe.request, so the other tests never
        exercise it. Drive it with a request context and prove it fires."""
        from frappe.utils import set_request

        from telephony.twilio.sms import generate_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        original_request = getattr(frappe.local, "request", None)
        self.addCleanup(setattr, frappe.local, "request", original_request)
        self.addCleanup(frappe.cache.delete_keys, "rl:")

        set_request(method="POST", path="/api/method/telephony.twilio.sms.generate_otp")
        frappe.local.request_ip = "127.0.0.1"
        frappe.form_dict.cmd = "telephony.twilio.sms.generate_otp"
        frappe.form_dict.phone_number = PHONE_NORMALIZE
        self.addCleanup(frappe.form_dict.pop, "cmd", None)
        self.addCleanup(frappe.form_dict.pop, "phone_number", None)

        # limit is 5 per 10 minutes
        for _ in range(5):
            generate_otp(phone_number=PHONE_NORMALIZE, purpose="Verification")

        with self.assertRaises(frappe.RateLimitExceededError):
            generate_otp(phone_number=PHONE_NORMALIZE, purpose="Verification")

    def test_guest_may_call_otp_endpoints_but_not_send_sms(self):
        """Guest access is decided by frappe.is_whitelisted against the exact
        object registered at decoration time. Since normalize_form_field wraps
        the function *under* @frappe.whitelist, a mistake in that stacking would
        silently drop guest registration — so assert it directly."""
        from telephony import email_otp
        from telephony.twilio import sms

        guest_callable = [
            sms.generate_otp,
            sms.verify_otp,
            email_otp.generate_otp,
            email_otp.verify_otp,
        ]

        with self.set_user("Guest"):
            for fn in guest_callable:
                frappe.is_whitelisted(fn)  # must not raise

            with self.assertRaises(frappe.PermissionError):
                frappe.is_whitelisted(sms.send_sms)

        # POST-only: GET skips Frappe's CSRF check, so a state-changing
        # whitelisted method must not accept it.
        for fn in [*guest_callable, sms.send_sms]:
            self.assertEqual(
                tuple(frappe.allowed_http_methods_for_whitelisted_func[fn]), ("POST",)
            )

    def test_send_sms_requires_permission(self):
        from telephony.twilio.sms import send_sms

        with self.set_user("Guest"), self.assertRaises(frappe.PermissionError):
            send_sms(to=PHONE_VERIFY, message="hi")

    @patch("telephony.twilio.sms.dispatch_sms")
    def test_send_sms_allowed_for_permitted_user(self, mock_dispatch_sms):
        from telephony.twilio.sms import send_sms

        mock_dispatch_sms.side_effect = (
            lambda to, message, purpose="General": self._log_sent_sms(
                to, message, purpose
            )
        )

        result = send_sms(to=PHONE_VERIFY, message="hi")
        self.assertEqual(result["status"], "Sent")
