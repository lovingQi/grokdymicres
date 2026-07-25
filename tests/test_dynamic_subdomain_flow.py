"""动态子域相关：forced domain、skip 统计、成功后间隔。"""

import unittest
from unittest.mock import patch

import app_config
import mail_service
from registration_flow import (
    RegistrationCallbacks,
    RegistrationOperations,
    RegistrationSettings,
    SlotPrepareResult,
    run_batch,
)


class Cancelled(Exception):
    pass


class Retryable(Exception):
    pass


class FakeOps:
    def __init__(self):
        self.events = []
        self.account_no = 0

    def operations(self, before_account=None, after_account=None):
        return RegistrationOperations(
            start_browser=lambda: self.events.append("start"),
            restart_browser=lambda: self.events.append("restart"),
            browser_missing=lambda: False,
            open_signup_page=lambda: self.events.append("open"),
            fill_email_and_submit=self._email,
            save_mail_credential=lambda email, token: True,
            fill_code_and_submit=lambda email, token: "123456",
            fill_profile_and_submit=lambda: {
                "given_name": "A",
                "family_name": "B",
                "password": "pw",
            },
            wait_for_sso_cookie=lambda: "sso-token",
            enable_nsfw=lambda sso: (True, "ok"),
            persist_account_line=lambda email, password, sso: self.events.append(
                ("persist", email)
            ),
            queue_unsaved_result=lambda payload, error: True,
            add_tokens=lambda sso, email: {
                "local": {"enabled": False, "ok": None, "error": None},
                "remote": {"enabled": False, "ok": None, "error": None},
            },
            export_cpa=lambda email, password, sso: {"ok": False, "skipped": True},
            cleanup=lambda reason: self.events.append(("cleanup", reason)),
            sleep=lambda seconds: self.events.append(("sleep", seconds)),
            cancelled_exception=Cancelled,
            retry_exception=Retryable,
            before_account=before_account,
            after_account=after_account,
        )

    def _email(self):
        self.account_no += 1
        return f"user{self.account_no}@example.com", "mail-token"


class DynamicSubdomainFlowTests(unittest.TestCase):
    def callbacks(self, logs=None):
        logs = logs if logs is not None else []
        return RegistrationCallbacks(log=logs.append, cancelled=lambda: False)

    def test_resolve_batch_count_prefers_max_accounts(self):
        self.assertEqual(app_config.resolve_batch_count({"max_accounts": 7, "register_count": 2}), 7)
        self.assertEqual(app_config.resolve_batch_count({"max_accounts": 0, "register_count": 3}), 3)

    def test_forced_domain_bypasses_rotation(self):
        mail_service.set_forced_cloudflare_domain(None)
        mail_service.config = {"defaultDomains": "a.xbltest.xyz,b.xbltest.xyz"}
        mail_service._cf_domain_index = 0
        mail_service.set_forced_cloudflare_domain("zz.xbltest.xyz")
        self.assertEqual(mail_service.cloudflare_next_default_domain(), "zz.xbltest.xyz")
        self.assertEqual(mail_service.cloudflare_next_default_domain(), "zz.xbltest.xyz")
        mail_service.set_forced_cloudflare_domain(None)
        self.assertEqual(mail_service.cloudflare_next_default_domain(), "a.xbltest.xyz")

    def test_subdomain_prepare_failure_skips_registration(self):
        fake = FakeOps()
        after_calls = []

        def before(i, total):
            return SlotPrepareResult(ok=False, skip=True, error="no domain")

        def after():
            after_calls.append(True)

        settings = RegistrationSettings(
            count=2,
            delay_browser_start=True,
            account_interval_sec=300,
        )
        batch = run_batch(
            2,
            self.callbacks(),
            lambda *args: None,
            fake.operations(before_account=before, after_account=after),
            settings=settings,
        )
        self.assertEqual(batch.processed_count, 2)
        self.assertEqual(batch.fail_count, 2)
        self.assertEqual(batch.success_count, 0)
        self.assertNotIn("open", fake.events)
        self.assertNotIn("start", fake.events)
        self.assertEqual(len(after_calls), 2)
        self.assertNotIn(("sleep", 300), fake.events)

    def test_interval_only_after_success_and_not_last(self):
        fake = FakeOps()
        settings = RegistrationSettings(count=2, account_interval_sec=300)
        batch = run_batch(
            2,
            self.callbacks(),
            lambda *args: None,
            fake.operations(),
            settings=settings,
        )
        self.assertEqual(batch.success_count, 2)
        sleeps = [e for e in fake.events if e[0] == "sleep"]
        self.assertEqual(sleeps.count(("sleep", 300)), 1)
        self.assertNotIn(("sleep", 1), fake.events)


if __name__ == "__main__":
    unittest.main()
