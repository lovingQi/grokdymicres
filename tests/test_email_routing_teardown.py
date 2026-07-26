"""Email Routing 拆除复查、误报 not found、purge 保留 keep。"""

import unittest
from unittest.mock import patch

import dynamic_subdomain as ds


class EmailRoutingTeardownTests(unittest.TestCase):
    def test_disable_success_and_list_absent(self):
        calls = {"n": 0}

        def fake_has(token, zone_id, fqdn):
            calls["n"] += 1
            # 第一次 list_before：还在；DELETE 后复查：不在
            return True if calls["n"] == 1 else False

        with patch.object(ds, "email_routing_has_subdomain", side_effect=fake_has), patch.object(
            ds, "_cf_request", return_value={"success": True}
        ) as req:
            result = ds.disable_email_routing_subdomain("tok", "zone", "a.xbltest.xyz", retries=3)
        self.assertTrue(result["ok"])
        self.assertTrue(result["verified"])
        self.assertEqual(req.call_count, 1)

    def test_disable_not_found_but_still_in_list_is_failure(self):
        with patch.object(ds, "email_routing_has_subdomain", return_value=True), patch.object(
            ds,
            "_cf_request",
            return_value={
                "success": False,
                "_http_status": 404,
                "errors": [{"message": "not found"}],
            },
        ):
            result = ds.disable_email_routing_subdomain("tok", "zone", "a.xbltest.xyz", retries=2)
        self.assertFalse(result["ok"])
        self.assertFalse(result["verified"])
        self.assertTrue(result.get("still_present"))

    def test_disable_retries_then_success(self):
        states = {"delete": 0, "has": 0}

        def fake_has(token, zone_id, fqdn):
            states["has"] += 1
            # attempts: before1=True, after1=True, before2=True, after2=False
            if states["has"] >= 4:
                return False
            return True

        def fake_req(token, method, path, body=None, query=None):
            states["delete"] += 1
            return {"success": states["delete"] >= 2}

        with patch.object(ds, "email_routing_has_subdomain", side_effect=fake_has), patch.object(
            ds, "_cf_request", side_effect=fake_req
        ), patch("time.sleep", return_value=None):
            result = ds.disable_email_routing_subdomain("tok", "zone", "a.xbltest.xyz", retries=3)
        self.assertTrue(result["ok"])
        self.assertTrue(result["verified"])
        self.assertGreaterEqual(result["attempts"], 2)

    def test_purge_keeps_mail_only(self):
        listed = {
            "ok": True,
            "domains": [
                "mail.xbltest.xyz",
                "qwe.xbltest.xyz",
                "asd.xbltest.xyz",
            ],
        }
        removed = []

        def fake_disable(token, zone_id, fqdn, retries=3):
            removed.append(fqdn)
            return {"ok": True, "verified": True}

        cfg = {
            "cf_api_token": "tok",
            "dynamic_subdomain_root": "xbltest.xyz",
            "dynamic_subdomain_keep": "mail.xbltest.xyz",
            "cf_worker_name": "temp-email",
            "dynamic_subdomain_teardown_retries": 3,
        }
        with patch.object(ds, "get_zone_id", return_value="zone"), patch.object(
            ds, "get_account_id", return_value="acct"
        ), patch.object(
            ds, "list_email_routing_subdomains", side_effect=[listed, {"ok": True, "domains": ["mail.xbltest.xyz"]}]
        ), patch.object(
            ds, "disable_email_routing_subdomain", side_effect=fake_disable
        ), patch.object(
            ds,
            "read_worker_domains",
            return_value={
                "ok": True,
                "domains": ["mail.xbltest.xyz", "qwe.xbltest.xyz"],
                "bindings": [{"name": "DOMAINS", "type": "json", "json": []}],
            },
        ), patch.object(
            ds, "write_worker_domains", return_value={"ok": True}
        ) as write:
            result = ds.purge_email_routing_residuals(cfg, log=None)
        self.assertTrue(result["ok"])
        self.assertEqual(sorted(removed), ["asd.xbltest.xyz", "qwe.xbltest.xyz"])
        self.assertNotIn("mail.xbltest.xyz", removed)
        self.assertEqual(result["before"], 3)
        self.assertEqual(result["after"], 1)
        write.assert_called_once()
        self.assertEqual(write.call_args.args[3], ["mail.xbltest.xyz"])

    def test_teardown_one_false_when_routing_verify_fails(self):
        cfg = {
            "cf_api_token": "tok",
            "dynamic_subdomain_root": "xbltest.xyz",
            "dynamic_subdomain_keep": "mail.xbltest.xyz",
            "cf_worker_name": "temp-email",
            "dynamic_subdomain_teardown_retries": 2,
        }
        with patch.object(ds, "get_zone_id", return_value="zone"), patch.object(
            ds, "get_account_id", return_value="acct"
        ), patch.object(
            ds,
            "read_worker_domains",
            return_value={"ok": True, "domains": ["a.xbltest.xyz"], "bindings": []},
        ), patch.object(
            ds, "write_worker_domains", return_value={"ok": True}
        ), patch.object(
            ds,
            "disable_email_routing_subdomain",
            return_value={"ok": False, "verified": False, "error": "still there"},
        ):
            ok = ds.teardown_one("a.xbltest.xyz", cfg, log=None)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
