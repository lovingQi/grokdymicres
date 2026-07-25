"""验证 write_worker_domains 不会用 minimal 回退清空 JWT_SECRET / D1。"""

import unittest
from unittest.mock import patch

import dynamic_subdomain as ds


class WriteWorkerDomainsSafeTests(unittest.TestCase):
    def test_sanitize_secret_text_omits_text(self):
        out = ds._sanitize_binding_for_rewrite(
            {"type": "secret_text", "name": "JWT_SECRET"}
        )
        self.assertEqual(out, {"type": "secret_text", "name": "JWT_SECRET"})

    def test_sanitize_d1_keeps_database_id(self):
        out = ds._sanitize_binding_for_rewrite(
            {
                "type": "d1",
                "name": "DB",
                "id": "abc-123",
                "database_id": "abc-123",
            }
        )
        self.assertEqual(
            out, {"type": "d1", "name": "DB", "database_id": "abc-123"}
        )

    def test_detect_json_domains_type(self):
        self.assertEqual(
            ds._detect_domains_binding_type(
                [{"type": "json", "name": "DOMAINS", "json": ["a.example.com"]}]
            ),
            "json",
        )
        self.assertEqual(
            ds._detect_domains_binding_type(
                [{"type": "plain_text", "name": "DOMAINS", "text": '["a"]'}]
            ),
            "plain_text",
        )

    def test_extract_domain_vars_supports_json_binding(self):
        settings = {
            "result": {
                "bindings": [
                    {
                        "type": "json",
                        "name": "DOMAINS",
                        "json": ["mail.xbltest.xyz", "a.xbltest.xyz"],
                    }
                ]
            }
        }
        vars_map = ds._extract_domain_vars(settings)
        domains = ds.parse_domains_json(vars_map["DOMAINS"])
        self.assertEqual(domains, ["mail.xbltest.xyz", "a.xbltest.xyz"])

    def test_write_preserves_critical_bindings_and_never_minimal_fallback(self):
        existing = [
            {"type": "secret_text", "name": "JWT_SECRET"},
            {
                "type": "d1",
                "name": "DB",
                "database_id": "db-1",
                "id": "db-1",
            },
            {"type": "json", "name": "DOMAINS", "json": ["mail.xbltest.xyz"]},
            {
                "type": "plain_text",
                "name": "ENABLE_USER_CREATE_EMAIL",
                "text": "true",
            },
        ]
        patch_calls = []

        def fake_patch(token, account_id, worker_name, settings_obj):
            patch_calls.append(settings_obj)
            names = [b.get("name") for b in settings_obj.get("bindings") or []]
            # 若只提交 DOMAINS 两个变量，视为危险 minimal（应永不发生）
            if set(names) <= {"DOMAINS", "DEFAULT_DOMAINS"}:
                self.fail("dangerous minimal-only bindings patch was attempted")
            return {"success": True, "result": None}

        def fake_read(token, account_id, worker_name):
            # 写后校验：返回含关键绑定的列表
            domains = ["mail.xbltest.xyz", "new.xbltest.xyz"]
            return {
                "ok": True,
                "domains": domains,
                "bindings": [
                    {"type": "secret_text", "name": "JWT_SECRET"},
                    {"type": "d1", "name": "DB", "database_id": "db-1"},
                    {"type": "json", "name": "DOMAINS", "json": domains},
                    {"type": "json", "name": "DEFAULT_DOMAINS", "json": domains},
                    {
                        "type": "plain_text",
                        "name": "ENABLE_USER_CREATE_EMAIL",
                        "text": "true",
                    },
                ],
                "domains_binding_type": "json",
            }

        with patch.object(ds, "_cf_multipart_patch_settings", side_effect=fake_patch), \
                patch.object(ds, "read_worker_domains", side_effect=fake_read):
            result = ds.write_worker_domains(
                "tok",
                "acct",
                "temp-email",
                ["mail.xbltest.xyz", "new.xbltest.xyz"],
                existing_bindings=existing,
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(len(patch_calls), 1)
        names = [b["name"] for b in patch_calls[0]["bindings"]]
        self.assertIn("JWT_SECRET", names)
        self.assertIn("DB", names)
        self.assertIn("DOMAINS", names)
        jwt = next(b for b in patch_calls[0]["bindings"] if b["name"] == "JWT_SECRET")
        self.assertEqual(jwt, {"type": "secret_text", "name": "JWT_SECRET"})
        domains_b = next(b for b in patch_calls[0]["bindings"] if b["name"] == "DOMAINS")
        self.assertEqual(domains_b["type"], "json")
        self.assertEqual(
            domains_b["json"], ["mail.xbltest.xyz", "new.xbltest.xyz"]
        )

    def test_write_refuses_when_critical_binding_cannot_be_sanitized(self):
        existing = [
            {"type": "d1", "name": "DB"},  # 缺少 database_id
            {"type": "json", "name": "DOMAINS", "json": ["mail.xbltest.xyz"]},
        ]
        with patch.object(ds, "_cf_multipart_patch_settings") as patch_mock:
            result = ds.write_worker_domains(
                "tok",
                "acct",
                "temp-email",
                ["mail.xbltest.xyz"],
                existing_bindings=existing,
            )
        self.assertFalse(result["ok"])
        self.assertIn("拒绝写入", result["error"])
        self.assertIn("DB:d1", result["error"])
        patch_mock.assert_not_called()

    def test_write_fails_without_minimal_when_patch_errors(self):
        existing = [
            {"type": "secret_text", "name": "JWT_SECRET"},
            {"type": "json", "name": "DOMAINS", "json": ["mail.xbltest.xyz"]},
        ]

        def fake_patch(*args, **kwargs):
            return {
                "success": False,
                "errors": [{"message": "boom"}],
            }

        with patch.object(ds, "_cf_multipart_patch_settings", side_effect=fake_patch):
            result = ds.write_worker_domains(
                "tok",
                "acct",
                "temp-email",
                ["mail.xbltest.xyz", "x.xbltest.xyz"],
                existing_bindings=existing,
            )
        self.assertFalse(result["ok"])
        self.assertIn("未使用危险 minimal 回退", result["error"])


if __name__ == "__main__":
    unittest.main()
