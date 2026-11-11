"""True positive and near-miss false positive for every static check."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
os.environ["PATCHLABS_OFFLINE"] = "1"   # no network in tests

from patchlabs_cli.codescan import scan  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "codescan")
_cache = {}


def run(name):
    if name not in _cache:
        _cache[name] = scan(os.path.join(FIX, name), offline=True)
    return _cache[name]


def hits(name, fid, severity=None):
    return [(f["file"], f["line_no"], f["severity"]) for f in run(name)["findings"]
            if f["id"] == fid and (severity is None or f["severity"] == severity)]


class TestPL017(unittest.TestCase):
    def test_open_function_with_service_key_is_high(self):
        self.assertEqual(hits("pl017_tp", "PL-017", "high"), [("supabase/config.toml", 4, "high")])
        f = next(f for f in run("pl017_tp")["findings"] if f["severity"] == "high")
        self.assertEqual(f["object"], "supabase/functions/admin-delete-user")
        self.assertFalse(f["proven"])

    def test_open_function_without_service_key_is_info(self):
        self.assertEqual(hits("pl017_tp", "PL-017", "info"), [("supabase/config.toml", 7, "info")])

    def test_near_miss_self_checked_or_jwt_on(self):
        self.assertEqual(hits("pl017_fp", "PL-017", "high"), [])
        # send-invite (getUser via shared admin client) and stripe-webhook (constructEventAsync) -> info only
        self.assertEqual(len(hits("pl017_fp", "PL-017", "info")), 2)
        self.assertFalse(any("normal" in f["evidence"] for f in run("pl017_fp")["findings"]))


class TestPL018(unittest.TestCase):
    def test_confirmations_off(self):
        self.assertEqual(hits("pl018_tp", "PL-018"), [("supabase/config.toml", 6, "low")])

    def test_near_miss_on_or_sms(self):
        self.assertEqual(hits("pl018_fp", "PL-018"), [])


class TestPL019(unittest.TestCase):
    def test_code_and_sql(self):
        got = hits("pl019_tp", "PL-019")
        self.assertIn(("src/hooks/useIsAdmin.ts", 4, "critical"), got)
        self.assertIn(("src/pages/Pro.tsx", 2, "high"), got)
        self.assertIn(("supabase/migrations/20240101000000_init.sql", 2, "critical"), got)
        self.assertIn(("supabase/migrations/20240101000000_init.sql", 6, "critical"), got)
        self.assertEqual(len(got), 4)

    def test_near_miss_full_name_app_metadata_comments(self):
        self.assertEqual(hits("pl019_fp", "PL-019"), [])


class TestPL020(unittest.TestCase):
    def test_email_lists_and_localstorage(self):
        got = hits("pl020_tp", "PL-020")
        self.assertEqual(sorted(got), [("src/config.ts", 1, "high"), ("src/lib/admin.ts", 1, "high"),
                                       ("src/pages/Admin.tsx", 2, "high")])
        for f in run("pl020_tp")["findings"]:
            self.assertFalse(f["proven"])
            self.assertNotIn("owner@example.com", f["evidence"])  # emails are masked

    def test_near_miss_support_email_theme_server_list(self):
        self.assertEqual(hits("pl020_fp", "PL-020"), [])


class TestPL021(unittest.TestCase):
    def test_unverified_webhooks(self):
        self.assertEqual(sorted(hits("pl021_tp", "PL-021")), [("api/lemon-webhook.ts", 3, "high"),
                                                              ("supabase/functions/stripe-webhook/index.ts", 5,
                                                               "high")])

    def test_near_miss_verified_and_checkout(self):
        self.assertEqual(hits("pl021_fp", "PL-021"), [])


class TestPL022(unittest.TestCase):
    def test_trusted_ids(self):
        self.assertEqual(sorted(hits("pl022_tp", "PL-022")), [
            ("supabase/functions/delete-account/index.ts", 5, "high"),
            ("supabase/functions/get-orders/index.ts", 4, "high"),
            ("supabase/functions/update-credits/index.ts", 5, "high")])

    def test_near_miss_getuser_or_anon_client(self):
        self.assertEqual(hits("pl022_fp", "PL-022"), [])


class TestPL024(unittest.TestCase):
    def test_raw_html(self):
        self.assertEqual(sorted(hits("pl024_tp", "PL-024")), [("src/components/Comment.tsx", 2, "medium"),
                                                              ("src/components/Post.tsx", 5, "medium"),
                                                              ("src/lib/render.ts", 2, "medium")])

    def test_near_miss_sanitised_static_style(self):
        self.assertEqual(hits("pl024_fp", "PL-024"), [])


class TestPL025(unittest.TestCase):
    def test_open_rules(self):
        got = sorted(hits("pl025_tp", "PL-025"))
        self.assertEqual(got, [("database.rules.json", 3, "critical"), ("database.rules.json", 4, "critical"),
                               ("firestore.rules", 5, "critical"), ("other/firestore.rules", 4, "high"),
                               ("storage.rules", 5, "critical")])

    def test_near_miss_scoped_rules_comment_expired(self):
        self.assertEqual([h for h in hits("pl025_fp", "PL-025") if h[2] != "info"], [])
        self.assertEqual(hits("pl025_fp", "PL-025", "info"), [("storage.rules", 4, "info")])


class TestPL026(unittest.TestCase):
    def test_cors_with_cookies_or_reflection(self):
        self.assertEqual(sorted(hits("pl026_tp", "PL-026", "medium")), [
            ("api/me.ts", 2, "medium"), ("supabase/functions/session/index.ts", 2, "medium")])

    def test_near_miss_bearer_only_allowlist_noauth(self):
        self.assertEqual(hits("pl026_fp", "PL-026", "medium"), [])
        # bearer-token function is reported as info only; ping (no auth) and allow-listed origin not at all
        self.assertEqual(hits("pl026_fp", "PL-026"), [("supabase/functions/profile/index.ts", 2, "info")])


class TestPL010(unittest.TestCase):
    def test_client_secrets(self):
        got = sorted(hits("pl010_tp", "PL-010"))
        self.assertEqual(got, [(".env", 2, "critical"),
                               ("src/integrations/supabase/admin.ts", 1, "critical"),
                               ("src/lib/env.ts", 1, "critical"), ("src/lib/env.ts", 2, "high"),
                               ("src/lib/stripe.ts", 1, "critical")])
        for f in run("pl010_tp")["findings"]:
            self.assertEqual(f["source"], "codescan")

    def test_near_miss_anon_publishable_server_example_tests(self):
        self.assertEqual(hits("pl010_fp", "PL-010"), [])


if __name__ == "__main__":
    unittest.main()
