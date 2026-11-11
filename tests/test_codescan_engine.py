"""Walker skip rules, finding shape, redaction, dedupe, determinism and failure handling."""
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
os.environ["PATCHLABS_OFFLINE"] = "1"

from patchlabs_cli.codescan import scan  # noqa: E402
from patchlabs_cli.codescan.common import redact, Repo  # noqa: E402
from patchlabs_cli.codescan import code_checks  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "codescan")
KEYS = {"id", "line", "severity", "title", "object", "file", "line_no", "evidence", "proven", "proof", "fix",
        "fixed_in_lab", "source"}


class TestWalker(unittest.TestCase):
    def test_skips_node_modules_dist_minified_large(self):
        r = scan(os.path.join(FIX, "skip_rules"), offline=True)
        files = {f["file"] for f in r["findings"]}
        self.assertEqual(files, {"src/real.ts"})
        self.assertEqual(r["stats"]["skipped_large"], 1)
        self.assertEqual(r["stats"]["skipped_minified"], 2)

    def test_symlinks_not_followed(self):
        d = tempfile.mkdtemp()
        outside = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "src"))
            with open(os.path.join(outside, "x.ts"), "w") as fh:
                fh.write('localStorage.getItem("isAdmin");\n')
            os.symlink(os.path.join(outside, "x.ts"), os.path.join(d, "src", "link.ts"))
            os.symlink(outside, os.path.join(d, "src", "linkdir"))
            self.assertEqual(scan(d, offline=True)["findings"], [])
        finally:
            shutil.rmtree(d)
            shutil.rmtree(outside)


class TestShape(unittest.TestCase):
    def test_every_fixture_finding_has_contract_shape(self):
        for name in sorted(os.listdir(FIX)):
            r = scan(os.path.join(FIX, name), offline=True)
            self.assertEqual(r["stats"]["errors"], [], name)
            for f in r["findings"]:
                self.assertTrue(KEYS <= set(f), (name, f))
                self.assertEqual(f["line"], "code")
                self.assertIn(f["severity"], ("critical", "high", "medium", "low", "info"))
                self.assertRegex(f["id"], r"^PL-0\d\d$")
                self.assertIsInstance(f["line_no"], int)
                self.assertLessEqual(len(f["evidence"]), 180)
                self.assertTrue(f["fix"] and f["title"])

    def test_no_secret_values_in_output(self):
        r = scan(os.path.join(FIX, "pl010_tp"), offline=True)
        blob = json.dumps(r)
        self.assertNotIn("FAKE0test0FAKE0test", blob)
        self.assertNotIn("FAKEsignatureFAKE", blob)
        self.assertNotRegex(blob, r"eyJ[A-Za-z0-9_-]{20,}")

    def test_redact_patterns(self):
        self.assertEqual(redact('k = "sk_live_' + "a1b2c3d4e5f6g7h8" + 'abcd"'), 'k = "sk_live_••••abcd"')
        self.assertIn("•", redact("OPENAI_API_KEY=sk-proj-" + "x" * 40))
        self.assertEqual(redact("contact owner@example.com"), "contact o••••@example.com")
        self.assertEqual(redact('Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")'), 'Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")')
        self.assertTrue(redact("x" * 500).endswith("…"))


class TestEngine(unittest.TestCase):
    def test_deterministic(self):
        a = scan(os.path.join(FIX, "pl025_tp"), offline=True)["findings"]
        b = scan(os.path.join(FIX, "pl025_tp"), offline=True)["findings"]
        self.assertEqual(a, b)
        ranks = [("critical", "high", "medium", "low", "info").index(f["severity"]) for f in a]
        self.assertEqual(ranks, sorted(ranks))

    def test_dedupe_same_id_file_line(self):
        import patchlabs_cli.codescan as codescan
        orig = list(codescan.CHECKS)
        # run the PL-020 check twice: every finding appears twice in the raw list
        codescan.CHECKS.append(("dup", code_checks.check_client_admin))
        try:
            r = scan(os.path.join(FIX, "pl020_tp"), offline=True)
            keys = [(f["id"], f["file"], f["line_no"]) for f in r["findings"]]
            self.assertEqual(len(keys), 3)
            self.assertEqual(len(keys), len(set(keys)))
        finally:
            codescan.CHECKS[:] = orig

    def test_missing_path_does_not_raise(self):
        r = scan("/nonexistent/patchlabs/repo")
        self.assertEqual(r["findings"], [])
        self.assertTrue(r["stats"]["dependencies"].startswith("skipped:"))

    def test_broken_check_is_reported_not_raised(self):
        orig = code_checks.check_raw_html

        def boom(repo):
            raise RuntimeError("boom")
        import patchlabs_cli.codescan as codescan
        idx = [n for n, _ in codescan.CHECKS].index("PL-024")
        codescan.CHECKS[idx] = ("PL-024", boom)
        try:
            r = scan(os.path.join(FIX, "pl024_tp"), offline=True)
            self.assertEqual(r["findings"], [])
            self.assertTrue(any("PL-024" in e for e in r["stats"]["errors"]))
        finally:
            codescan.CHECKS[idx] = ("PL-024", orig)

    def test_tiny_budget_truncates_without_raising(self):
        r = scan(os.path.join(FIX, "pl010_tp"), offline=False, budget_s=0.5)
        self.assertTrue(r["stats"]["truncated"])
        self.assertTrue(r["stats"]["dependencies"].startswith("skipped:"))

    def test_long_hostile_lines_are_fast(self):
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "src"))
            hostile = ("{" * 1500 + "\n" + "user_metadata" + "." * 1900 + "\n" + "a@" * 900 + "\n") * 50
            with open(os.path.join(d, "src", "h.ts"), "w") as fh:
                fh.write(hostile)
            import time
            t = time.monotonic()
            scan(d, offline=True)
            self.assertLess(time.monotonic() - t, 5)
        finally:
            shutil.rmtree(d)

    def test_next_server_files_not_client(self):
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "app", "api", "admin"))
            os.makedirs(os.path.join(d, "components"))
            with open(os.path.join(d, "package.json"), "w") as fh:
                fh.write('{"dependencies": {"next": "14.2.0"}}')
            with open(os.path.join(d, "app", "api", "admin", "route.ts"), "w") as fh:
                fh.write('const key = process.env.SUPABASE_SERVICE_ROLE_KEY;\n')
            with open(os.path.join(d, "components", "Panel.tsx"), "w") as fh:
                fh.write('"use client";\nconst key = process.env.SUPABASE_SERVICE_ROLE_KEY;\n')
            r = scan(d, offline=True)
            self.assertEqual([(f["id"], f["file"]) for f in r["findings"]], [("PL-010", "components/Panel.tsx")])
            self.assertEqual(r["stats"]["framework"], "next")
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
