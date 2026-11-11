"""Exit codes, output rules and the no-network guarantee of the command line."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from patchlabs_cli import cli, output, posture  # noqa: E402
from patchlabs_cli.codescan import osv  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "codescan")
RLS = os.path.join(HERE, "fixtures", "rls", "project")
CRITICAL = os.path.join(FIX, "pl010_tp")       # critical findings
HIGH_ONLY = os.path.join(FIX, "pl021_tp")      # high findings only
FOOTER = ("Static checks only. To prove who can read what in a rebuilt copy of your database and get a re-tested fix, "
          "run the hosted check at https://patchlabs.dev")


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class TestExitCodes(unittest.TestCase):
    def test_critical_fails_by_default(self):
        self.assertEqual(run(["scan", CRITICAL, "--offline"])[0], 1)

    def test_high_fails_by_default_but_not_at_critical(self):
        self.assertEqual(run(["scan", HIGH_ONLY, "--offline"])[0], 1)
        self.assertEqual(run(["scan", HIGH_ONLY, "--offline", "--fail-on", "critical"])[0], 0)

    def test_fail_on_none_never_fails(self):
        self.assertEqual(run(["scan", CRITICAL, "--offline", "--fail-on", "none"])[0], 0)

    def test_clean_folder_exits_zero(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "README.txt"), "w") as fh:
                fh.write("nothing here\n")
            code, out, _ = run(["scan", d, "--offline"])
            self.assertEqual(code, 0)
            self.assertIn("No findings.", out)
        finally:
            shutil.rmtree(d)

    def test_usage_errors_exit_two(self):
        self.assertEqual(run(["scan", "/nonexistent/patchlabs/path"])[0], 2)
        self.assertEqual(run(["scan", CRITICAL, "--fail-on", "bogus"])[0], 2)
        self.assertEqual(run([])[0], 2)
        self.assertEqual(run(["headers", "not a site!"])[0], 2)
        self.assertEqual(run(["headers", "http://192.168.0.1"])[0], 2)

    def test_help_and_version_exit_zero(self):
        self.assertEqual(run(["--help"])[0], 0)
        self.assertEqual(run(["--version"])[0], 0)

    def test_unreachable_site_exits_three(self):
        with mock.patch.object(posture, "fetch", side_effect=posture.Unreachable("We couldn't connect to x.example.")):
            code, _, err = run(["headers", "https://x.example.com"])
        self.assertEqual(code, 3)
        self.assertIn("couldn't connect", err)

    def test_headers_exit_codes_follow_fail_on(self):
        def fake(url, verify=True):
            if url.startswith("http://"):
                return {"status": 200, "headers": {}, "body": "", "cookies": [], "tls": None}
            return {"status": 200, "headers": {}, "body": "", "cookies": [], "tls": {"version": "TLSv1.3",
                    "cert": None}}
        with mock.patch.object(posture, "fetch", side_effect=fake):
            code, out, _ = run(["headers", "https://example.com", "--json"])
            medium, _, _ = run(["headers", "https://example.com", "--json", "--fail-on", "medium"])
        self.assertEqual(code, 0)      # only medium and low findings: the default threshold is high
        self.assertEqual(medium, 1)    # a medium finding exists: --fail-on medium fails
        doc = json.loads(out)
        self.assertEqual(doc["command"], "headers")
        self.assertIn(doc["grade"], "BCD")


class TestScanOutput(unittest.TestCase):
    def test_json_document(self):
        code, out, _ = run(["scan", CRITICAL, "--offline", "--json"])
        doc = json.loads(out)
        self.assertEqual(doc["tool"], "patchlabs-cli")
        self.assertEqual(doc["version"], "0.1.0")
        self.assertEqual(doc["command"], "scan")
        self.assertTrue(doc["findings"])
        self.assertTrue(doc["stats"]["dependencies"].startswith("skipped:"))  # no lockfile in this fixture
        self.assertEqual(code, 1)

    def test_no_secret_values_on_stdout(self):
        _, human, _ = run(["scan", CRITICAL, "--offline"])
        _, machine, _ = run(["scan", CRITICAL, "--offline", "--json"])
        for text in (human, machine):
            self.assertNotIn("FAKE0test0FAKE0test", text)
            self.assertNotIn("sk_live_51FAKE", text)

    def test_human_table_has_ids_links_and_footer(self):
        _, out, _ = run(["scan", CRITICAL, "--offline"])
        self.assertIn("SEVERITY  ID", out)
        self.assertIn("https://patchlabs.dev/findings/PL-010", out)
        self.assertIn("src/lib/stripe.ts:1", out)
        self.assertEqual(out.rstrip("\n").splitlines()[-1], FOOTER)
        self.assertNotIn("\x1b[", out)  # not a terminal: no colour codes

    def test_rls_read_finds_anon_policy_on_personal_data(self):
        code, out, _ = run(["scan", RLS, "--offline", "--json"])
        doc = json.loads(out)
        self.assertEqual([(f["id"], f["severity"], f["file"]) for f in doc["findings"]],
                         [("PL-001", "critical", "supabase/migrations/20240101000000_init.sql")])
        self.assertEqual(doc["stats"]["sql_files"], 1)
        self.assertEqual(code, 1)

    def test_sarif_file_is_written_and_valid(self):
        d = tempfile.mkdtemp()
        try:
            target = os.path.join(d, "out.sarif")
            code, out, _ = run(["scan", RLS, "--offline", "--sarif", target])
            with open(target, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["version"], "2.1.0")
            self.assertEqual(doc["runs"][0]["results"][0]["ruleId"], "PL-001")
            self.assertIn("SEVERITY  ID", out)  # the table still prints
        finally:
            shutil.rmtree(d)

    def test_sarif_into_missing_folder_is_usage_error(self):
        code, _, err = run(["scan", RLS, "--offline", "--sarif", "/nonexistent/dir/out.sarif"])
        self.assertEqual(code, 2)
        self.assertIn("cannot write", err)

    def test_offline_scan_opens_no_connections(self):
        def boom(*a, **k):
            raise AssertionError("network used during an offline scan")
        with mock.patch.object(osv, "urlopen", boom), mock.patch("socket.getaddrinfo", boom), \
                mock.patch("socket.create_connection", boom):
            self.assertEqual(run(["scan", CRITICAL, "--offline"])[0], 1)


class TestColour(unittest.TestCase):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    def test_colour_only_on_a_terminal(self):
        self.assertTrue(output.colour_enabled(self.Tty()))
        self.assertFalse(output.colour_enabled(io.StringIO()))

    def test_no_color_disables_colour(self):
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(output.colour_enabled(self.Tty()))
        with mock.patch.dict(os.environ, {"NO_COLOR": ""}):
            self.assertTrue(output.colour_enabled(self.Tty()))

    def test_coloured_render_has_codes_and_plain_has_none(self):
        findings = [{"id": "PL-010", "severity": "critical", "title": "t", "file": "a.ts", "line_no": 2}]
        self.assertIn("\x1b[1;31m", output.render("h", [], findings, colour=True))
        self.assertNotIn("\x1b[", output.render("h", [], findings, colour=False))


class TestModuleEntry(unittest.TestCase):
    def test_python_dash_m_runs_the_cli(self):
        proc = subprocess.run([sys.executable, "-m", "patchlabs_cli", "scan", CRITICAL, "--offline", "--json"],
                              cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["command"], "scan")


if __name__ == "__main__":
    unittest.main()


class RowCapTest(unittest.TestCase):
    def test_table_shows_first_rows_and_says_how_many_more(self):
        from patchlabs_cli import output
        f = {"severity": "low", "id": "PL-029", "title": "t", "file": "a.sql", "line_no": 1}
        text = output.render("h", [], [dict(f) for _ in range(60)], colour=False, max_rows=50)
        self.assertIn("... and 10 more", text)
