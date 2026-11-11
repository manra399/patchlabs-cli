"""PL-023: lockfile parsers and the OSV client, with urlopen stubbed (no network)."""
import io
import json
import os
import socket
import sys
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from patchlabs_cli.codescan import scan, lockfiles, osv  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "codescan")


def read_dir(name):
    locks, pj = {}, {}
    for n in sorted(os.listdir(os.path.join(FIX, name))):
        with open(os.path.join(FIX, name, n)) as fh:
            t = fh.read()
        (pj if n == "package.json" else locks)[n] = t
    return locks, pj


def names(name):
    pkgs, _, errors = lockfiles.collect(*read_dir(name))
    assert not errors, errors
    return [(p.name, p.version, p.direct, p.dev) for p in pkgs]


class TestParsers(unittest.TestCase):
    def test_npm_v3(self):
        self.assertEqual(names("deps_npm_v3"), [
            ("lodash", "4.17.20", True, False), ("react", "18.3.1", True, False), ("vite", "5.0.0", True, True),
            ("loose-envify", "1.4.0", False, False), ("esbuild", "0.19.0", False, True)])

    def test_npm_v1(self):
        got = names("deps_npm_v1")
        self.assertIn(("loose-envify", "1.4.0", False, False), got)
        self.assertIn(("lodash", "4.17.20", True, False), got)
        self.assertEqual(len(got), 4)

    def test_pnpm_v9_v6_v5(self):
        self.assertEqual(sorted(n[:2] for n in names("deps_pnpm")),
                         [("@babel/core", "7.24.0"), ("lodash", "4.17.20"), ("react-dom", "18.3.1")])
        expect = [("@babel/core", "7.24.0"), ("react-dom", "18.3.1")]
        self.assertEqual(sorted(n[:2] for n in names("deps_pnpm_v6")), expect)
        self.assertEqual(sorted(n[:2] for n in names("deps_pnpm_v5")), expect)

    def test_yarn_classic_and_berry(self):
        self.assertEqual(sorted(n[:2] for n in names("deps_yarn")),
                         [("@babel/core", "7.24.0"), ("lodash", "4.17.20"), ("string-width", "4.2.3")])
        self.assertEqual([n[:2] for n in names("deps_yarn_berry")], [("lodash", "4.17.20")])

    def test_bun_jsonc(self):
        self.assertEqual(sorted(n[:2] for n in names("deps_bun")),
                         [("@types/react", "18.3.3"), ("lodash", "4.17.20"), ("scheduler", "0.23.2")])

    def test_package_json_exact_only(self):
        # near miss: ranges (^18.3.1, ~5.0.0) are not guessed
        self.assertEqual(names("deps_pkgjson"), [("left-pad", "1.3.0", True, False),
                                                 ("lodash", "4.17.20", True, False)])

    def test_strip_jsonc_keeps_strings(self):
        self.assertEqual(json.loads(lockfiles.strip_jsonc('{"a": "x // y, }", /* c */ "b": [1, 2,],}')),
                         {"a": "x // y, }", "b": [1, 2]})

    def test_malformed_lockfile_reported(self):
        pkgs, _, errors = lockfiles.collect({"package-lock.json": "{not json"}, {})
        self.assertEqual(pkgs, [])
        self.assertTrue(errors)


class TestVersionsAndSeverity(unittest.TestCase):
    def test_vkey(self):
        self.assertLess(osv.vkey("1.2.3-beta.1"), osv.vkey("1.2.3"))
        self.assertLess(osv.vkey("1.2.3"), osv.vkey("1.10.0"))
        self.assertLess(osv.vkey("0"), osv.vkey("0.0.1"))

    def test_cvss(self):
        self.assertEqual(osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(osv.cvss3_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"), 0.0)
        self.assertIsNone(osv.cvss3_score("garbage"))

    def test_severity_sources(self):
        self.assertEqual(osv.severity_of({"id": "MAL-2024-1"}), "critical")
        self.assertEqual(osv.severity_of({"id": "G", "database_specific": {"severity": "MODERATE"}}), "medium")
        self.assertEqual(osv.severity_of({"id": "G", "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}), "critical")
        self.assertIsNone(osv.severity_of({"id": "G"}))

    def test_fixed_version_picks_matching_range(self):
        v = {"affected": [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "1.2.4"}, {"introduced": "2.0.0"}, {"fixed": "2.0.3"}]}]}]}
        self.assertEqual(osv.fixed_version(v, "x", "1.2.0"), "1.2.4")
        self.assertEqual(osv.fixed_version(v, "x", "2.0.1"), "2.0.3")
        self.assertIsNone(osv.fixed_version(v, "y", "2.0.1"))


# ---------------------------------------------------------------- stubbed OSV

ADV = {
    "GHSA-test-0000-0001": {"id": "GHSA-test-0000-0001", "summary": "Prototype pollution in lodash",
                            "database_specific": {"severity": "HIGH"},
                            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [
                                {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
    "CVE-test-0002": {"id": "CVE-test-0002", "aliases": ["GHSA-test-0000-0002"], "summary": "Command injection",
                      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                      "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [
                          {"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.20"},
                                                        {"introduced": "4.17.20"}, {"fixed": "4.17.22"}]}]}]},
}
VULNERABLE = {("lodash", "4.17.20"): ["GHSA-test-0000-0001", "CVE-test-0002"]}


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeOSV:
    def __init__(self, vulnerable=None, advisories=None):
        self.vulnerable = VULNERABLE if vulnerable is None else vulnerable
        self.advisories = ADV if advisories is None else advisories
        self.batches, self.details = [], []

    def __call__(self, req, timeout=None):
        assert timeout and timeout <= 25
        url = req.full_url
        if url == osv.BATCH_URL:
            body = json.loads(req.data)
            self.batches.append(body["queries"])
            res = []
            for q in body["queries"]:
                assert q["package"]["ecosystem"] == "npm"
                ids = self.vulnerable.get((q["package"]["name"], q["version"]), [])
                res.append({"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in ids]} if ids else {})
            return FakeResp(json.dumps({"results": res}).encode())
        vid = url.rsplit("/", 1)[1]
        self.details.append(vid)
        if vid not in self.advisories:
            raise HTTPError(url, 404, "not found", {}, None)
        return FakeResp(json.dumps(self.advisories[vid]).encode())


class TestOSV(unittest.TestCase):
    def run_scan(self, fake, fixture="deps_npm_v3"):
        with mock.patch.object(osv, "urlopen", fake):
            return scan(os.path.join(FIX, fixture), offline=False)

    def test_grouped_finding_with_fix_and_advisory(self):
        fake = FakeOSV()
        r = self.run_scan(fake)
        deps = [f for f in r["findings"] if f["id"] == "PL-023"]
        self.assertEqual(len(deps), 1)
        f = deps[0]
        self.assertEqual(f["severity"], "critical")             # max of HIGH and CVSS 9.8
        self.assertEqual(f["object"], "npm:lodash@4.17.20")
        self.assertEqual(f["file"], "package-lock.json")
        self.assertEqual(f["fix"], "Upgrade lodash to 4.17.22 or later.")
        self.assertEqual(f["advisory"], "GHSA-test-0000-0001, GHSA-test-0000-0002")
        self.assertEqual(f["line"], "code")
        self.assertIn("direct", f["evidence"])
        with open(os.path.join(FIX, "deps_npm_v3", "package-lock.json")) as fh:
            lock_lines = fh.read().splitlines()
        self.assertIn("lodash", lock_lines[f["line_no"] - 1])
        st = r["stats"]["dependencies"]
        self.assertEqual((st["packages"], st["vulnerable_packages"], st["details_fetched"]), (5, 1, 2))
        # direct dependencies are queried first
        self.assertEqual([q["package"]["name"] for q in fake.batches[0]][:3], ["lodash", "react", "vite"])

    def test_near_miss_clean_packages_no_findings(self):
        r = self.run_scan(FakeOSV(vulnerable={}))
        self.assertEqual([f for f in r["findings"] if f["id"] == "PL-023"], [])
        self.assertEqual(r["stats"]["dependencies"]["vulnerable_packages"], 0)

    def test_offline_and_timeouts_skip(self):
        for exc in (URLError(OSError("no route")), socket.timeout("timed out"), TimeoutError(),
                    HTTPError(osv.BATCH_URL, 503, "busy", {}, None), ConnectionResetError()):
            def boom(req, timeout=None, _e=exc):
                raise _e
            r = self.run_scan(boom)
            self.assertIsInstance(r["stats"]["dependencies"], str, exc)
            self.assertTrue(r["stats"]["dependencies"].startswith("skipped: "), r["stats"]["dependencies"])
            self.assertEqual([f for f in r["findings"] if f["id"] == "PL-023"], [])

    def test_offline_flag_makes_no_requests(self):
        def never(req, timeout=None):
            raise AssertionError("network used")
        with mock.patch.object(osv, "urlopen", never):
            r = scan(os.path.join(FIX, "deps_npm_v3"), offline=True)
        self.assertEqual(r["stats"]["dependencies"], "skipped: offline mode")

    def test_batch_and_detail_caps(self):
        pkgs = [lockfiles.Pkg(f"pkg{i:03d}", "1.0.0", direct=i < 10) for i in range(650)]
        vulnerable = {(p.name, "1.0.0"): [f"GHSA-cap-{i:04d}-0001", f"GHSA-cap-{i:04d}-0002"]
                      for i, p in enumerate(pkgs[:40])}
        advisories = {v: {"id": v, "database_specific": {"severity": "LOW"}} for ids in vulnerable.values()
                      for v in ids}
        fake = FakeOSV(vulnerable, advisories)
        import time
        with mock.patch.object(osv, "urlopen", fake):
            findings, stats = osv.check_dependencies(pkgs, {}, {}, time.monotonic() + 60)
        self.assertEqual([len(b) for b in fake.batches], [300, 300, 50])
        self.assertEqual(len(fake.details), 30)
        # round-robin: the first 30 packages each got one lookup before any second lookup
        self.assertTrue(all(d.endswith("-0001") for d in fake.details))
        self.assertEqual(len(findings), 40)
        self.assertEqual(stats["vulnerable_packages"], 40)
        unlooked = [f for f in findings if "not looked up" in f["evidence"]]
        self.assertEqual(len(unlooked), 10)

    def test_time_budget_exhausted_skips(self):
        import time
        findings, stats = osv.check_dependencies([lockfiles.Pkg("a", "1.0.0")], {}, {}, time.monotonic() + 1)
        self.assertEqual(findings, [])
        self.assertEqual(stats, "skipped: time budget used up")

    def test_no_packages(self):
        r = self.run_scan(FakeOSV(), fixture="pl018_tp")
        self.assertTrue(r["stats"]["dependencies"].startswith("skipped: no lockfile"))


if __name__ == "__main__":
    unittest.main()
