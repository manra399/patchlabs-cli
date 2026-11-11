"""SARIF 2.1.0 structure (no schema download, so this checks the shape the GitHub upload needs)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchlabs_cli import engine, posture, sarif  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_FIX = os.path.join(HERE, "fixtures", "codescan", "pl010_tp")
RLS_FIX = os.path.join(HERE, "fixtures", "rls", "project")
LEVELS = {"none", "note", "warning", "error"}


def check_sarif(doc):
    """Raises AssertionError when the document is not SARIF 2.1.0 in the parts GitHub reads."""
    json.dumps(doc)  # must serialise
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "patchlabs-cli" and driver["version"]
    rules = driver["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    for r in rules:
        assert r["shortDescription"]["text"]
        float(r["properties"]["security-severity"])
    for res in run["results"]:
        assert res["level"] in LEVELS
        assert res["message"]["text"]
        assert 0 <= rules.index(next(r for r in rules if r["id"] == res["ruleId"])) < len(rules)
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        if "region" in loc:
            assert isinstance(loc["region"]["startLine"], int) and loc["region"]["startLine"] >= 1
        float(res["properties"]["security-severity"])
    return run


class TestSarif(unittest.TestCase):
    def test_code_findings_document_is_valid(self):
        findings = engine.scan_repo(CODE_FIX, offline=True)["findings"]
        self.assertTrue(findings)
        run = check_sarif(sarif.to_sarif(findings))
        self.assertEqual(len(run["results"]), len(findings))
        first = run["results"][0]
        self.assertEqual(first["level"], "error")
        self.assertIn("region", first["locations"][0]["physicalLocation"])

    def test_rls_findings_document_is_valid(self):
        findings = engine.scan_repo(RLS_FIX, offline=True)["findings"]
        run = check_sarif(sarif.to_sarif(findings))
        self.assertEqual([r["ruleId"] for r in run["results"]], ["PL-001"])
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "supabase/migrations/20240101000000_init.sql")

    def test_live_site_findings_use_the_page_address(self):
        r = {"status": 200, "headers": {}, "body": "", "cookies": ["sid=1"], "tls": None, "url": "https://example.com/"}
        out = posture.analyze("https://example.com", r, {"redirects": False, "seen": ["https://example.com/"]})
        run = check_sarif(sarif.to_sarif(out["findings"]))
        for res in run["results"]:
            loc = res["locations"][0]["physicalLocation"]
            self.assertEqual(loc["artifactLocation"]["uri"], "https://example.com")
            self.assertNotIn("region", loc)

    def test_empty_document_is_valid(self):
        run = check_sarif(sarif.to_sarif([]))
        self.assertEqual(run["results"], [])
        self.assertEqual(run["tool"]["driver"]["rules"], [])

    def test_severity_mapping(self):
        f = {"id": "PL-001", "title": "t", "severity": "medium", "file": "a.ts", "line_no": 1, "evidence": "e"}
        levels = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            levels[sev] = sarif.to_sarif([dict(f, severity=sev)])["runs"][0]["results"][0]["level"]
        self.assertEqual(levels, {"critical": "error", "high": "error", "medium": "warning", "low": "note",
                                  "info": "note"})


if __name__ == "__main__":
    unittest.main()
