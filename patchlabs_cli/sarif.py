"""SARIF 2.1.0 output, so GitHub code scanning can show the findings next to the code."""
from . import __version__
from .findings import CHECK_TITLES, FINDING_URL

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub code scanning reads security-severity (0.0 to 10.0) to rank alerts.
SECURITY_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}


def to_sarif(findings):
    rules, rule_index, rule_score, results = [], {}, {}, []
    for f in findings:
        rid = f["id"]
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rule_score[rid] = 0.0
            rules.append({"id": rid, "name": rid,
                          "shortDescription": {"text": CHECK_TITLES.get(rid, f["title"])},
                          "helpUri": FINDING_URL.format(rid), "properties": {"tags": ["security"]}})
        score = SECURITY_SEVERITY.get(f["severity"], 0.0)
        rule_score[rid] = max(rule_score[rid], score)
        message = f"{f['title']}: {f['evidence']}" if f.get("evidence") else f["title"]
        if f.get("file"):
            physical = {"artifactLocation": {"uri": f["file"]}}
            if f.get("line_no") and f["line_no"] >= 1:
                physical["region"] = {"startLine": int(f["line_no"])}
        else:
            physical = {"artifactLocation": {"uri": f["object"]}}  # live-site findings: the page address
        results.append({"ruleId": rid, "ruleIndex": rule_index[rid], "level": LEVEL.get(f["severity"], "note"),
                        "message": {"text": message}, "locations": [{"physicalLocation": physical}],
                        "properties": {"security-severity": str(score)}})
    for rid, idx in rule_index.items():
        rules[idx]["properties"]["security-severity"] = str(rule_score[rid])
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "patchlabs-cli", "version": __version__, "semanticVersion": __version__,
                                "informationUri": "https://patchlabs.dev", "rules": rules}},
            "invocations": [{"executionSuccessful": True}],
            "results": results,
        }],
    }
