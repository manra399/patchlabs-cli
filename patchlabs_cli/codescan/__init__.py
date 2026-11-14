"""PatchLabs Code scanner.

    from patchlabs_cli.codescan import scan
    result = scan("/path/to/repo")   # {"findings": [...], "stats": {...}}

Reads the repository as text only: never imports, executes or installs anything from it.
Static checks: PL-009 (Claude Code settings files), PL-010 (backup), PL-017..PL-022, PL-024..PL-026. Dependency check: PL-023 via OSV.
"""
import os
import time

from . import claude_settings, code_checks, lockfiles, osv, server_checks
from .common import MAX_PER_CHECK, SEVERITY_RANK, Repo

__all__ = ["scan"]

CHECKS = [
    ("PL-017/018", server_checks.check_config),
    ("PL-019", code_checks.check_user_metadata),
    ("PL-020", code_checks.check_client_admin),
    ("PL-021", server_checks.check_webhooks),
    ("PL-022", server_checks.check_trusted_ids),
    ("PL-024", code_checks.check_raw_html),
    ("PL-025", code_checks.check_firebase_rules),
    ("PL-026", server_checks.check_cors),
    ("PL-010", code_checks.check_client_secrets),
    ("PL-009", claude_settings.check_claude_settings),
]


def _offline_default():
    return os.environ.get("PATCHLABS_OFFLINE", "").lower() in ("1", "true", "yes")


def scan(repo_path, *, offline=None, budget_s=120.0):
    """Scan a checked-out repository. Never raises; problems are reported in stats."""
    t0 = time.monotonic()
    deadline = t0 + budget_s
    offline = _offline_default() if offline is None else offline
    stats = {"errors": []}
    if not repo_path or not os.path.isdir(repo_path):
        stats.update({"error": "repo path not found", "dependencies": "skipped: repo path not found",
                      "elapsed_s": 0.0})
        return {"findings": [], "stats": stats}
    try:
        repo = Repo(repo_path, deadline - 20)   # keep time for the dependency lookups
    except Exception as e:
        stats.update({"error": f"walk failed: {type(e).__name__}", "dependencies": "skipped: walk failed"})
        return {"findings": [], "stats": stats}
    repo.check_deadline = deadline - 10       # static checks stop here; OSV gets the rest
    stats["framework"] = repo.framework

    raw = []
    for name, fn in CHECKS:
        if time.monotonic() > deadline - 10:
            stats["errors"].append(f"{name}: skipped (time budget)")
            continue
        try:
            raw.extend(fn(repo))
        except Exception as e:  # one broken check must not sink the scan
            stats["errors"].append(f"{name}: {type(e).__name__}: {str(e)[:120]}")

    try:
        pkg_jsons = {r: f.text for r, f in repo.files.items() if f.base == "package.json"
                     and "/node_modules/" not in "/" + r}
        pkgs, sources, lock_errors = lockfiles.collect(repo.lockfiles, pkg_jsons)
        stats["errors"].extend(f"lockfile {e}" for e in lock_errors)
        texts = dict(repo.lockfiles)
        texts.update(pkg_jsons)
        dep_findings, dep_stats = osv.check_dependencies(pkgs, sources, texts, deadline - 1, offline=offline)
        if isinstance(dep_stats, dict):
            dep_stats["lockfiles"] = sorted(repo.lockfiles) or ["package.json (exact versions only)"]
        raw.extend(dep_findings)
        stats["dependencies"] = dep_stats
    except Exception as e:
        stats["dependencies"] = f"skipped: {type(e).__name__}"

    stats.update(repo.stats)
    findings, seen, per_check = [], set(), {}
    for f in sorted(raw, key=lambda d: (SEVERITY_RANK.get(d["severity"], 9), d["id"], d["file"] or "",
                                        d["line_no"] or 0, d["title"])):
        key = (f["id"], f["file"], f["line_no"])
        if key in seen:
            continue
        seen.add(key)
        per_check[f["id"]] = per_check.get(f["id"], 0) + 1
        if per_check[f["id"]] > MAX_PER_CHECK:
            continue
        findings.append(f)
    stats["counts"] = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_RANK}
    stats["by_check"] = dict(sorted(per_check.items()))
    stats["elapsed_s"] = round(time.monotonic() - t0, 2)
    return {"findings": findings, "stats": stats}
