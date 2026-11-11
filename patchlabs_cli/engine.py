"""Runs the code checks and the static RLS read on one repository, then merges the findings."""
import time

from . import rls, sqlfiles
from .codescan import scan as codescan_scan
from .findings import counts, order_and_limit


def scan_repo(root, offline=False):
    """Returns {"findings": [...], "stats": {...}}. Never raises for problems inside the repository."""
    t0 = time.monotonic()
    result = codescan_scan(root, offline=True if offline else None)
    stats = result["stats"]
    found = list(result["findings"])
    errors = list(stats.get("errors", []))
    try:
        files, sql_stats = sqlfiles.collect(root)
        n_tables = 0
        for project, group in sqlfiles.group(files).items():
            tables, raw = rls.analyze(group)
            n_tables += len(tables)
            found.extend(rls.to_findings(raw))
        stats.update(sql_stats)
        stats["rls_tables"] = n_tables
        stats["rls_projects"] = len(sqlfiles.group(files))
    except Exception as e:  # the RLS read must not sink the code checks
        errors.append(f"rls: {type(e).__name__}: {str(e)[:120]}")
    merged, per_check = order_and_limit(found)
    stats["errors"] = errors
    stats["counts"] = counts(merged)
    stats["by_check"] = per_check
    stats["elapsed_s"] = round(time.monotonic() - t0, 2)
    return {"findings": merged, "stats": stats}
