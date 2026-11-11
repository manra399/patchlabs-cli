"""The finding shape shared by every check, its ordering, de-duplication and the title of each check."""
from .codescan.common import MAX_PER_CHECK, SEVERITY_RANK
from .rls import TITLES as RLS_TITLES

FINDING_URL = "https://patchlabs.dev/findings/{}"

# One title per check id, taken from the code. Some checks produce several titles; the first is shown here.
CHECK_TITLES = dict(RLS_TITLES)
CHECK_TITLES.update({
    "PL-010": "Service role key in client code",
    "PL-017": "Edge function open without sign-in while using the service key",
    "PL-018": "Sign-ups need no email confirmation",
    "PL-019": "Access decided by user_metadata, which users can edit",
    "PL-020": "Admin check only in the browser",
    "PL-021": "Payment webhook doesn't verify its signature",
    "PL-022": "Server route trusts a user id sent in the request",
    "PL-023": "Dependency with a known vulnerability",
    "PL-024": "User content rendered as raw HTML",
    "PL-025": "Firebase rules allow anyone to read and write",
    "PL-026": "Any website can call a signed-in function (CORS reflects any origin)",
    "PL-027": "Site doesn't force HTTPS",
    "PL-028": "TLS certificate is invalid, expired or about to expire",
    "PL-029": "No HSTS header, or max-age under 180 days",
    "PL-030": "No Content-Security-Policy",
    "PL-031": "Any site can frame the page",
    "PL-032": "No X-Content-Type-Options: nosniff",
    "PL-033": "Cookie set without Secure, or a session cookie without HttpOnly",
    "PL-034": "Page loads scripts or styles over plain HTTP",
    "PL-035": "Server headers reveal software versions",
    "PL-036": "No Referrer-Policy",
})


def location(f):
    """'file:line' for code findings, the page address for live-site findings."""
    if f.get("file"):
        return f"{f['file']}:{f['line_no']}" if f.get("line_no") else f["file"]
    return f.get("object") or ""


def sort_key(f):
    return (SEVERITY_RANK.get(f["severity"], 9), f["id"], f.get("file") or "", f.get("line_no") or 0, f["title"])


def order_and_limit(found):
    """Same order, de-duplication and per-check cap as codescan.scan(). Returns (findings, count per check)."""
    out, seen, per_check = [], set(), {}
    for f in sorted(found, key=sort_key):
        key = (f["id"], f.get("file"), f.get("line_no"))
        if key in seen:
            continue
        seen.add(key)
        per_check[f["id"]] = per_check.get(f["id"], 0) + 1
        if per_check[f["id"]] > MAX_PER_CHECK:
            continue
        out.append(f)
    return out, dict(sorted(per_check.items()))


def counts(findings):
    return {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_RANK}
