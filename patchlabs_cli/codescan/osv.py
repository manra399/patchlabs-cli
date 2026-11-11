"""PL-023: known-vulnerable npm dependencies via the OSV API (https://osv.dev).

Only package names and versions are sent to OSV. Network failures never raise: the caller gets
stats "skipped: <reason>".
"""
import json
import math
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .. import __version__
from .common import SEVERITY_RANK, finding

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{}"
BATCH_SIZE = 300
MAX_BATCHES = 10
MAX_DETAILS = 30
DETAIL_WORKERS = 6
MAX_BODY = 8_000_000
UA = f"patchlabs-cli/{__version__} (+https://patchlabs.dev)"


class Skip(Exception):
    pass


def _request(url, payload, timeout):
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": UA,
                                           "Accept": "application/json"},
                  method="POST" if data is not None else "GET")
    try:
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read(MAX_BODY).decode("utf-8", "replace"))
    except HTTPError as e:
        code = e.code
        try:
            e.close()
        except Exception:
            pass
        raise Skip(f"OSV HTTP {code}")
    except (URLError, socket.timeout, TimeoutError, ConnectionError) as e:
        reason = getattr(e, "reason", e)
        raise Skip(f"OSV unreachable ({type(reason).__name__ if not isinstance(reason, str) else reason})")
    except (OSError, ValueError) as e:
        raise Skip(f"OSV error ({type(e).__name__})")


# ---------------------------------------------------------------- versions

_VER = re.compile(r"^v?(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:-([0-9A-Za-z.-]{1,100}))?(?:\+.*)?$")


def vkey(v):
    m = _VER.match(str(v).strip())
    if not m:
        return (0, 0, 0, 0, ())
    pre = m.group(4)
    nums = (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))
    if not pre:
        return nums + (1, ())
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return nums + (0, parts)


def fixed_version(vuln, name, version):
    """Lowest fixed version that covers the installed version, or None."""
    cur = vkey(version)
    candidates = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem", "").lower() != "npm" or pkg.get("name") != name:
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced = None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    introduced = vkey(ev["introduced"])
                elif "fixed" in ev:
                    fx = vkey(ev["fixed"])
                    if introduced is not None and introduced <= cur < fx:
                        candidates.append((fx, ev["fixed"]))
                    introduced = None
                elif "last_affected" in ev:
                    introduced = None
        if not candidates:
            for rng in aff.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if "fixed" in ev and vkey(ev["fixed"]) > cur:
                        candidates.append((vkey(ev["fixed"]), ev["fixed"]))
    return min(candidates)[1] if candidates else None


# ---------------------------------------------------------------- severity

_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
      "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope = parts["S"]
        pr = {"N": 0.85, "L": 0.62 if scope == "U" else 0.68, "H": 0.27 if scope == "U" else 0.5}[parts["PR"]]
        iss = 1 - (1 - _W["CIA"][parts["C"]]) * (1 - _W["CIA"][parts["I"]]) * (1 - _W["CIA"][parts["A"]])
        impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = 8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]] * pr * _W["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        base = impact + expl if scope == "U" else 1.08 * (impact + expl)
        return _roundup(min(base, 10.0))
    except (KeyError, ValueError, IndexError):
        return None


def _from_score(s):
    if s is None:
        return None
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "info"


_DB_SEV = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


def severity_of(vuln):
    vid = vuln.get("id", "")
    if vid.startswith("MAL-"):
        return "critical"
    ds = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.lower() in _DB_SEV:
        return _DB_SEV[ds.lower()]
    for aff in vuln.get("affected") or []:
        for k in ("database_specific", "ecosystem_specific"):
            s = (aff.get(k) or {}).get("severity")
            if isinstance(s, str) and s.lower() in _DB_SEV:
                return _DB_SEV[s.lower()]
    for sev in vuln.get("severity") or []:
        if sev.get("type") == "CVSS_V3" and isinstance(sev.get("score"), str):
            r = _from_score(cvss3_score(sev["score"]))
            if r:
                return r
    return None


def _label(vid, vuln):
    if vid.startswith("GHSA-"):
        return vid
    for a in (vuln or {}).get("aliases") or []:
        if a.startswith("GHSA-"):
            return a
    return vid


# ---------------------------------------------------------------- main entry

def _locate(text, name):
    """1-based line where a package first appears in a lockfile / package.json, or 1."""
    if not text:
        return 1
    rx = re.compile(r"(?:^|[\s\"'/])" + re.escape(name) + r"(?:[\"'@:/]|$)")
    for i, ln in enumerate(text.splitlines(), 1):
        if name in ln and rx.search(ln[:2000]):
            return i
    return 1


def check_dependencies(pkgs, sources, texts, deadline, offline=False):
    """Returns (findings, stats). Never raises for network problems."""
    if not pkgs:
        return [], "skipped: no lockfile or exact package.json versions found"
    if offline:
        return [], "skipped: offline mode"
    queried = pkgs[:BATCH_SIZE * MAX_BATCHES]
    hits = {}            # index -> [vuln ids]
    try:
        for b in range(0, len(queried), BATCH_SIZE):
            left = deadline - time.monotonic()
            if left < 3:
                if b == 0:
                    raise Skip("time budget used up")
                break
            chunk = queried[b:b + BATCH_SIZE]
            resp = _request(BATCH_URL, {"queries": [{"package": {"name": p.name, "ecosystem": "npm"},
                                                     "version": p.version} for p in chunk]}, min(25.0, left))
            results = resp.get("results") if isinstance(resp, dict) else None
            if not isinstance(results, list):
                raise Skip("OSV returned an unexpected response")
            for j, res in enumerate(results[:len(chunk)]):
                ids = sorted({v.get("id") for v in (res or {}).get("vulns") or [] if isinstance(v, dict)
                              and isinstance(v.get("id"), str)})
                if ids:
                    hits[b + j] = ids
    except Skip as e:
        return [], f"skipped: {e}"

    # detail lookups: round-robin across packages (direct first) so each package gets a severity
    order = sorted(hits)
    wanted = []
    rnd = 0
    while len(wanted) < MAX_DETAILS and any(rnd < len(hits[i]) for i in order):
        for i in order:
            if rnd < len(hits[i]) and hits[i][rnd] not in wanted:
                wanted.append(hits[i][rnd])
                if len(wanted) >= MAX_DETAILS:
                    break
        rnd += 1
    details = {}

    def fetch(vid):
        left = deadline - time.monotonic()
        if left < 2:
            return vid, None
        try:
            d = _request(VULN_URL.format(quote(vid, safe="")), None, min(10.0, left))
            return vid, d if isinstance(d, dict) else None
        except Skip:
            return vid, None

    if wanted:
        with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
            for vid, d in pool.map(fetch, wanted):
                if d is not None:
                    details[vid] = d

    findings = []
    for i in order:
        p = queried[i]
        ids = hits[i]
        sevs, fixes, summary = [], [], ""
        for vid in ids:
            d = details.get(vid)
            if not d:
                continue
            s = severity_of(d)
            if s:
                sevs.append(s)
            fx = fixed_version(d, p.name, p.version)
            if fx:
                fixes.append(fx)
            if not summary and d.get("summary"):
                summary = str(d["summary"])[:90]
        sev = min(sevs, key=lambda s: SEVERITY_RANK[s]) if sevs else "medium"
        labels = [_label(v, details.get(v)) for v in ids]
        labels = sorted(set(labels))
        advisory = ", ".join(labels[:5]) + (f" +{len(labels) - 5} more" if len(labels) > 5 else "")
        target = max(fixes, key=vkey) if fixes else None
        fix = (f"Upgrade {p.name} to {target} or later." if target else
               f"No fixed version found for {p.name}; check the advisory and consider replacing the package.")
        n = len(ids)
        rel = sources.get(p.key(), "package.json")
        kind = ("direct" if p.direct else "transitive") + (", dev only" if p.dev else "")
        ev = f"{p.name}@{p.version} ({kind})" + (f": {summary}" if summary else "") + (
            "" if sevs else " [severity not looked up]")
        findings.append(finding(
            "PL-023", sev, f"Dependency with a known vulnerability: {p.name} {p.version} "
                           f"({n} advisor{'y' if n == 1 else 'ies'})",
            rel, _locate(texts.get(rel, ""), p.name), ev, fix, obj=f"npm:{p.name}@{p.version}", advisory=advisory,
            proof="Matched against the OSV advisory database; not reproduced."))
    stats = {"status": "ok", "packages": len(pkgs), "queried": len(queried), "vulnerable_packages": len(hits),
             "advisories": len({v for ids in hits.values() for v in ids}), "details_fetched": len(details),
             "truncated": len(queried) < len(pkgs)}
    return findings, stats
