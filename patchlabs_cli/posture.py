"""Passive check of one public site: the home page, the http-to-https redirect and the TLS certificate.

Ported from the hosted free headers check, with the same requests: a plain http:// GET of the home page (does it
redirect to https://?), then an https:// GET of the home page that follows at most five redirects. Nothing else is
requested: no other paths, forms, APIs or crawling. Every host must resolve to public addresses, and the connection
is pinned to the address that was checked, so the name cannot be resolved again to something else.

Findings PL-027 to PL-036. Grades: A (90+), B (75+), C (60+), D (40+), F; an expired certificate is always F.
"""
import http.client
import ipaddress
import re
import socket
import ssl
import zlib
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from . import __version__
from .codescan.common import redact

UA = f"patchlabs-cli/{__version__} (+https://patchlabs.dev)"
TIMEOUT, MAX_BODY, MAX_REDIRECTS = 8, 1_000_000, 5
REDIRECT_CODES = (301, 302, 303, 307, 308)
EXPIRY_WARN_DAYS = 21
HSTS_MIN = 180 * 86400
# TLDs on the browsers' HSTS preload list: every site on them is HTTPS-only before the first request.
PRELOADED_TLDS = {"app", "dev", "page", "new", "day", "foo", "bank", "insurance", "how", "soy", "boo", "channel", "esq",
                  "meme", "mov", "nexus", "phd", "prof", "rsvp", "zip", "ing", "search", "youtube", "google", "chrome", "gle"}
SEVERITIES = ("critical", "high", "medium", "low", "info")
PENALTY = {"high": 30, "medium": 15, "low": 5}
SHOWN_HEADERS = ("strict-transport-security", "content-security-policy", "content-security-policy-report-only",
                 "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "server",
                 "x-powered-by")
LIVE_PROOF = "Read from one live response; not reproduced."

CHECKS = {  # id: (title when it fails, title when it passes, fix)
    "PL-027": ("Site doesn't force HTTPS", "HTTPS is forced",
               "Redirect every http:// request to https:// with a 301 or 308 (most hosts have a setting for it)."),
    "PL-028": ("TLS certificate is invalid, expired or about to expire", "TLS certificate is valid",
               "Renew the certificate, or turn on automatic renewal at your host or CDN."),
    "PL-029": ("No HSTS header, or max-age under 180 days", "HSTS is on",
               "Send Strict-Transport-Security: max-age=63072000; includeSubDomains"),
    "PL-030": ("No Content-Security-Policy", "Content-Security-Policy is set",
               "Send a Content-Security-Policy that lists where scripts may load from (start with default-src 'self')."),
    "PL-031": ("Any site can frame the page", "Framing is restricted",
               "Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY)."),
    "PL-032": ("No X-Content-Type-Options: nosniff", "X-Content-Type-Options is nosniff",
               "Send X-Content-Type-Options: nosniff"),
    "PL-033": ("Cookie set without Secure, or a session cookie without HttpOnly",
               "Cookies carry Secure (and HttpOnly on sessions)",
               "Set cookies with Secure and SameSite=Lax; add HttpOnly to session cookies."),
    "PL-034": ("Page loads scripts or styles over plain HTTP", "No scripts or styles over plain HTTP",
               "Load every script and stylesheet over https://."),
    "PL-035": ("Server headers reveal software versions", "No software versions in headers",
               "Remove version numbers from the Server and X-Powered-By headers."),
    "PL-036": ("No Referrer-Policy", "Referrer-Policy is set",
               "Send Referrer-Policy: strict-origin-when-cross-origin"),
}

# Addresses a public site must never point at: transition prefixes that reach IPv4 addresses, carrier NAT and the
# cloud metadata address.
BLOCKED_NETS = [ipaddress.ip_network(n) for n in (
    "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32",
    "100.64.0.0/10", "168.63.129.16/32", "169.254.169.254/32")]


class Unreachable(Exception):
    """The page couldn't be loaded; the message is a sentence for the user."""


class CertError(Exception):
    """The certificate failed verification; the message says why in a sentence."""


# ---- URLs ----------------------------------------------------------------------------------------------------------

def origin(text, schemes=("https",)):
    """'example.com', 'https://example.com/x?y' -> 'https://example.com'. Raises ValueError with a sentence."""
    t = (text or "").strip()
    if not t:
        raise ValueError("Enter your app's address, for example https://app.example.com")
    if "://" not in t:
        t = "https://" + t
    try:
        u = urlsplit(t)
        port = u.port
    except ValueError:
        raise ValueError("That address isn't valid.")
    host = (u.hostname or "").rstrip(".").lower()
    if u.scheme not in schemes:
        raise ValueError("Use an https:// address." if schemes == ("https",) else "Use an http:// or https:// address.")
    if u.username or u.password or (port and port not in (80, 443)):
        raise ValueError("Use the plain address of the site, without a login or port.")
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}", host or "-"):
        raise ValueError("Use a domain name such as app.example.com (IP addresses and local names aren't allowed).")
    if host.rsplit(".", 1)[-1] in ("local", "localhost", "internal", "test", "invalid", "example", "lan", "home", "corp"):
        raise ValueError("That's a private name. Use your app's public address.")
    return f"https://{host}"


def public_ip(text):
    try:
        ip = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if any(ip.version == n.version and ip in n for n in BLOCKED_NETS):
        return False
    return ip.is_global and not ip.is_multicast


def resolve(host, port):
    """The first address of host, if every address it has is public. Raises Unreachable otherwise."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError, TypeError):
        raise Unreachable(f"We couldn't find {host}. Check the address.")
    ips = [i[4][0] for i in infos]
    if not ips or not all(public_ip(ip) for ip in ips):
        raise Unreachable(f"{host} points to a private address, so we won't load it.")
    return ips[0]


# ---- fetching: one GET, no redirects followed, pinned to the checked address ----------------------------------------

class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to a checked address. SNI and the certificate check still use the host name."""

    def __init__(self, ip, port, server_name, context):
        super().__init__(ip, port=port, timeout=TIMEOUT, context=context)
        self._server_name = server_name

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._server_name)


def _context(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _inflate(raw, wbits):
    return zlib.decompressobj(wbits).decompress(raw, MAX_BODY)


def _decode_body(raw, encoding, ctype):
    enc = (encoding or "").strip().lower()
    try:
        if enc in ("gzip", "x-gzip"):
            raw = _inflate(raw, 16 + zlib.MAX_WBITS)
        elif enc == "deflate":
            try:
                raw = _inflate(raw, zlib.MAX_WBITS)
            except zlib.error:
                raw = _inflate(raw, -zlib.MAX_WBITS)
    except zlib.error:
        pass  # keep the bytes as they came; the body checks then see less
    m = re.search(r"charset=\"?([\w.:-]+)", ctype or "", re.I)
    try:
        return raw.decode(m.group(1) if m else "utf-8", "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


def cert_reason(text):
    for needle, reason in (("expired", "The certificate has expired."),
                           ("Hostname mismatch", "The certificate is for a different name."),
                           ("self-signed", "The certificate is self-signed."),
                           ("self signed", "The certificate is self-signed."),
                           ("unable to get local issuer", "The certificate isn't signed by a trusted authority.")):
        if needle in text:
            return reason
    return "Browsers won't trust the certificate."


def fetch(url, verify=True):
    """One GET without following redirects. Returns {status, headers, cookies, body, tls}."""
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise Unreachable("The page redirects somewhere we can't follow.")
    default = 443 if u.scheme == "https" else 80
    port = u.port or default
    ip = resolve(u.hostname, port)
    name = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
    host_header = name if port == default else f"{name}:{port}"
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    headers = {"Host": host_header, "User-Agent": UA, "Accept": "text/html,*/*;q=0.5",
               "Accept-Encoding": "gzip, deflate"}
    conn = None
    try:
        if u.scheme == "https":
            conn = _PinnedHTTPS(ip, port, u.hostname, _context(verify))
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=TIMEOUT)
        conn.request("GET", path, headers=headers)
        tls = None
        if u.scheme == "https":
            sslsock = conn.sock
            tls = {"version": sslsock.version(), "cert": sslsock.getpeercert() if verify else None}
        resp = conn.getresponse()
        hdrs, cookies = {}, []
        for key, value in resp.getheaders():
            lk = key.lower()
            if lk == "set-cookie":
                cookies.append(value)
            hdrs[lk] = f"{hdrs[lk]}, {value}" if lk in hdrs else value
        raw = resp.read(MAX_BODY)
        body = _decode_body(raw, hdrs.get("content-encoding"), hdrs.get("content-type"))
        return {"status": resp.status, "headers": hdrs, "cookies": cookies, "body": body, "tls": tls}
    except ssl.SSLCertVerificationError as e:
        raise CertError(cert_reason(str(e)))
    except (socket.timeout, TimeoutError):
        raise Unreachable(f"{u.hostname} didn't answer within {TIMEOUT} seconds.")
    except ConnectionError:
        raise Unreachable(f"We couldn't connect to {u.hostname}.")
    except (OSError, http.client.HTTPException, ValueError):
        raise Unreachable(f"We couldn't load {u.hostname}.")
    finally:
        if conn is not None:
            conn.close()


def load(url, verify=True):
    """Follows up to MAX_REDIRECTS redirects, resolving and checking every hop. Returns (response, URLs visited)."""
    seen = [url]
    for _ in range(MAX_REDIRECTS + 1):
        r = fetch(url, verify)
        loc = r["headers"].get("location")
        if r["status"] not in REDIRECT_CODES or not loc:
            return r, seen
        url = urljoin(url, loc)
        if urlsplit(url).scheme not in ("http", "https"):
            raise Unreachable("The page redirects somewhere we can't follow.")
        seen.append(url)
    raise Unreachable(f"The page redirects more than {MAX_REDIRECTS} times.")


# ---- analysis ------------------------------------------------------------------------------------------------------

def _cert_name(parts, key):
    return next((v for rdn in parts or () for k, v in rdn if k == key), None)


def tls_facts(tls, now=None):
    cert = (tls or {}).get("cert") or {}
    if not cert.get("notAfter"):
        return {"version": (tls or {}).get("version"), "issuer": None, "expires": None, "days_left": None}
    exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    issuer = _cert_name(cert.get("issuer"), "organizationName") or _cert_name(cert.get("issuer"), "commonName")
    return {"version": tls.get("version"), "issuer": issuer, "expires": exp.date().isoformat(),
            "days_left": (exp - (now or datetime.now(timezone.utc))).days}


def parse_cookie(raw):
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True)
             for p in parts[1:] if p}
    return {"name": name[:100], "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": str(attrs["samesite"]).title() if isinstance(attrs.get("samesite"), str) else None}


SESSION_NAME = re.compile(r"sess|auth|token|sid|jwt|login|remember", re.I)
META = r"<meta\b[^>]*\b{attr}\s*=\s*[\"']?{value}(?=[\"'\s/>])[^>]*>"


def meta_tag(body, attr, value):
    m = re.search(META.format(attr=attr, value=re.escape(value)), body or "", re.I)
    if not m:
        return None
    c = re.search(r"\bcontent\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", m.group(0), re.I)
    return c.group(1).strip("\"'") if c else ""


def hsts_age(value):
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value or "", re.I)
    return int(m.group(1)) if m else None


def analyze(page_url, r, http_info, cert_problem=None, now=None):
    """Turns one load into findings. r: the final https response; http_info: {"redirects": bool|None, "seen": [...]}."""
    h, body, host = r["headers"], r["body"], urlsplit(page_url).hostname or ""
    preloaded = host.rsplit(".", 1)[-1] in PRELOADED_TLDS
    tls = tls_facts(r.get("tls"), now)
    found = []

    def fail(fid, evidence, severity):
        found.append({"id": fid, "line": "live", "severity": severity, "title": CHECKS[fid][0], "object": page_url,
                      "file": None, "line_no": None, "evidence": redact(evidence), "fix": CHECKS[fid][2],
                      "proven": False, "proof": LIVE_PROOF, "fixed_in_lab": False, "source": "headers"})

    final = r.get("url") or page_url
    if urlsplit(final).scheme != "https":
        fail("PL-027", "Loading the site over https:// ends up on a plain http:// page.", "medium")
    elif http_info.get("redirects") is False and not preloaded:
        fail("PL-027", f"http://{host}/ answers without redirecting to https://.", "medium")
    if cert_problem:
        fail("PL-028", cert_problem, "high")
    elif tls["days_left"] is not None and tls["days_left"] < 0:
        fail("PL-028", f"The certificate expired on {tls['expires']}.", "high")
    elif tls["days_left"] is not None and tls["days_left"] < EXPIRY_WARN_DAYS:
        fail("PL-028", f"The certificate expires on {tls['expires']} ({tls['days_left']} days).", "medium")
    age = hsts_age(h.get("strict-transport-security"))
    if not preloaded and (age is None or age < HSTS_MIN):
        fail("PL-029", "No Strict-Transport-Security header." if age is None else
             f"Strict-Transport-Security max-age is {age} seconds (under 180 days).", "low")
    csp = h.get("content-security-policy") or ""
    meta_csp = meta_tag(body, "http-equiv", "Content-Security-Policy")
    if not csp.strip() and not (meta_csp or "").strip():
        fail("PL-030", "The page sends no Content-Security-Policy header or meta tag" +
             (" (only a Report-Only policy, which blocks nothing)."
              if h.get("content-security-policy-report-only") else "."), "medium")
    xfo = (h.get("x-frame-options") or "").strip().upper()
    if "frame-ancestors" not in csp.lower() and xfo not in ("DENY", "SAMEORIGIN"):
        fail("PL-031", "No frame-ancestors in the Content-Security-Policy header and no X-Frame-Options.", "low")
    if (h.get("x-content-type-options") or "").strip().lower() != "nosniff":
        fail("PL-032", "X-Content-Type-Options is missing or isn't nosniff.", "low")
    cookies = [parse_cookie(c) for c in r.get("cookies") or []][:20]
    cookie_hits = 0
    for ck in cookies:
        # SameSite isn't required: browsers treat a cookie without it as Lax
        missing = [a for a, ok in (("Secure", ck["secure"]),
                                   ("HttpOnly", ck["httponly"] or not SESSION_NAME.search(ck["name"]))) if not ok]
        if missing and cookie_hits < 5:
            cookie_hits += 1
            fail("PL-033", f"Cookie {ck['name']} is set without {', '.join(missing)}.", "medium")
    insecure = re.findall(r"<script\b[^>]*\bsrc\s*=\s*[\"']?(http://[^\"'\s>]+)", body, re.I) + \
        [m for tag in re.findall(r"<link\b[^>]*>", body, re.I) if re.search(r"stylesheet", tag, re.I)
         for m in re.findall(r"\bhref\s*=\s*[\"']?(http://[^\"'\s>]+)", tag, re.I)]
    if insecure:
        fail("PL-034", "Loaded over plain HTTP: " + ", ".join(dict.fromkeys(insecure[:3])), "medium")
    leaky = [f"{k}: {h[k]}" for k in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
             if h.get(k) and re.search(r"\d+\.\d+", h[k])]
    if leaky:
        fail("PL-035", "; ".join(leaky), "info")
    if not (h.get("referrer-policy") or "").strip() and meta_tag(body, "name", "referrer") is None:
        fail("PL-036", "No Referrer-Policy header or meta tag.", "info")

    failed = {f["id"] for f in found}
    counts = {s: sum(f["severity"] == s for f in found) for s in SEVERITIES}
    # each check costs points once, however many cookies it caught
    score = max(0, 100 - sum(PENALTY.get(f["severity"], 0) for f in {f["id"]: f for f in found}.values()))
    grade = "F" if any(f["id"] == "PL-028" and f["severity"] == "high" for f in found) else \
        next(g for g, floor in (("A", 90), ("B", 75), ("C", 60), ("D", 40), ("F", 0)) if score >= floor)
    found.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["id"]))
    return {
        "url": page_url, "final_url": final, "grade": grade, "score": score, "counts": counts, "findings": found,
        "passed": [{"id": fid, "title": t[1]} for fid, t in CHECKS.items() if fid not in failed],
        "facts": {"status": r["status"], "redirects": http_info.get("seen") or [final],
                  "https_redirect": http_info.get("redirects"), "https_preloaded_tld": preloaded, "tls": tls,
                  "headers": {k: (h[k][:300] if h.get(k) else None) for k in SHOWN_HEADERS},
                  "cookies": cookies, "server": (h.get("server") or None) and h["server"][:100]},
    }


def inspect(site):
    """Runs the whole check on an origin from origin(). Raises Unreachable when the https page can't be loaded."""
    host = urlsplit(site).hostname
    try:
        hr = fetch(f"http://{host}/")
        loc = hr["headers"].get("location") or ""
        redirects = hr["status"] in REDIRECT_CODES and urljoin(f"http://{host}/", loc).startswith("https://")
    except Unreachable:
        redirects = None  # nothing listens on plain http: nothing to downgrade to
    except CertError:
        redirects = True
    cert_problem = None
    try:
        r, seen = load(site + "/")
    except CertError as e:
        cert_problem = str(e)
        r, seen = load(site + "/", verify=False)  # still read the headers, as a browser would after the warning
    r["url"] = seen[-1]
    out = analyze(site, r, {"redirects": redirects, "seen": seen}, cert_problem)
    out["checked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return out
