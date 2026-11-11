"""Headers check: grading on canned responses, the request sequence (network patched out), and address rules."""
import gzip
import os
import sys
import unittest
import zlib
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchlabs_cli import posture  # noqa: E402

GOOD = {"strict-transport-security": "max-age=63072000; includeSubDomains",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin"}
CERT_2099 = {"notAfter": "Jan  1 00:00:00 2099 GMT", "issuer": ((("organizationName", "Test CA"),),)}


def response(headers=None, body="", cookies=(), cert=CERT_2099, status=200, version="TLSv1.3"):
    tls = {"version": version, "cert": cert}
    return {"status": status, "headers": dict(GOOD if headers is None else headers), "body": body,
            "cookies": list(cookies), "tls": tls}


def grade(headers=None, host="https://example.com", redirects=True, body="", cookies=(), cert=CERT_2099,
          cert_problem=None, now=None):
    r = response(headers, body, cookies, cert)
    r["url"] = host + "/"
    out = posture.analyze(host, r, {"redirects": redirects, "seen": [host + "/"]}, cert_problem, now=now)
    return out["grade"], out["score"], sorted((f["id"], f["severity"]) for f in out["findings"])


class TestGrading(unittest.TestCase):
    def test_clean_site_is_a(self):
        self.assertEqual(grade(), ("A", 100, []))

    def test_bare_site_without_headers(self):
        g, score, found = grade({}, redirects=False)
        self.assertEqual((g, score), ("D", 55))
        self.assertIn(("PL-027", "medium"), found)
        self.assertIn(("PL-029", "low"), found)
        self.assertIn(("PL-030", "medium"), found)

    def test_preloaded_tld_skips_redirect_and_hsts_checks(self):
        g, score, found = grade({}, host="https://x.dev", redirects=False)
        ids = [i for i, _ in found]
        self.assertNotIn("PL-027", ids)
        self.assertNotIn("PL-029", ids)

    def test_session_cookie_without_flags(self):
        g, score, found = grade(cookies=["session=abc; Path=/", "theme=dark; Secure; HttpOnly"])
        self.assertEqual(found, [("PL-033", "medium")])
        self.assertEqual(score, 85)

    def test_mixed_content_script(self):
        body = '<script src="http://cdn.example.com/a.js"></script>'
        self.assertEqual(grade(body=body)[2], [("PL-034", "medium")])

    def test_version_numbers_in_headers(self):
        h = dict(GOOD, server="nginx/1.25.3", **{"x-powered-by": "PHP/8.2"})
        self.assertEqual(grade(h)[2], [("PL-035", "info")])

    def test_certificate_expiring_soon_is_medium(self):
        cert = {"notAfter": "Jan  1 00:00:00 2027 GMT", "issuer": ((("organizationName", "Test CA"),),)}
        now = datetime(2026, 12, 20, tzinfo=timezone.utc)
        self.assertEqual(grade(cert=cert, now=now)[2], [("PL-028", "medium")])

    def test_expired_certificate_is_f(self):
        cert = {"notAfter": "Jan  1 00:00:00 2027 GMT", "issuer": ((("organizationName", "Test CA"),),)}
        now = datetime(2027, 2, 1, tzinfo=timezone.utc)
        g, _, found = grade(cert=cert, now=now)
        self.assertEqual(g, "F")
        self.assertIn(("PL-028", "high"), found)

    def test_certificate_problem_is_f(self):
        g, _, found = grade(cert=None, cert_problem="The certificate is self-signed.")
        self.assertEqual(g, "F")
        self.assertIn(("PL-028", "high"), found)

    def test_report_only_csp_does_not_count(self):
        h = {k: v for k, v in GOOD.items() if k != "content-security-policy"}
        h["content-security-policy-report-only"] = "default-src 'self'"
        ids = [i for i, _ in grade(h)[2]]
        self.assertIn("PL-030", ids)

    def test_every_finding_has_the_shared_shape(self):
        r = response({}, body='<script src="http://a.example.com/x.js"></script>', cookies=["sid=1"])
        r["url"] = "https://example.com/"
        out = posture.analyze("https://example.com", r, {"redirects": False, "seen": ["https://example.com/"]})
        self.assertTrue(out["findings"])
        for f in out["findings"]:
            self.assertEqual(f["line"], "live")
            self.assertIsNone(f["file"])
            self.assertFalse(f["proven"])
            self.assertEqual(f["object"], "https://example.com")
            self.assertTrue(f["fix"])


class TestAddresses(unittest.TestCase):
    def test_origin_normalises_and_refuses(self):
        both = ("https", "http")
        self.assertEqual(posture.origin("example.com"), "https://example.com")
        self.assertEqual(posture.origin("https://app.example.com/x?y=1"), "https://app.example.com")
        self.assertEqual(posture.origin("http://example.com", schemes=both), "https://example.com")
        for bad in ("", "192.168.0.1", "localhost", "x.local", "user:pw@example.com", "http://example.com:8080",
                    "ftp://example.com", "not a host"):
            with self.subTest(bad):
                with self.assertRaises(ValueError):
                    posture.origin(bad, schemes=both)
        with self.assertRaises(ValueError):
            posture.origin("http://example.com", schemes=("https",))

    def test_public_addresses_only(self):
        for ip in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.1.1", "::ffff:127.0.0.1", "::1", "fe80::1",
                   "224.0.0.1"):
            self.assertFalse(posture.public_ip(ip), ip)
        for ip in ("8.8.8.8", "2606:4700:4700::1111"):
            self.assertTrue(posture.public_ip(ip), ip)

    def test_private_resolution_is_refused_before_any_connection(self):
        infos = [(2, 1, 6, "", ("10.0.0.5", 443))]
        with mock.patch.object(posture.socket, "getaddrinfo", return_value=infos), \
                mock.patch.object(posture.http.client, "HTTPConnection", side_effect=AssertionError("connected")):
            with self.assertRaises(posture.Unreachable):
                posture.fetch("http://example.com/")


class TestRequests(unittest.TestCase):
    """inspect() must make exactly the hosted tool's requests: one http:// GET, one https:// GET, redirects followed."""

    def run_inspect(self, routes):
        calls = []

        def fake(url, verify=True):
            calls.append((url, verify))
            route = routes[url]
            if isinstance(route, Exception):
                raise route
            if callable(route):
                return route(verify)
            return route

        with mock.patch.object(posture, "fetch", side_effect=fake):
            report = posture.inspect("https://example.com")
        return report, calls

    def test_plain_then_https_only(self):
        routes = {
            "http://example.com/": {"status": 301, "headers": {"location": "https://example.com/"}, "body": "",
                                    "cookies": [], "tls": None},
            "https://example.com/": response(),
        }
        report, calls = self.run_inspect(routes)
        self.assertEqual(calls, [("http://example.com/", True), ("https://example.com/", True)])
        self.assertEqual(report["grade"], "A")
        self.assertEqual(report["facts"]["https_redirect"], True)

    def test_redirect_on_https_adds_one_hop_and_nothing_else(self):
        routes = {
            "http://example.com/": {"status": 301, "headers": {"location": "https://example.com/"}, "body": "",
                                    "cookies": [], "tls": None},
            "https://example.com/": {"status": 301, "headers": {"location": "/home"}, "body": "", "cookies": [],
                                     "tls": None},
            "https://example.com/home": response(),
        }
        _, calls = self.run_inspect(routes)
        self.assertEqual(calls, [("http://example.com/", True), ("https://example.com/", True),
                                 ("https://example.com/home", True)])

    def test_certificate_error_is_reported_and_headers_still_read(self):
        def verified(verify):
            if verify:
                raise posture.CertError("The certificate has expired.")
            return response(cert=None)
        routes = {
            "http://example.com/": {"status": 301, "headers": {"location": "https://example.com/"}, "body": "",
                                    "cookies": [], "tls": None},
            "https://example.com/": verified,
        }
        report, calls = self.run_inspect(routes)
        self.assertEqual(calls, [("http://example.com/", True), ("https://example.com/", True),
                                 ("https://example.com/", False)])
        self.assertEqual(report["grade"], "F")
        self.assertIn(("PL-028", "high"), [(f["id"], f["severity"]) for f in report["findings"]])

    def test_unreachable_page_raises(self):
        routes = {"http://example.com/": posture.Unreachable("nothing on port 80"),
                  "https://example.com/": posture.Unreachable("We couldn't connect to example.com.")}
        with self.assertRaises(posture.Unreachable):
            self.run_inspect(routes)


class TestBodyDecoding(unittest.TestCase):
    def test_gzip_deflate_and_charset(self):
        text = "<html>café</html>"
        self.assertEqual(posture._decode_body(gzip.compress(text.encode("utf-8")), "gzip", "text/html"), text)
        self.assertEqual(posture._decode_body(zlib.compress(text.encode("utf-8")), "deflate", ""), text)
        self.assertEqual(posture._decode_body(text.encode("latin-1"), "", "text/html; charset=latin-1"), text)
        self.assertEqual(posture._decode_body(b"not gzip", "gzip", ""), "not gzip")


if __name__ == "__main__":
    unittest.main()
