"""Command line entry point: `patchlabs scan [PATH]` and `patchlabs headers URL`.

Exit codes: 0 no finding at or above --fail-on, 1 such a finding exists, 2 usage error (bad flag, path or
address), 3 the live site could not be loaded.
"""
import argparse
import json
import os
import sys

from . import __version__, output, posture, sarif
from .codescan.common import SEVERITY_RANK
from .engine import scan_repo

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_UNREACHABLE = 0, 1, 2, 3
FAIL_LEVELS = ("critical", "high", "medium", "low", "none")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="patchlabs",
        description="Static checks for apps built with Lovable, Supabase, Bolt, Replit or Cursor.")
    parser.add_argument("--version", action="version", version=f"patchlabs {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    scan = sub.add_parser("scan", help="check a repository's code, dependencies and SQL files")
    scan.add_argument("path", nargs="?", default=".", help="repository folder (default: .)")
    scan.add_argument("--offline", action="store_true", help="skip the OSV dependency lookup")
    _output_flags(scan)

    headers = sub.add_parser("headers", help="check the headers, redirect and certificate of one live site")
    headers.add_argument("url", help="site address, for example https://app.example.com")
    _output_flags(headers)
    return parser


def _output_flags(p):
    p.add_argument("--json", action="store_true", help="print JSON instead of the table")
    p.add_argument("--sarif", metavar="FILE", help="also write SARIF 2.1.0 to FILE (for GitHub code scanning)")
    p.add_argument("--fail-on", choices=FAIL_LEVELS, default="high",
                   help="exit 1 when a finding at or above this severity exists (default: high)")


def failing(findings, level):
    if level == "none":
        return False
    limit = SEVERITY_RANK[level]
    return any(SEVERITY_RANK[f["severity"]] <= limit for f in findings)


def _usage(message):
    sys.stderr.write(f"patchlabs: error: {message}\n")
    return EXIT_USAGE


def _emit(args, payload, findings, heading, notes):
    if args.sarif:
        try:
            with open(args.sarif, "w", encoding="utf-8") as fh:
                json.dump(sarif.to_sarif(findings), fh, indent=2)
                fh.write("\n")
        except OSError as e:
            return _usage(f"cannot write {args.sarif}: {e.strerror or e}")
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        footer = output.HEADERS_FOOTER if payload.get("command") == "headers" else output.FOOTER
        text = output.render(heading, notes, findings, output.colour_enabled(sys.stdout), footer=footer)
        sys.stdout.write(text + "\n")
    return EXIT_FINDINGS if failing(findings, args.fail_on) else EXIT_OK


def _scan(args):
    if not os.path.isdir(args.path):
        return _usage(f"not a folder: {args.path}")
    result = scan_repo(args.path, offline=args.offline)
    findings, stats = result["findings"], result["stats"]
    payload = {"tool": "patchlabs-cli", "version": __version__, "command": "scan", "path": args.path,
               "findings": findings, "stats": stats}
    heading = f"patchlabs scan: {args.path}\n{output.summary(findings)}"
    return _emit(args, payload, findings, heading, output.scan_notes(stats))


def _headers(args):
    try:
        site = posture.origin(args.url, schemes=("https", "http"))
    except ValueError as e:
        return _usage(str(e))
    try:
        report = posture.inspect(site)
    except posture.Unreachable as e:
        sys.stderr.write(f"patchlabs: error: {e}\n")
        return EXIT_UNREACHABLE
    findings = report["findings"]
    payload = {"tool": "patchlabs-cli", "version": __version__, "command": "headers", "url": site,
               "final_url": report["final_url"], "grade": report["grade"], "score": report["score"],
               "counts": report["counts"], "findings": findings, "passed": report["passed"],
               "facts": report["facts"], "checked_at": report["checked_at"]}
    heading = (f"patchlabs headers: {site}\nGrade {report['grade']} (score {report['score']}). "
               f"{output.summary(findings)}")
    notes = [f"Requests: one plain http:// GET of the home page, and one https:// GET of the home page "
             f"(redirects followed, at most {posture.MAX_REDIRECTS})."]
    return _emit(args, payload, findings, heading, notes)


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as e:  # argparse exits 0 for --help and --version, 2 for usage errors
        return e.code if isinstance(e.code, int) else EXIT_USAGE
    if args.command == "scan":
        return _scan(args)
    return _headers(args)
