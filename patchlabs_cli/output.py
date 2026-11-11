"""Human-readable output: a compact table, coloured when the terminal allows it, and the closing line."""
import os

from .findings import FINDING_URL, location

FOOTER = ("Static checks only. To prove who can read what in a rebuilt copy of your database and get a re-tested fix, "
          "run the hosted check at https://patchlabs.dev")
HEADERS_FOOTER = ("One page load of a public URL. To grade your site every day and get alerts when it changes, "
                  "add Live posture at https://patchlabs.dev/product/live-posture")
MAX_ROWS = 50  # the table shows the first 50 findings (most severe first); --json and --sarif always have all of them
COLOURS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}
TITLE_MAX = 72


def colour_enabled(stream):
    """Colour only on a terminal, and never when NO_COLOR is set to a non-empty value (https://no-color.org)."""
    if os.environ.get("NO_COLOR", ""):
        return False
    try:
        return bool(stream.isatty())
    except AttributeError:
        return False


def _paint(text, code, on):
    return f"\x1b[{code}m{text}\x1b[0m" if on and code else text


def _title(title):
    return title if len(title) <= TITLE_MAX else title[:TITLE_MAX - 3] + "..."


def render(heading, notes, findings, colour, footer=FOOTER, max_rows=MAX_ROWS):
    """Returns the text to print for a scan or a headers check."""
    lines = [heading]
    if findings:
        rows = [(f["severity"], f["id"], _title(f["title"]), location(f)) for f in findings[:max_rows]]
        w0 = max(len("SEVERITY"), max(len(r[0]) for r in rows))
        w1 = max(len("ID"), max(len(r[1]) for r in rows))
        w2 = max(len("TITLE"), max(len(r[2]) for r in rows))
        lines.append("")
        lines.append(_paint(f"{'SEVERITY':<{w0}}  {'ID':<{w1}}  {'TITLE':<{w2}}  LOCATION", "1", colour))
        for sev, fid, title, loc in rows:
            lines.append(f"{_paint(sev.ljust(w0), COLOURS.get(sev, ''), colour)}  {fid.ljust(w1)}  "
                         f"{title.ljust(w2)}  {loc}")
        if len(findings) > max_rows:
            lines.append(f"... and {len(findings) - max_rows} more. Use --json or --sarif FILE for the full list.")
        lines.append("")
        lines.append("Details:")
        seen = []
        for f in findings:
            if f["id"] not in seen:
                seen.append(f["id"])
        for fid in seen:
            lines.append(f"  {fid}  {FINDING_URL.format(fid.lower())}")
    else:
        lines.append("")
        lines.append("No findings.")
    if notes:
        lines.append("")
        lines.extend(notes)
    lines.append("")
    lines.append(footer)
    return "\n".join(lines)


def summary(findings):
    if not findings:
        return "0 findings."
    tally = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = sum(1 for f in findings if f["severity"] == sev)
        if n:
            tally.append(f"{n} {sev}")
    return f"{len(findings)} finding{'s' if len(findings) != 1 else ''}: " + ", ".join(tally) + "."


def scan_notes(stats):
    notes = []
    deps = stats.get("dependencies")
    if isinstance(deps, dict):
        notes.append(f"Dependencies: {deps.get('packages', 0)} packages checked against OSV, "
                     f"{deps.get('vulnerable_packages', 0)} with known advisories.")
    elif isinstance(deps, str):
        notes.append(f"Dependency check {deps}.")
    if stats.get("sql_files") is not None:
        notes.append(f"SQL files read for the RLS check: {stats['sql_files']}.")
    for err in stats.get("errors", []):
        notes.append(f"Check error: {err}")
    if stats.get("truncated") or stats.get("sql_truncated"):
        notes.append("The scan stopped early (file, count or time limit), so results may be incomplete.")
    return notes
