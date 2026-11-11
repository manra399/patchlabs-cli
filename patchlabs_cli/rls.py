"""Static read of Supabase migration SQL for risky row level security (RLS) patterns.

Pure parsing and analysis: text in, findings out. Nothing is connected to, run or rebuilt. Each finding is a
reading of the SQL text, not a test against a database. The hosted check proves what leaks in a rebuilt copy.
"""
import re
from bisect import bisect_right

from .codescan.common import redact

TITLES = {"PL-001": "Anyone with the public key can read personal data", "PL-002": "Any signed-in user can read all rows",
          "PL-003": "Row level security is on but the table has no policies", "PL-004": "UPDATE policy without WITH CHECK",
          "PL-005": "Policy is always true", "PL-006": "SECURITY DEFINER function exposure", "PL-007": "Public storage bucket",
          "PL-008": "Row level security is not enabled"}
FIXES = {
    "PL-001": "Limit the policy to the row owner, for example using (auth.uid() = user_id), or drop the anon role from it.",
    "PL-002": "Scope the policy to the row owner, for example using (auth.uid() = user_id), instead of any signed-in user.",
    "PL-003": "Add the policies the app needs for this table, or drop RLS if the table should not be exposed.",
    "PL-004": "Add a WITH CHECK clause to the UPDATE policy so that a row cannot be changed into one the owner should not own.",
    "PL-005": "Replace using (true) with a condition on the row owner, for example auth.uid() = user_id.",
    "PL-006": "Set a fixed search_path (set search_path = '') and revoke EXECUTE on the function from anon and public.",
    "PL-007": "Make the bucket private and serve files through signed URLs or a policy on storage.objects.",
    "PL-008": "Run alter table ... enable row level security, then add policies for the access the app needs.",
}
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PERSONAL = re.compile(r"email|phone|address|dob|birth|ssn|passport", re.I)
IDENT = r'(?:"[^"]+"|[A-Za-z_][\w$]*)'
NAME = rf"{IDENT}(?:\s*\.\s*{IDENT})?"
DOLLAR = re.compile(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$")
F = re.I | re.S
CREATE_TABLE = re.compile(rf"^create\s+(?:(?:global\s+|local\s+)?(?:temporary|temp|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?({NAME})\s*\(", F)
ALTER_TABLE = re.compile(rf"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({NAME})\s+(.*)$", F)
DROP_TABLE = re.compile(r"^drop\s+table\s+(?:if\s+exists\s+)?", F)
TRAILING_DROP = re.compile(r"\s+(?:cascade|restrict)$", re.I)
NEXT_TUPLE = re.compile(r"\s*,")
MAX_STATEMENT, MAX_NAME = 50_000, 200
CREATE_POLICY = re.compile(rf'^create\s+policy\s+("[^"]+"|\S+)\s+on\s+({NAME})(.*)$', F)
DROP_POLICY = re.compile(rf'^drop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|\S+)\s+on\s+({NAME})', F)
CREATE_FUNCTION = re.compile(rf"^create\s+(?:or\s+replace\s+)?function\s+({NAME})\s*\(", F)
GRANT_FUNCTION = re.compile(rf"^grant\s+(?:execute|all)(?:\s+privileges)?\s+on\s+(?:function\s+({NAME})|all\s+functions\s+in\s+schema\s+(\w+))"
                            r".*?\bto\s+(.*)$", F)
BUCKET_INSERT = re.compile(r"^insert\s+into\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*values\s*(.*)$", F)
BUCKET_UPDATE = re.compile(r"^update\s+storage\s*\.\s*buckets\s+set\s+(.*?)\bpublic\s*=\s*true\b(.*)$", F)
USER_SCOPED = re.compile(r"auth\s*\.\s*(?:uid|jwt|email)\s*\(\s*\)|current_user|session_user|current_setting|is_member|has_role", re.I)
SIGNED_IN_ONLY = re.compile(r"auth\s*\.\s*role\s*\(\s*\)\s*=\s*'authenticated'|auth\s*\.\s*uid\s*\(\s*\)\s+is\s+not\s+null", re.I)


# ---- SQL scanning ------------------------------------------------------------------------------------------------

# Alternatives start with different characters, so matching is linear (Python 3.9 has no possessive quantifiers).
QUOTED = {"'": re.compile(r"'(?:[^']|'')*'"), '"': re.compile(r'"(?:[^"]|"")*"')}


def quoted_end(sql, i):
    """Index just past the quoted string or identifier opening at i ('' and "" escape the quote)."""
    m = QUOTED[sql[i]].match(sql, i)
    return m.end() if m else len(sql)


def dollar_end(sql, m):
    """Index just past the dollar-quoted body whose opening tag is match m."""
    k = sql.find(m.group(0), m.end())
    return len(sql) if k < 0 else k + len(m.group(0))


SPECIAL_COMMENTS, SPECIAL_STATEMENTS = re.compile(r"--|/\*|['\"$]"), re.compile(r"['\"$;]")


def strip_comments(sql):
    """Removes -- and /* */ comments (keeping line breaks) without touching strings or dollar-quoted bodies. Linear."""
    out, i, n = [], 0, len(sql)
    while (m := SPECIAL_COMMENTS.search(sql, i)):
        j, tok = m.start(), m.group(0)
        out.append(sql[i:j])
        if tok == "--":
            k = sql.find("\n", j)
            i = n if k < 0 else k
        elif tok == "/*":
            k = sql.find("*/", j + 2)
            k = n if k < 0 else k + 2
            out.append("\n" * sql.count("\n", j, k))
            i = k
        elif tok in "'\"":
            i = quoted_end(sql, j)
            out.append(sql[j:i])
        elif (d := DOLLAR.match(sql, j)):
            i = dollar_end(sql, d)
            out.append(sql[j:i])
        else:
            out.append("$")
            i = j + 1
    out.append(sql[i:])
    return "".join(out)


def statements(sql):
    """Yields (line, statement) for each top-level statement. Linear."""
    sql = strip_comments(sql)
    starts = [0] + [m.end() for m in re.finditer("\n", sql)]
    i = start = 0

    def emit(a, b):
        text = sql[a:b]
        s = text.strip()
        return (bisect_right(starts, a + len(text) - len(text.lstrip())), s) if s else None

    while (m := SPECIAL_STATEMENTS.search(sql, i)):
        j, tok = m.start(), m.group(0)
        if tok == ";":
            if (s := emit(start, j)):
                yield s
            i = start = j + 1
        elif tok in "'\"":
            i = quoted_end(sql, j)
        elif (d := DOLLAR.match(sql, j)):
            i = dollar_end(sql, d)
        else:
            i = j + 1
    if (s := emit(start, len(sql))):
        yield s


def outside_dollar(st):
    """The statement without its dollar-quoted bodies (function code). Linear."""
    out, i = [], 0
    while (m := DOLLAR.search(st, i)):
        out.append(st[i:m.start()])
        i = dollar_end(st, m)
    out.append(st[i:])
    return "".join(out)


def balanced(text, pos):
    """Returns the text inside the parenthesis that opens at or after pos, and the index after it."""
    i = text.find("(", pos)
    if i < 0:
        return None, pos
    depth, j = 0, i
    while j < len(text):
        if text[j] == "'":
            j = text.find("'", j + 1)
            if j < 0:
                break
        elif text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[i + 1:j], j + 1
        j += 1
    return text[i + 1:], len(text)


def split_top(text):
    parts, depth, cur, q = [], 0, [], False
    for ch in text:
        if ch == "'":
            q = not q
        elif not q and ch == "(":
            depth += 1
        elif not q and ch == ")":
            depth -= 1
        if ch == "," and depth == 0 and not q:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def norm(name):
    parts = [p[1:-1] if p.startswith('"') else p.lower() for p in re.findall(r'"[^"]+"|[^."\s]+', name)] or [""]
    return (parts[-2] if len(parts) > 1 else "public"), parts[-1]


def snippet(stmt):
    s = re.sub(r"\s+", " ", stmt).strip()
    return s if len(s) <= 240 else s[:237] + "..."


def is_true(expr):
    return expr is not None and re.sub(r"[\s()]", "", expr).lower() in ("true", "1=1", "'t'", "true::boolean")


# ---- analysis ----------------------------------------------------------------------------------------------------

def analyze(files):
    """files: [(path, sql)] in migration order. Returns (tables, findings)."""
    tables, functions, buckets, findings = {}, {}, [], []

    def find(fid, severity, table, path, line, stmt, detail=None):
        findings.append({"id": fid, "title": TITLES[fid], "table": table, "file": path, "line": line, "severity": severity,
                         "snippet": snippet(stmt), **({"detail": detail} if detail else {})})

    for path, sql in files:
        for line, st in statements(sql):
            if len(st) > MAX_STATEMENT:  # no real migration statement is this big; skipping keeps the scan cheap
                continue
            if (m := CREATE_TABLE.match(st)):
                schema, t = norm(m.group(1))
                if schema != "public":
                    continue
                body, _ = balanced(st, m.end() - 1)
                cols = [re.match(rf"\s*({IDENT})", p).group(1).strip('"').lower() for p in split_top(body or "")
                        if re.match(rf"\s*{IDENT}", p) and not re.match(r"\s*(constraint|primary|unique|foreign|check|exclude|like)\b", p, re.I)]
                tables[t] = {"name": t, "rls": False, "policies": {}, "columns": cols, "file": path, "line": line, "stmt": st}
            elif (m := ALTER_TABLE.match(st)):
                schema, t = norm(m.group(1))
                if schema != "public" or t not in tables:
                    continue
                action = m.group(2)
                if re.search(r"\benable\s+row\s+level\s+security\b", action, re.I):
                    tables[t]["rls"] = True
                if re.search(r"\bdisable\s+row\s+level\s+security\b", action, re.I):
                    tables[t]["rls"] = False
                for col in re.findall(rf"\badd\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?({IDENT})", action, re.I):
                    if col.lower() not in ("constraint", "primary", "unique", "foreign", "check", "exclude"):
                        tables[t]["columns"].append(col.strip('"').lower())
            elif (m := DROP_TABLE.match(st)):
                for nm in TRAILING_DROP.sub("", st[m.end():].rstrip()).split(","):
                    if len(nm.strip()) <= MAX_NAME:
                        tables.pop(norm(nm.strip())[1], None)
            elif (m := CREATE_POLICY.match(st)):
                schema, t = norm(m.group(2))
                if schema != "public" or t not in tables:
                    continue
                rest = m.group(3)
                cmd = (re.search(r"\bfor\s+(all|select|insert|update|delete)\b", rest, re.I) or [None, "all"])[1].lower()
                roles_m = re.search(r"\bto\s+(.*?)(?=\busing\b|\bwith\s+check\b|$)", rest, re.I | re.S)
                roles = {r.strip().strip('"').lower() for r in roles_m.group(1).split(",")} if roles_m else {"public"}
                using = balanced(rest, re.search(r"\busing\b", rest, re.I).end())[0] if re.search(r"\busing\b", rest, re.I) else None
                wc = re.search(r"\bwith\s+check\b", rest, re.I)
                check = balanced(rest, wc.end())[0] if wc else None
                tables[t]["policies"][m.group(1).strip('"')] = {"cmd": cmd, "roles": roles, "using": using, "check": check,
                                                                "file": path, "line": line, "stmt": st}
            elif (m := DROP_POLICY.match(st)):
                schema, t = norm(m.group(2))
                if t in tables:
                    tables[t]["policies"].pop(m.group(1).strip('"'), None)
            elif (m := CREATE_FUNCTION.match(st)):
                schema, fn = norm(m.group(1))
                outside = outside_dollar(st)
                functions[fn] = {"definer": bool(re.search(r"\bsecurity\s+definer\b", outside, re.I)),
                                 "search_path": bool(re.search(r"\bset\s+search_path\b", outside, re.I)), "anon": False,
                                 "file": path, "line": line, "stmt": st, "schema": schema}
            elif (m := GRANT_FUNCTION.match(st)):
                to = {r.strip().strip('"').lower() for r in re.sub(r"\bwith\s+grant\s+option\b", "", m.group(3), flags=re.I).split(",")}
                if not to & {"anon", "public"}:
                    continue
                if m.group(1):
                    fn = norm(m.group(1))[1]
                    if fn in functions:
                        functions[fn]["anon"] = True
                else:
                    for f in functions.values():
                        if f["schema"] == m.group(2).lower():
                            f["anon"] = True
            elif (m := BUCKET_INSERT.match(st)):
                cols = [x.strip().strip('"').lower() for x in m.group(1).split(",")]
                if "public" in cols:
                    rest, pos = m.group(2), 0
                    while True:
                        tup, pos = balanced(rest, pos)
                        if tup is None:
                            break
                        vals = split_top(tup)
                        idx = cols.index("public")
                        if idx < len(vals) and vals[idx].strip().lower() in ("true", "'true'", "'t'"):
                            name = vals[cols.index("id")].strip("' ") if "id" in cols and cols.index("id") < len(vals) else None
                            buckets.append((name, path, line, st))
                        if not NEXT_TUPLE.match(rest, pos):
                            break
            elif (m := BUCKET_UPDATE.match(st)):
                bid = re.search(r"\bid\s*=\s*'([^']*)'", m.group(2), re.I)
                buckets.append((bid.group(1) if bid else None, path, line, st))

    out_tables = []
    for t in tables.values():
        personal = [c for c in t["columns"] if PERSONAL.search(c)]
        out_tables.append({"name": t["name"], "rls_enabled": t["rls"], "policies": len(t["policies"]), "personal_columns": personal,
                           "file": t["file"], "line": t["line"]})
        if not t["rls"]:
            find("PL-008", "critical" if personal else "high", t["name"], t["file"], t["line"], t["stmt"],
                 "Anyone with the public key can read and change every row through the Supabase API.")
            continue
        if not t["policies"]:
            find("PL-003", "low", t["name"], t["file"], t["line"], t["stmt"], "Nobody can read or write it through the API; the app may be broken.")
        for p in t["policies"].values():
            anon = bool(p["roles"] & {"anon", "public"})
            reads = p["cmd"] in ("select", "all")
            flagged = False
            if reads and p["using"] is not None:
                signed_in = bool(SIGNED_IN_ONLY.search(p["using"]))
                wide = signed_in or not USER_SCOPED.search(p["using"])
                if wide and anon and not signed_in and personal:
                    find("PL-001", "critical", t["name"], p["file"], p["line"], p["stmt"], "Personal columns: " + ", ".join(personal))
                    flagged = True
                elif wide and (signed_in or "authenticated" in p["roles"]):
                    find("PL-002", "high" if personal else "medium", t["name"], p["file"], p["line"], p["stmt"])
                    flagged = True
            if not flagged and (is_true(p["using"]) or is_true(p["check"])):
                writes = p["cmd"] != "select"
                find("PL-005", "high" if writes and anon else "medium" if writes else "low", t["name"], p["file"], p["line"], p["stmt"],
                     "Anyone it applies to can " + ("change rows." if writes else "read every row."))
            if p["cmd"] == "update" and p["check"] is None:
                find("PL-004", "medium", t["name"], p["file"], p["line"], p["stmt"],
                     "Without WITH CHECK the USING rule decides what a row may be changed into.")
    for name, f in functions.items():
        if f["definer"] and (not f["search_path"] or f["anon"]):
            why = [w for w, on in (("no fixed search_path", not f["search_path"]), ("callable by anon", f["anon"])) if on]
            find("PL-006", "high" if f["anon"] else "medium", None, f["file"], f["line"], f["stmt"], f"Function {name}: " + " and ".join(why))
    for name, path, line, st in buckets:
        find("PL-007", "medium", None, path, line, st, f"Bucket {name or '(unnamed)'} serves its files to anyone with the link.")
    findings.sort(key=lambda x: (RANK[x["severity"]], x["id"], x["file"], x["line"]))
    return out_tables, findings


PROOF = "Found by reading the migration SQL; not tested against a live database."


def to_findings(raw):
    """Turns analyze() findings into the finding shape the code scanner uses."""
    out = []
    for f in raw:
        ev = f"{f['detail'].rstrip('.')}. {f['snippet']}" if f.get("detail") else f["snippet"]
        out.append({"id": f["id"], "line": "code", "severity": f["severity"], "title": f["title"],
                    "object": f["table"] or f["file"], "file": f["file"], "line_no": f["line"],
                    "evidence": redact(ev), "proven": False, "proof": PROOF, "fix": FIXES[f["id"]],
                    "fixed_in_lab": False, "source": "rls"})
    return out
