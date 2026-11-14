"""Shared helpers: repo walking, path classification, redaction and the finding shape.

Everything here treats the repository as untrusted text. Nothing is executed or imported.
"""
import base64
import json
import os
import re
import time

SKIP_DIRS = {
    "node_modules", "dist", "build", ".git", "vendor", "vendors", "third_party", "third-party",
    "bower_components", ".next", ".nuxt", ".output", ".svelte-kit", ".vercel", ".netlify", ".turbo",
    ".cache", "coverage", ".parcel-cache", ".expo", ".idea", ".vscode", "__pycache__", ".venv", "venv",
    "out", "public/build", ".yarn", ".pnpm-store", ".deno",
}
CODE_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro",
            ".html", ".htm"}
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"}
MAX_FILE = 1_000_000
MAX_LOCK = 25_000_000
MAX_FILES = 20_000
LINE_CAP = 2000          # regexes only ever see the first LINE_CAP chars of a line
MINIFIED_LINE = 2000
MAX_PER_CHECK = 100

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
DEFAULT_PROOF = "Found by reading the code; not reproduced in the lab."


class SourceFile:
    __slots__ = ("rel", "lines", "_text", "_head")

    def __init__(self, rel, lines):
        self.rel = rel
        self.lines = lines          # already capped to LINE_CAP chars each
        self._text = None
        self._head = None

    @property
    def text(self):
        if self._text is None:
            self._text = "\n".join(self.lines)
        return self._text

    @property
    def head(self):
        if self._head is None:
            self._head = "\n".join(self.lines[:8])
        return self._head

    @property
    def base(self):
        return self.rel.rsplit("/", 1)[-1]

    @property
    def ext(self):
        b = self.base
        i = b.rfind(".")
        return b[i:].lower() if i > 0 else ""

    def line_of(self, offset):
        return self.text.count("\n", 0, offset) + 1


def _wanted(base):
    low = base.lower()
    i = low.rfind(".")
    ext = low[i:] if i > 0 else ""
    if ext in CODE_EXT or ext in (".sql", ".rules"):
        return True
    if low in ("config.toml", "database.rules.json", "package.json") or low.startswith(".env"):
        return True
    if low.endswith(".rules.json"):
        return True
    return False


class Repo:
    """Walks the repository once and keeps the text of every file a check might want."""

    def __init__(self, root, deadline):
        self.root = os.path.realpath(root)
        self.deadline = deadline
        self.check_deadline = None
        self.files = {}           # rel -> SourceFile
        self.lockfiles = {}       # rel -> raw text
        self.stats = {"files_scanned": 0, "skipped_large": 0, "skipped_minified": 0, "skipped_binary": 0,
                      "truncated": False}
        self._walk()
        self.framework = self._framework()

    def _walk(self):
        count = 0
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            reld = os.path.relpath(dirpath, self.root).replace(os.sep, "/")
            reld = "" if reld == "." else reld
            keep = []
            for d in sorted(dirnames):
                sub = f"{reld}/{d}" if reld else d
                if d in SKIP_DIRS or sub in SKIP_DIRS or os.path.islink(os.path.join(dirpath, d)):
                    continue
                keep.append(d)
            dirnames[:] = keep
            for name in sorted(filenames):
                if time.monotonic() > self.deadline:
                    self.stats["truncated"] = True
                    return
                path = os.path.join(dirpath, name)
                rel = f"{reld}/{name}" if reld else name
                if os.path.islink(path):
                    continue
                if name in LOCKFILES:
                    self._load_lock(path, rel)
                    continue
                claude = reld.rsplit("/", 1)[-1] == ".claude" and name in ("settings.local.json", "settings.json")
                if (not _wanted(name) and not claude) or ".min." in name.lower():
                    if ".min." in name.lower():
                        self.stats["skipped_minified"] += 1
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size > MAX_FILE:
                    self.stats["skipped_large"] += 1
                    continue
                count += 1
                if count > MAX_FILES:
                    self.stats["truncated"] = True
                    return
                self._load(path, rel)

    def _load(self, path, rel):
        try:
            with open(path, "rb") as fh:
                raw = fh.read(MAX_FILE + 1)
        except OSError:
            return
        if b"\x00" in raw[:8192]:
            self.stats["skipped_binary"] += 1
            return
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        long_lines = 0
        for ln in lines:
            if len(ln) > MINIFIED_LINE:
                long_lines += 1
                if long_lines > 1:
                    break
        if long_lines > 1 or (long_lines == 1 and len(lines) <= 5):
            self.stats["skipped_minified"] += 1
            return
        self.files[rel] = SourceFile(rel, [ln[:LINE_CAP] for ln in lines])
        self.stats["files_scanned"] += 1

    def _load_lock(self, path, rel):
        try:
            if os.path.getsize(path) > MAX_LOCK:
                self.stats["skipped_large"] += 1
                return
            with open(path, "rb") as fh:
                self.lockfiles[rel] = fh.read(MAX_LOCK).decode("utf-8", errors="replace")
        except OSError:
            pass

    def _framework(self):
        pj = self.files.get("package.json")
        deps = {}
        if pj:
            try:
                data = json.loads(pj.text)
                for k in ("dependencies", "devDependencies"):
                    if isinstance(data.get(k), dict):
                        deps.update(data[k])
            except ValueError:
                pass
        if "next" in deps:
            return "next"
        if "vite" in deps:
            return "vite"
        if "react-scripts" in deps:
            return "cra"
        if "nuxt" in deps:
            return "nuxt"
        return "unknown"

    def rels(self):
        """Sorted relative paths; stops early (and marks the scan truncated) once the check deadline passes."""
        for rel in sorted(self.files):
            if self.check_deadline and time.monotonic() > self.check_deadline:
                self.stats["truncated"] = True
                return
            yield rel

    def code_files(self):
        for rel in self.rels():
            f = self.files[rel]
            if f.ext in CODE_EXT:
                yield f


# ---------------------------------------------------------------- path classification

_SERVER_ANY = re.compile(r"/(?:supabase/functions|netlify/functions|app/api|pages/api|src/server|"
                         r"server/api|server/routes)/")
_SERVER_TOP = re.compile(r"^/(?:api|server|functions|backend|edge-functions|lambda|lambdas)/")
_SERVER_FILE = re.compile(r"(?:/route\.[cm]?[jt]s|^/(?:server|middleware|worker)\.[cm]?[jt]s)$")
_TEST_PATH = re.compile(r"(?:/(?:__tests__|tests?|e2e|cypress|playwright|__mocks__|fixtures|stories)/|"
                        r"\.(?:test|spec|stories|e2e)\.[a-z]+$)")
_CLIENT_SEG = re.compile(r"(?:^|/)(?:src|client|frontend|web|public)/")
_NEXT_CLIENT_SEG = re.compile(r"(?:^|/)(?:components|hooks|contexts?|store|providers)/")
_SUPABASE_DIR = re.compile(r"^supabase/|/supabase/(?:functions|migrations)/")
_USE_CLIENT = re.compile(r"^\s*['\"]use client['\"]", re.M)


def is_server(rel):
    p = "/" + rel
    return bool(_SERVER_ANY.search(p) or _SERVER_TOP.search(p) or _SERVER_FILE.search(p))


def is_test(rel):
    return bool(_TEST_PATH.search("/" + rel))


def is_edge_function(rel):
    return ("/" + rel).find("/supabase/functions/") != -1


def is_client(f, framework):
    rel = f.rel
    if is_server(rel) or is_test(rel) or _SUPABASE_DIR.search(rel):
        return False
    if framework == "next":
        if _USE_CLIENT.search(f.head):
            return True
        if "use server" in f.head or "server-only" in f.head:
            return False
        return bool(_NEXT_CLIENT_SEG.search(rel))
    return bool(_CLIENT_SEG.search(rel)) or f.base.lower() == "index.html"


_COMMENT_PREFIX = {"code": ("//", "/*", "*", "<!--"), "sql": ("--", "/*", "*"), "hash": ("#",)}


def is_comment(line, kind="code"):
    s = line.lstrip()
    return s.startswith(_COMMENT_PREFIX[kind])


# ---------------------------------------------------------------- redaction

DOT = "•" * 4
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_PREFIXED = re.compile(
    r"\b((?:sk|rk|pk)_(?:live|test)_|whsec_|sb_secret_|sb_publishable_|ghp_|gho_|github_pat_|xox[abpr]-|"
    r"sk-ant-|sk-proj-|sk-|AKIA|AIza|glpat-|SG\.)([A-Za-z0-9_\-.]{8,})")
_ENV_VALUE = re.compile(r"(\b[A-Za-z0-9_]{0,60}(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PRIVATE)[A-Za-z0-9_]{0,60}"
                        r"\s*[=:]\s*['\"`]?)([^\s'\"`,;)]{6,})", re.I)
_LONG_QUOTED = re.compile(r"(['\"`])([A-Za-z0-9_\-+/=.]{28,})\1")
_EMAIL = re.compile(r"\b([A-Za-z0-9])[A-Za-z0-9._%+-]{0,63}@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24})\b")


def mask(value, keep_prefix=""):
    tail = value[-4:] if len(value) >= 12 else ""
    return f"{keep_prefix}{DOT}{tail}"


def redact(text, limit=180):
    s = " ".join(str(text).split())
    s = _JWT.sub(lambda m: mask(m.group(0), "eyJ"), s)
    s = _PREFIXED.sub(lambda m: mask(m.group(2), m.group(1)), s)
    s = _ENV_VALUE.sub(lambda m: m.group(1) + (m.group(2) if DOT in m.group(2) or _is_ref(m.group(2))
                                               else mask(m.group(2))), s)
    s = _LONG_QUOTED.sub(lambda m: m.group(1) + (mask(m.group(2)) if _looks_secret(m.group(2)) else m.group(2))
                         + m.group(1), s)
    s = _EMAIL.sub(lambda m: f"{m.group(1)}{DOT}@{m.group(2)}", s)
    if len(s) > limit:
        s = s[:limit - 1] + "…"
    return s


def _looks_secret(v):
    if DOT in v or v.startswith((".", "/", "http")):
        return False
    return sum(c.isdigit() for c in v) >= 3 and sum(c.isalpha() for c in v) >= 6


def _is_ref(v):
    """Values that are references, not secrets: env lookups, identifiers, property paths."""
    return bool(re.match(r"^(?:Deno\.env|process\.env|import\.meta|env\.|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_]"
                         r"[A-Za-z0-9_]*)*(?:\(|$))", v)) and not re.search(r"\d{4,}", v)


def jwt_role(token):
    """Decode (never verify) a JWT payload and return its role claim, or None."""
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part.encode()).decode("utf-8", "replace"))
        return data.get("role") if isinstance(data, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------- finding shape

def finding(fid, severity, title, file, line_no, evidence, fix, obj=None, advisory=None, proof=None):
    d = {
        "id": fid, "line": "code", "severity": severity, "title": title,
        "object": obj or file, "file": file, "line_no": line_no,
        "evidence": redact(evidence), "proven": False, "proof": proof or DEFAULT_PROOF,
        "fix": fix, "fixed_in_lab": False, "source": "codescan",
    }
    if advisory:
        d["advisory"] = advisory
    return d
