"""PL-009 for Claude Code settings files.

Claude Code saves "Yes, and don't ask again" approvals as allow rules in .claude/settings.local.json, and the rule is
the command text itself, so a token or password typed into the command is saved in plain text. Claude Code keeps that
file out of commits through the global git excludes of the machine that wrote it, which doesn't cover a file git
already tracks, another machine, or `npm publish` (npm reads .npmignore / .gitignore / "files", never the global
excludes). This check reads the files as text; it never runs anything from the repository.
"""
import json
import os
import re
import subprocess

from .common import finding, mask

GUIDE = "https://patchlabs.dev/learn/claude-code-settings-local-json-secrets"
SETTINGS = ("settings.local.json", "settings.json")

_PREFIXED = re.compile(
    r"(?:\b(?:sk|rk)_live_[A-Za-z0-9]{16,}|\bsk-ant-[A-Za-z0-9_\-]{20,}|\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}"
    r"|\bsk-or-v1-[a-f0-9]{32,}|\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}|\bglpat-[A-Za-z0-9_\-]{20}"
    r"|\bnpm_[A-Za-z0-9]{36}|\bxox[abprs]-[A-Za-z0-9\-]{10,}|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bhf_[A-Za-z0-9]{30,}"
    r"|\bgsk_[A-Za-z0-9]{40,}|\bsb_secret_[A-Za-z0-9_\-]{16,}|\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{16,}"
    r"|\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}|\b\d{8,10}:[A-Za-z0-9_\-]{35}\b)")
_GENERIC = [
    re.compile(r"(?:Bearer|Token|Basic)\s+([A-Za-z0-9._~+/=\-]{16,})"),
    re.compile(r"\b(?:x-api-key|apikey|api-key|x-auth-token|private-token)\s*:\s*([A-Za-z0-9._~+/=\-]{16,})", re.I),
    re.compile(r"\b[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|AUTH)[A-Z0-9_]*=['\"]?([^\s'\"$`)]{8,})"),
    re.compile(r"--(?:password|passwd|token|api-key|apikey|secret)[= ]['\"]?([^\s'\"$`)]{8,})", re.I),
    re.compile(r"\s-(?:u|-user)\s+['\"]?[^\s:'\"]+:([^\s@'\"$`)]{6,})"),
    re.compile(r"://[^\s:/@'\"]+:([^\s@'\"$`]{6,})@"),
    re.compile(r"\s-p['\"]?([^\s'\"$`)-][^\s'\"$`)]{7,})"),
]
_SECRET_KEY = re.compile(r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE|CREDENTIAL|AUTH)", re.I)
_PLACEHOLDER = re.compile(r"(?:xxx|your[_\-]?|example|placeholder|changeme|redacted|dummy|<[^>]*>|\*{3,}|\.\.\.)", re.I)


def _secret_in(text):
    m = _PREFIXED.search(text)
    if m:
        return m.group(0)
    for rx in _GENERIC:
        for m in rx.finditer(text):
            v = m.group(1)
            if _PLACEHOLDER.search(v) or len(set(v)) <= 4:
                continue
            return v
    return None


def _strings(data):
    """(where, text) for every permission rule and env value."""
    out = []
    if not isinstance(data, dict):
        return out
    perms = data.get("permissions")
    if isinstance(perms, dict):
        for kind in ("allow", "ask", "deny"):
            for rule in perms.get(kind) or []:
                if isinstance(rule, str):
                    out.append((f"permissions.{kind}", rule))
    env = data.get("env")
    if isinstance(env, dict):
        for k, v in env.items():
            if isinstance(v, str) and v and _SECRET_KEY.search(str(k)) and not _PLACEHOLDER.search(v) \
                    and not v.startswith("$") and len(v) >= 8:
                out.append((f"env.{k}", f"{k}={v}"))
    return out


def _tracked(root, rel):
    try:
        r = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch", "--", rel],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _line_of(f, text):
    probe = json.dumps(text)[1:41]
    for i, ln in enumerate(f.lines, 1):
        if probe and probe in ln:
            return i
    return 1


def _npm_ships(repo, pkg_dir):
    """True if `npm publish` from pkg_dir would include .claude/settings.local.json."""
    pj = repo.files.get(f"{pkg_dir}/package.json" if pkg_dir else "package.json")
    if not pj:
        return False
    try:
        data = json.loads(pj.text)
    except ValueError:
        return False
    if not isinstance(data, dict) or data.get("private") is True or not data.get("name"):
        return False
    files = data.get("files")
    if isinstance(files, list):
        return any(isinstance(p, str) and p.strip("./").startswith(".claude") for p in files)
    base = os.path.join(repo.root, pkg_dir)
    for ignore in (".npmignore",) if os.path.exists(os.path.join(base, ".npmignore")) else (".gitignore",):
        try:
            with open(os.path.join(base, ignore), encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    s = ln.strip().lstrip("/")
                    if s and not s.startswith(("#", "!")) and (s.startswith(".claude") or
                                                                s.startswith("**/.claude") or
                                                                s.endswith("settings.local.json")):
                        return False
        except OSError:
            pass
    return True


def check_claude_settings(repo):
    out = []
    for rel in repo.rels():
        parts = rel.split("/")
        if len(parts) < 2 or parts[-2] != ".claude" or parts[-1] not in SETTINGS:
            continue
        f = repo.files[rel]
        local = parts[-1] == "settings.local.json"
        tracked = _tracked(repo.root, rel)
        try:
            data = json.loads(f.text)
        except ValueError:
            data = None
        leaked = 0
        for where, text in _strings(data):
            secret = _secret_in(text)
            if not secret:
                continue
            leaked += 1
            sev = "critical" if tracked else "high"
            title = ("Secret saved in a Claude Code settings file that git tracks" if tracked
                     else "Secret saved in a Claude Code settings file")
            out.append(finding(
                "PL-009", sev, title, rel, _line_of(f, text.split("=", 1)[1] if where.startswith("env.") else text), f"{where}: {text.replace(secret, mask(secret))}",
                f"Rotate the credential at the service first; it has been on disk in plain text"
                f"{' and in your git history' if tracked else ''}. Then delete the rule, pass the secret through an "
                f"environment variable instead of typing it into the command, and allow the command with a wildcard "
                f"rule such as Bash(curl *). Guide: {GUIDE}"))
        if local and tracked and not leaked:
            out.append(finding(
                "PL-009", "low", "Claude Code local settings file is committed to git", rel, 1,
                "git ls-files lists " + rel,
                f"Every future \"don't ask again\" approval will be committed with it. Run git rm --cached {rel} and "
                f"add .claude/settings.local.json to .gitignore. Guide: {GUIDE}"))
        if local:
            pkg_dir = "/".join(parts[:-2])
            if _npm_ships(repo, pkg_dir):
                out.append(finding(
                    "PL-009", "high" if leaked else "medium",
                    "npm publish would ship the Claude Code local settings file", rel, 1,
                    f"{pkg_dir or '.'}/package.json has no \"files\" list and no ignore rule for .claude",
                    f"npm ignores your global git excludes, so this file goes into the package. Add a \"files\" list to "
                    f"package.json (or .claude/ to .npmignore) and check with npm pack --dry-run. Guide: {GUIDE}"))
    return out
