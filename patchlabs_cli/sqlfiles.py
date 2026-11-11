"""Reads the *.sql files of a repository as text, for the static RLS read.

Walks the tree the way the code scanner does: symlinks are not followed, dependency and build folders are skipped,
and files over 1 MB or with NUL bytes are left out. Files under supabase/migrations come first, then the rest.
"""
import os
import re
import time

from .codescan.common import MAX_FILE, MAX_FILES, SKIP_DIRS

MIGRATION_MARK = "/supabase/migrations/"
TIME_LIMIT_S = 60


def collect(root, time_limit=TIME_LIMIT_S):
    """Returns ([(relative path, text)], stats). Never raises for unreadable files."""
    deadline = time.monotonic() + time_limit
    stats = {"sql_files": 0, "sql_skipped_large": 0, "sql_skipped_binary": 0, "sql_truncated": False}
    files = []
    root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        reld = os.path.relpath(dirpath, root).replace(os.sep, "/")
        reld = "" if reld == "." else reld
        keep = []
        for d in sorted(dirnames):
            sub = f"{reld}/{d}" if reld else d
            if d in SKIP_DIRS or sub in SKIP_DIRS or os.path.islink(os.path.join(dirpath, d)):
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            if not name.lower().endswith(".sql"):
                continue
            if time.monotonic() > deadline or len(files) >= MAX_FILES:
                stats["sql_truncated"] = True
                return _ordered(files), _done(stats, files)
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                continue
            try:
                if os.path.getsize(path) > MAX_FILE:
                    stats["sql_skipped_large"] += 1
                    continue
                with open(path, "rb") as fh:
                    raw = fh.read(MAX_FILE + 1)
            except OSError:
                continue
            if b"\x00" in raw[:8192]:
                stats["sql_skipped_binary"] += 1
                continue
            rel = f"{reld}/{name}" if reld else name
            files.append((rel, raw.decode("utf-8", errors="replace")))
    return _ordered(files), _done(stats, files)


def project_key(rel):
    """The folder a SQL file belongs to: the part of its path before supabase/, or its own folder otherwise.

    Each key is analysed on its own, so two apps in one monorepo can both have a table called profiles.
    """
    p = "/" + rel
    i = p.find("/supabase/")
    if i != -1:
        return p[1:i]
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


SUPABASE_HINT = re.compile(r"\bauth\.(uid|jwt|role)\s*\(|\bto\s+(anon|authenticated)\b|\bstorage\.objects\b", re.I)


def is_supabase(rel, text):
    """True for SQL that runs behind the Supabase API: files under supabase/, or SQL that uses Supabase's auth helpers or
    roles. Plain Postgres schemas (a server's own database) are left out, since their tables aren't exposed to anon."""
    return "/supabase/" in "/" + rel or bool(SUPABASE_HINT.search(text))


def group(files):
    """{project key: [(path, text)]} for Supabase SQL only, keeping the migration order inside each group."""
    out = {}
    for rel, text in files:
        if is_supabase(rel, text):
            out.setdefault(project_key(rel), []).append((rel, text))
    return out


def _ordered(files):
    return sorted(files, key=lambda item: (MIGRATION_MARK not in "/" + item[0], item[0]))


def _done(stats, files):
    stats["sql_files"] = len(files)
    return stats
