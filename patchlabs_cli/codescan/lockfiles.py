"""Read npm dependency versions from lockfiles without running any package manager.

Supported: package-lock.json / npm-shrinkwrap.json (v1, v2, v3), pnpm-lock.yaml (line parser, no YAML lib),
yarn.lock (classic and berry), bun.lock (JSONC text) and a package.json fallback (exact versions only).
"""
import json
import re

NAME_RE = re.compile(r"^(?:@[a-z0-9][\w.~-]{0,100}/)?[a-z0-9][\w.~-]{0,213}$", re.I)
VERSION_RE = re.compile(r"^\d{1,9}\.\d{1,9}\.\d{1,9}(?:[-+][0-9A-Za-z.+-]{1,100})?$")
LOCK_PRIORITY = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"]


class Pkg:
    __slots__ = ("name", "version", "direct", "dev")

    def __init__(self, name, version, direct=False, dev=False):
        self.name, self.version, self.direct, self.dev = name, version, direct, dev

    def key(self):
        return self.name, self.version

    def __repr__(self):
        return f"Pkg({self.name}@{self.version}{' direct' if self.direct else ''}{' dev' if self.dev else ''})"


def manifest_deps(pkg_json_text):
    """(prod names, dev names, {name: spec}) from a package.json text."""
    try:
        data = json.loads(pkg_json_text)
    except ValueError:
        return set(), set(), {}
    prod, dev, specs = set(), set(), {}
    if not isinstance(data, dict):
        return prod, dev, specs
    for k in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
        v = data.get(k)
        if isinstance(v, dict):
            for n, s in v.items():
                if isinstance(n, str) and isinstance(s, str):
                    (dev if k == "devDependencies" else prod).add(n)
                    specs.setdefault(n, s)
    return prod, dev - prod, specs


def _ok(name, version):
    return bool(name and version and NAME_RE.match(name) and VERSION_RE.match(version))


def _split_spec(spec):
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3')."""
    i = spec.rfind("@")
    if i <= 0:
        return None, None
    return spec[:i], spec[i + 1:]


# ---------------------------------------------------------------- npm

def parse_package_lock(text):
    data = json.loads(text)
    out = []
    pk = data.get("packages")
    if isinstance(pk, dict) and pk:
        for key, meta in pk.items():
            if not key or "node_modules/" not in key or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[1]
            ver = meta.get("version")
            if isinstance(ver, str) and _ok(name, ver):
                top = key == "node_modules/" + name
                out.append((Pkg(name, ver, dev=bool(meta.get("dev"))), top))
        return out
    stack = [(data.get("dependencies") or {}, True, 0)]
    while stack:
        deps, top, depth = stack.pop()
        if not isinstance(deps, dict) or depth > 60:
            continue
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if isinstance(ver, str) and _ok(name, ver):
                out.append((Pkg(name, ver, dev=bool(meta.get("dev"))), top))
            if isinstance(meta.get("dependencies"), dict):
                stack.append((meta["dependencies"], False, depth + 1))
    return out


# ---------------------------------------------------------------- pnpm

def parse_pnpm_lock(text):
    out = []
    major = 6
    section = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            s = raw.strip()
            if s.startswith("lockfileVersion:"):
                v = s.split(":", 1)[1].strip().strip("'\"")
                try:
                    major = int(float(v))
                except ValueError:
                    major = 6
            section = s[:-1] if s.endswith(":") else None
            continue
        if section != "packages":
            continue
        if not (raw.startswith("  ") and not raw.startswith("   ") and raw.rstrip().endswith(":")):
            continue
        key = raw.strip()[:-1].strip().strip("'\"").lstrip("/")
        key = key.split("(", 1)[0]
        if major < 6:
            if "/" not in key:
                continue
            name, ver = key.rsplit("/", 1)
            ver = ver.split("_", 1)[0]
        else:
            name, ver = _split_spec(key)
        if _ok(name, ver):
            out.append((Pkg(name, ver), False))
    return out


# ---------------------------------------------------------------- yarn

_YARN_VER = re.compile(r"^\s{2,}version:?\s+\"?([^\"\s]{1,120})\"?\s*$")
_SKIP_PROTO = ("@workspace:", "@patch:", "@file:", "@link:", "@portal:", "@exec:", "@git", "@http")


def parse_yarn_lock(text):
    out = []
    current = None
    for raw in text.splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        if not raw.startswith(" "):
            s = raw.rstrip()
            current = None
            if not s.endswith(":") or s.startswith("__metadata"):
                continue
            spec = s[:-1].split(",")[0].strip().strip('"').strip("'")
            if any(p in spec for p in _SKIP_PROTO):
                continue
            if "@npm:" in spec:
                alias, real = spec.split("@npm:", 1)
                n2, _ = _split_spec(real)
                spec_name = n2 if n2 and NAME_RE.match(n2) else alias
            else:
                spec_name, _ = _split_spec(spec)
            current = spec_name
            continue
        if current:
            m = _YARN_VER.match(raw)
            if m:
                if _ok(current, m.group(1)):
                    out.append((Pkg(current, m.group(1)), False))
                current = None
    return out


# ---------------------------------------------------------------- bun

def strip_jsonc(text):
    """Remove // and /* */ comments and trailing commas outside strings."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
            out.append(c)
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def parse_bun_lock(text):
    data = json.loads(strip_jsonc(text))
    out = []
    pk = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(pk, dict):
        return out
    for key, val in pk.items():
        if not isinstance(val, list) or not val or not isinstance(val[0], str):
            continue
        spec = val[0]
        if any(p in spec for p in _SKIP_PROTO):
            continue
        name, ver = _split_spec(spec)
        if ver and ver.startswith("npm:"):
            name, ver = _split_spec(ver[4:])
        if _ok(name, ver):
            out.append((Pkg(name, ver), "/" not in key or key.startswith("@") and key.count("/") == 1))
    return out


# ---------------------------------------------------------------- package.json fallback

_EXACT = re.compile(r"^(?:=|v)?(\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z.-]{1,60})?)$")


def parse_package_json(text):
    prod, dev, specs = manifest_deps(text)
    out = []
    for name in sorted(specs):
        m = _EXACT.match(specs[name].strip())
        if m and _ok(name, m.group(1)):
            out.append((Pkg(name, m.group(1), direct=True, dev=name in dev), True))
    return out


PARSERS = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock,
    "bun.lock": parse_bun_lock,
}


def collect(lockfiles, package_jsons):
    """Merge every lockfile found into one de-duplicated, ordered package list.

    lockfiles: {rel_path: text}; package_jsons: {rel_path: text}. Returns (pkgs, sources, errors) where
    sources maps (name, version) -> rel path of the file it came from.
    """
    prod, dev = set(), set()
    for rel in sorted(package_jsons):
        p, d, _ = manifest_deps(package_jsons[rel])
        prod |= p
        dev |= d
    dev -= prod
    seen, sources, errors = {}, {}, []

    def rank(rel):
        base = rel.rsplit("/", 1)[-1]
        return rel.count("/"), LOCK_PRIORITY.index(base) if base in LOCK_PRIORITY else 9, rel

    for rel in sorted(lockfiles, key=rank):
        base = rel.rsplit("/", 1)[-1]
        try:
            entries = PARSERS[base](lockfiles[rel])
        except Exception as e:  # malformed lockfile: note it, keep going
            errors.append(f"{rel}: {type(e).__name__}")
            continue
        for pkg, top in entries:
            k = pkg.key()
            pkg.direct = bool(top and (pkg.name in prod or pkg.name in dev)) or (
                base in ("pnpm-lock.yaml", "yarn.lock") and pkg.name in (prod | dev))
            pkg.dev = pkg.dev or (pkg.name in dev and pkg.name not in prod)
            if k in seen:
                seen[k].direct = seen[k].direct or pkg.direct
                continue
            seen[k] = pkg
            sources[k] = rel
    if not seen:
        for rel in sorted(package_jsons, key=lambda r: (r.count("/"), r)):
            try:
                entries = parse_package_json(package_jsons[rel])
            except Exception as e:
                errors.append(f"{rel}: {type(e).__name__}")
                continue
            for pkg, _ in entries:
                if pkg.key() not in seen:
                    seen[pkg.key()] = pkg
                    sources[pkg.key()] = rel
    pkgs = sorted(seen.values(), key=lambda p: (not p.direct, p.dev, p.name, p.version))
    return pkgs, sources, errors
