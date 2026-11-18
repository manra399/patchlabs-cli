"""PL-039: passwords stored or looked up in plain text.

AI builders asked for "a login page" sometimes write their own users table with a password column and save what
the user typed, then log people in with a query like .eq('password', password). Anyone who can read that table
(a leaky RLS policy, a backup, a support tool, a log) gets every user's password, and people reuse passwords.

Text only, line based. Three signals:
  1. a database query that matches rows on the password value (.eq('password', ...), where: { email, password },
     WHERE password = $1, Firestore where('password', '==', ...)): only possible if the stored value is the
     typed password (or an unsalted hash, which is almost as bad). High.
  2. a direct database write (supabase-js insert/upsert/update, drizzle values/set, prisma create/update, Firestore
     setDoc/addDoc, MongoDB insertOne, Django objects.create, SQL INSERT/UPDATE) that puts a bare password field in
     the row, in a repo that never calls a password hash (bcrypt, argon2, scrypt, pbkdf2, any *hash*() helper). High.
  3. a SQL table with a column called password (or passwd, plain_password, user_password) of a text type in a
     repo that never hashes passwords anywhere. Medium: the name alone doesn't prove what goes in it.
Calls to an auth provider (supabase.auth.signUp, auth.admin.createUser, createUserWithEmailAndPassword, ...) are
not writes: the provider hashes.
"""
import re

from .common import finding, is_comment, is_test

JS_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro")
PY_EXT = (".py",)

PW = r"(?:password|passwd|pass_word|plain_?password|user_?password|plaintext_?password)"
HASHING = re.compile(r"bcrypt|argon2|\bscrypt|pbkdf2|hashpw|hashSync|hash_password|make_password|"
                     r"generate_password_hash|check_password_hash|passlib|CryptContext|Bun\.password|"
                     r"password_hash\s*\(|password_verify|crypt\s*\(|gen_salt|\w*hash\w*\s*\(", re.I)
HASHED_VALUE = re.compile(r"hash|crypt|digest|encrypt|argon|bcrypt|scrypt|pbkdf|\*{3,}|null|undefined|None\b|"
                          r"['\"`]{2}|^\s*(?:true|false|0|1)\b|^\s*\{", re.I)   # select/include flags, nested writes
AUTH_CALL = re.compile(r"\bauth\.|signUp|signIn|createUserWith|updateUser|admin\.createUser|resetPassword|"
                       r"verifyPassword|comparePassword|\.compare\s*\(", re.I)

# 1. lookups on the password value
# password used as a key: `password: value`, `password=value`, or the shorthand `{ email, password }`
KEYFORM = (r"(?:^|(?<=[{,(\s]))['\"]?" + PW + r"['\"]?\s*(?:(?::|=(?!=))\s*([^,})\n]{1,80})|(?=[,})]))")
LOOKUP = [
    re.compile(r"\.(?:eq|match|filter)\s*\(\s*['\"`]" + PW + r"['\"`]\s*,\s*(.{1,120})", re.I),      # supabase
    re.compile(r"\bwhere\s*\(\s*['\"`]" + PW + r"['\"`]\s*,\s*['\"`]==['\"`]\s*,\s*(.{1,120})", re.I),  # firestore
    re.compile(r"\bwhere\s*:\s*\{[^}]{0,200}?" + KEYFORM, re.I),                                      # prisma/sequelize
    re.compile(r"(?:\.(?:findOne|findFirst|findUnique|findOneBy|find_one|filter_by)|\.objects\.(?:get|filter))"
               r"\s*\([^)]{0,200}?" + KEYFORM, re.I),                                                   # ORMs
    re.compile(r"\bWHERE\b[^;]{0,200}?\b" + PW + r"\s*=\s*(\$\d+|\?|%s|:\w+|\$\{[^}]+\}|['\"]\s*\+|\{\w+\})",
               re.I),                                                                                 # raw SQL
]

# 2. writes that carry a bare password field
# Only direct database clients: an ORM or CMS service (payload.create, directus updateOne, a mongoose model with
# a pre-save hook) may hash on its own.
WRITE = re.compile(r"\.from\s*\(\s*['\"`][\w.]+['\"`]\s*\)\s*\.(?:insert|upsert|update)\s*\(|"   # supabase-js
                   r"^\s*\.(?:insert|upsert|update)\s*\(|"                                         # chained
                   r"\)\s*\.(?:values|set)\s*\(|"                                                # drizzle
                   r"\bprisma\.\w+\.(?:create|createMany|update|upsert)\s*\(|"                      # prisma
                   r"\b(?:setDoc|addDoc|updateDoc)\s*\(|"                                         # firestore
                   r"\.(?:insertOne|insertMany)\s*\(|"                                            # mongodb driver
                   r"\.objects\.create\s*\(|"                                                    # django
                   r"\bINSERT\s+INTO\b|\bUPDATE\s+[\w.\"]+\s+SET\b[^;]{0,200}?\b" + PW + r"\s*=", re.I)
PW_KEY = re.compile(r"(?<![\w.])['\"]?" + PW + r"['\"]?\s*(?::|=(?!=))\s*([^,}\n]{1,80})|"
                    r"(?<![\w.:'\"])" + PW + r"\s*(?=[,}])", re.I)
SQL_INSERT_COLS = re.compile(r"\bINSERT\s+INTO\s+[\w.\"]+\s*\(([^)]{1,400})\)", re.I)
WRITE_WINDOW = 10

# 3. schema
CREATE_TABLE = re.compile(r"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?([\w.\"]+)", re.I)
PW_COLUMN = re.compile(r"^\s*,?\s*\"?(" + PW + r")\"?\s+(?:text|varchar|character\s+varying|char|citext)\b", re.I)
ADD_PW_COLUMN = re.compile(r"\badd\s+column\s+(?:if\s+not\s+exists\s+)?\"?(" + PW + r")\"?\s+"
                           r"(?:text|varchar|character\s+varying|char|citext)\b", re.I)

FIX = ("Never store or compare the password itself. Best: delete the custom password column and let your auth "
       "provider do it (Supabase Auth signUp / signInWithPassword, Firebase Auth, Clerk), which hashes for you. If "
       "you must keep your own users table, hash with Argon2id or bcrypt before saving and log in by loading the row "
       "by email and calling the library's verify function, never with a query that matches on the password. If "
       "real passwords were ever saved, treat them as leaked: force a reset for every account and tell users who "
       "may have reused them.")


def _is_hashed(value):
    value = re.split(r"\s(?://|#|--)", value or "")[0]    # a trailing comment ("hash this later") is not a hash
    return bool(value) and bool(HASHED_VALUE.search(value))


def _lookup_hits(f, rel, kind):
    out = []
    for i, ln in enumerate(f.lines, 1):
        if is_comment(ln, kind) or AUTH_CALL.search(ln):
            continue
        for rx in LOOKUP:
            m = rx.search(ln)
            if not m:
                continue
            if _is_hashed(m.group(1) if m.lastindex else ""):
                break
            out.append(finding("PL-039", "high", "Login looks users up by their password (stored in plain text)",
                               rel, i, ln.strip(), FIX))
            break
    return out


def _write_hits(f, rel, kind):
    out, lines, done = [], f.lines, set()
    for i, ln in enumerate(lines):
        if is_comment(ln, kind) or AUTH_CALL.search(ln) or not WRITE.search(ln):
            continue
        m = SQL_INSERT_COLS.search(ln)
        if m:
            if re.search(r"(?<![\w])" + PW + r"(?![\w])", m.group(1), re.I) and i not in done:
                done.add(i)
                out.append(finding("PL-039", "high", "Password saved to the database without hashing", rel, i + 1,
                                   ln.strip(), FIX))
            continue
        # the row object: this line and up to WRITE_WINDOW lines below, stopping at the call's closing paren
        depth = 0
        for j in range(i, min(len(lines), i + WRITE_WINDOW + 1)):
            seg = lines[j]
            if j > i and is_comment(seg, kind):
                continue
            k = PW_KEY.search(seg if j > i else seg[WRITE.search(seg).start():])
            if k and not _is_hashed(k.group(1)) and j not in done:
                done.add(j)
                out.append(finding("PL-039", "high", "Password saved to the database without hashing", rel, j + 1,
                                   seg.strip(), FIX))
                break
            depth += seg.count("(") - seg.count(")")
            if depth <= 0:
                break
    return out


def _schema_hits(f, rel):
    out, table = [], None
    for i, ln in enumerate(f.lines, 1):
        if is_comment(ln, "sql"):
            continue
        t = CREATE_TABLE.search(ln)
        if t:
            table = t.group(1).strip('"').lower()
        if table and table.startswith("auth."):
            continue
        if (table and PW_COLUMN.search(ln)) or ADD_PW_COLUMN.search(ln):
            out.append(finding("PL-039", "medium", "Table has a plain password column and the app never hashes "
                               "passwords", rel, i, ln.strip(), FIX, obj=table or rel))
        if ";" in ln:
            table = None
    return out


def check_passwords(repo):
    files = []
    for rel in repo.rels():
        f = repo.files[rel]
        if is_test(rel) or "/node_modules/" in "/" + rel or "/seed" in "/" + rel.lower():
            continue
        if f.ext in JS_EXT:
            files.append((rel, f, "code"))
        elif f.ext in PY_EXT:
            files.append((rel, f, "hash"))
        elif f.ext == ".sql":
            files.append((rel, f, "sql"))
    repo_hashes = any(HASHING.search(f.text) for _, f, _ in files)
    out = []
    for rel, f, kind in files:
        out.extend(_lookup_hits(f, rel, kind))
        if kind == "sql":
            if not repo_hashes:
                out.extend(_schema_hits(f, rel))
            continue
        if not repo_hashes:
            out.extend(_write_hits(f, rel, kind))
    return out
