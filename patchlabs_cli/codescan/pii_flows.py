"""PL-037: personal data put in HTTP request headers, or sent to an AI model API.

Headers are copied into CDN, proxy, load-balancer and APM logs that keep them for months and that many vendors can
read. Prompts sent to an AI API are stored by the provider (and by any gateway in between) for abuse monitoring,
traces and evals. Neither is where a user's email, phone number or ID number should go unless you decided it must.

Text only, line based. Two signals:
  1. a header is set whose name or value carries a personal field (user.email in 'X-User-Email', a literal address);
  2. in a file that calls an AI model API, a prompt line interpolates a personal field or a whole user record.
Severity: high for government ID, health, card or bank fields; medium for contact fields (email, phone, address,
date of birth, full name).
"""
import re

from .common import finding, is_comment, is_test

JS_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro")
PY_EXT = (".py",)

HIGH_FIELDS = (r"ssn|social_?security(?:_?number)?|national_?insurance(?:_?number)?|ni_?number|nino|passport"
               r"(?:_?(?:no|number))?|tax_?id|tin|driv(?:er|ing)_?licen[cs]e(?:_?(?:no|number))?|"
               r"medical_?(?:history|record|notes?)|diagnosis|health_?(?:data|record)|card_?number|"
               r"credit_?card|cvv|iban|account_?number|sort_?code|routing_?number")
MED_FIELDS = (r"email(?:_?address)?|phone(?:_?number)?|mobile(?:_?number)?|telephone|date_?of_?birth|dob|"
              r"birth_?date|birthday|home_?address|street_?address|address(?:_?line_?1)?|postcode|zip_?code|"
              r"full_?name|first_?name|last_?name|surname|ip_?address")
OWNER = r"(?:user|profile|customer|client|patient|member|account|contact|person|lead|applicant|student|employee|me|data|body|row|record|session\.user|req\.body|request\.body|currentUser|current_user)"
# owner.field / owner?.field / owner["field"] / owner['field']
FIELD_REF = re.compile(r"\b" + OWNER + r"\s*(?:\?\.|\.|\[\s*['\"])\s*(" + HIGH_FIELDS + "|" + MED_FIELDS
                       + r")\b", re.I)
HIGH_ONLY = re.compile(r"^(?:" + HIGH_FIELDS + r")$", re.I)
WHOLE_RECORD = re.compile(r"(?:JSON\.stringify|json\.dumps)\s*\(\s*(?:\w+\.)?(user|profile|customer|patient|"
                          r"client|member|contact|person|applicant|employee|record|row)s?\s*[,)]", re.I)
EMAIL_LIT = re.compile(r"['\"`][A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,5}\.[A-Za-z]{2,24}"
                       r"['\"`]")
PLACEHOLDER_EMAIL = re.compile(r"@(?:example\.(?:com|org|net)|test\.com|localhost|users\.noreply\.github\.com)", re.I)

# --- headers
HEADER_NAME_PII = re.compile(r"['\"`]?(x-[\w-]{0,30}(?:email|phone|mobile|ssn|dob|birth|address|passport|"
                             r"national-insurance|full-?name|user-name)[\w-]{0,20})['\"`]?\s*[:,]", re.I)
HEADER_CONTEXT = re.compile(r"\bheaders?\b|setHeader\s*\(|\.headers\.(?:set|append)\s*\(|"
                            r"\bres\.(?:set|header)\s*\(", re.I)
HEADER_CALL = re.compile(r"(?:setHeader|\w+\.(?:set|append)|res\.(?:set|header))\s*\(\s*['\"`]([A-Za-z][\w]*-[\w-]{1,58})"
                         r"['\"`]\s*,\s*(.{1,200})", re.I)
HEADER_PAIR = re.compile(r"['\"`]([A-Za-z][\w-]{1,60})['\"`]\s*:\s*(.{1,200})")
SAFE_HEADERS = re.compile(r"^(?:authorization|content-type|accept|apikey|x-api-key|x-client-info|cookie|"
                          r"x-request-id|x-correlation-id|prefer|range|cache-control|if-none-match)$", re.I)

# --- AI APIs
AI_FILE = re.compile(r"from\s+['\"](?:openai|@anthropic-ai/sdk|@google/generative-ai|@google/genai|ai|@ai-sdk/[\w-]+|"
                     r"groq-sdk|@mistralai/mistralai|cohere-ai|replicate|together-ai|langchain|@langchain/[\w-]+)['\"]|"
                     r"require\(\s*['\"](?:openai|@anthropic-ai/sdk|ai|@google/generative-ai)['\"]\s*\)|"
                     r"^\s*(?:from|import)\s+(?:openai|anthropic|google\.generativeai|google\.genai|litellm|"
                     r"langchain\w*|mistralai|cohere|groq)\b|"
                     r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|"
                     r"api\.groq\.com|api\.mistral\.ai|openrouter\.ai/api", re.I | re.M)
AI_CALL = re.compile(r"chat\.completions\.create|responses\.create|messages\.create|completions\.create|"
                     r"generateContent|generateText|streamText|generateObject|streamObject|\.invoke\s*\(|"
                     r"litellm\.completion|ChatCompletion\.create|api\.openai\.com|api\.anthropic\.com|"
                     r"openrouter\.ai/api|generativelanguage\.googleapis\.com", re.I)
PROMPT_LINE = re.compile(r"\$\{|\bf['\"]|\{[\w.\[\]'\"]+\}|\bcontent\b|\bprompt\b|\bmessages?\b|\binput\b|"
                         r"\bsystem\b|\+\s*\w", re.I)
WINDOW = 40   # lines around an AI call that count as "the prompt"

HEADER_FIX = ("Send the user's id (or nothing) and look the details up on the server. Headers are written to CDN, "
              "proxy and APM logs that keep them for months and that other vendors can read; if a header must carry "
              "an identifier, use an opaque id, never an email, phone or ID number.")
AI_FIX = ("Send the model only what the task needs: drop or mask contact and ID fields before building the prompt "
          "(replace them with placeholders and fill them back in after), never JSON.stringify a whole user record, "
          "and check the provider's retention and training settings for your account. The provider and any gateway "
          "or tracing tool in between keep prompts.")


def _sev(field):
    return "high" if HIGH_ONLY.match(field.replace("-", "_")) else "medium"


def _line_sev(text):
    """Highest severity over every personal field referenced in text, or None."""
    sevs = [_sev(m.group(1)) for m in FIELD_REF.finditer(text)]
    if not sevs:
        return None
    return "high" if "high" in sevs else "medium"


def _lit_email(text):
    m = EMAIL_LIT.search(text)
    return bool(m) and not PLACEHOLDER_EMAIL.search(m.group(0))


def _header_hits(f, rel, comment_kind):
    out = []
    lines = f.lines
    for i, ln in enumerate(lines, 1):
        if is_comment(ln, comment_kind):
            continue
        name = value = None
        m = HEADER_CALL.search(ln)
        if m:
            name, value = m.group(1), m.group(2)
        else:
            # a "Name": value pair inside a headers block (this line or up to 8 lines below 'headers')
            p = HEADER_PAIR.search(ln)
            if p and any(HEADER_CONTEXT.search(lines[j]) for j in range(max(0, i - 9), i)):
                name, value = p.group(1), p.group(2)
        if not name or SAFE_HEADERS.match(name):
            continue
        # header pairs are only interesting if the name looks like a header (x-..., or contains a dash)
        if not m and "-" not in name:
            continue
        ref = _line_sev(value)
        named = HEADER_NAME_PII.search(f"'{name}':")
        if ref:
            sev = ref
        elif _lit_email(value):
            sev = "medium"
        elif named and re.search(r"[\w)\]]", value):
            sev = "medium"
        else:
            continue
        out.append(finding("PL-037", sev, "Personal data sent in a request header", rel, i, ln.strip(),
                           HEADER_FIX))
    return out


def _ai_hits(f, rel, comment_kind):
    if not AI_FILE.search(f.text):
        return []
    lines = f.lines
    calls = [i for i, ln in enumerate(lines) if AI_CALL.search(ln) and not is_comment(ln, comment_kind)]
    if not calls:
        return []
    out = []
    for i, ln in enumerate(lines):
        if is_comment(ln, comment_kind) or not any(abs(i - c) <= WINDOW for c in calls):
            continue
        whole = WHOLE_RECORD.search(ln)
        ref = _line_sev(ln)
        if ref and PROMPT_LINE.search(ln):
            sev = ref
        elif whole:
            sev = "medium"
        else:
            continue
        # skip lines that are clearly reading the model's answer, or a DB query for the record
        if re.search(r"\.(?:from|select|eq|insert|update|upsert)\s*\(|choices\s*\[|\.output_text|"
                     r"\.text\s*\(\s*\)", ln):
            continue
        out.append(finding("PL-037", sev, "Personal data sent to an AI model API", rel, i + 1, ln.strip(), AI_FIX))
    return out


def check_pii_flows(repo):
    out = []
    for rel in repo.rels():
        f = repo.files[rel]
        if is_test(rel) or "/node_modules/" in "/" + rel:
            continue
        if f.ext in JS_EXT:
            kind = "code"
        elif f.ext in PY_EXT:
            kind = "hash"
        else:
            continue
        out.extend(_header_hits(f, rel, kind))
        out.extend(_ai_hits(f, rel, kind))
    return out
