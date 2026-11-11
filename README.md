# patchlabs-cli

A command line scanner for apps built with Lovable, Supabase, Bolt, Replit or Cursor. It reads your code, your
dependency list and your SQL files, and it can run one passive check on a live site. It is free and open source
under Apache-2.0.

It never connects to a database, never runs or rebuilds your migrations, and never runs or imports your code. It
sends no repository contents anywhere. The only network calls are the dependency lookup to OSV (package names and
versions only, skip it with `--offline`), and the requests to the site you give to `patchlabs headers`.

## What it checks

### Code, dependencies and SQL: `patchlabs scan`

| ID | Severity | What it looks for | Title shown |
|---|---|---|---|
| PL-010 | critical, high | Supabase service role keys, live Stripe or Supabase secret keys, and secrets behind a public env prefix (`VITE_`, `NEXT_PUBLIC_`, ...) in browser code or `.env` files | Service role key in client code |
| PL-017 | high, info | Edge functions with JWT checks off that use the service role key and check the caller nowhere | Edge function open without sign-in while using the service key |
| PL-018 | low | Email confirmation switched off in `supabase/config.toml` | Sign-ups need no email confirmation |
| PL-019 | critical, high | Access decided from `user_metadata`, which users can change themselves | Access decided by user_metadata, which users can edit |
| PL-020 | high | Admin email lists, or admin flags in browser code or browser storage | Admin check only in the browser |
| PL-021 | high | Stripe, Lemon Squeezy or Paddle webhook that reads the body and does not check the signature | Payment webhook doesn't verify its signature |
| PL-022 | high | Server code that uses the service role key and takes the user id from the request | Server route trusts a user id sent in the request |
| PL-023 | critical to medium | npm dependency with a known advisory, from OSV | Dependency with a known vulnerability |
| PL-024 | medium | HTML inserted from a value that is not a literal (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`) without sanitising | User content rendered as raw HTML |
| PL-025 | critical, high, info | Firebase or Realtime Database rules that allow anyone, or any signed-in user, to read or write | Firebase rules allow anyone to read and write |
| PL-026 | medium, info | Server code that allows any origin through CORS and also uses cookies or credentials | Any website can call a signed-in function (CORS reflects any origin) |
| PL-001 | critical | A policy that lets the public or `anon` role read personal columns | Anyone with the public key can read personal data |
| PL-002 | high, medium | A policy that lets any signed-in user read every row | Any signed-in user can read all rows |
| PL-003 | low | Row level security on, with no policies | Row level security is on but the table has no policies |
| PL-004 | medium | An UPDATE policy with no `WITH CHECK` | UPDATE policy without WITH CHECK |
| PL-005 | high, medium, low | A policy whose condition is always true | Policy is always true |
| PL-006 | high, medium | A `SECURITY DEFINER` function with no fixed `search_path`, or callable by `anon` | SECURITY DEFINER function exposure |
| PL-007 | medium | A public storage bucket | Public storage bucket |
| PL-008 | critical, high | Row level security not enabled on a public table | Row level security is not enabled |

The SQL checks (PL-001 to PL-008) read the text of the Supabase `*.sql` files in the repository (see Limits), except dependency and build
folders such as `node_modules` and `dist`. They do not run the SQL and do not test anything.
Migrations are read in order, one project folder at a time.

### Live site: `patchlabs headers`

| ID | Severity | What it looks for | Title shown |
|---|---|---|---|
| PL-027 | medium | `http://` does not redirect to `https://` | Site doesn't force HTTPS |
| PL-028 | high, medium | Certificate invalid or expired (high), or expiring within 21 days (medium) | TLS certificate is invalid, expired or about to expire |
| PL-029 | low | No `Strict-Transport-Security`, or max-age under 180 days | No HSTS header, or max-age under 180 days |
| PL-030 | medium | No `Content-Security-Policy` | No Content-Security-Policy |
| PL-031 | low | No `frame-ancestors` in the policy and no `X-Frame-Options` | Any site can frame the page |
| PL-032 | low | No `X-Content-Type-Options: nosniff` | No X-Content-Type-Options: nosniff |
| PL-033 | medium | A cookie without `Secure`, or a session cookie without `HttpOnly` | Cookie set without Secure, or a session cookie without HttpOnly |
| PL-034 | medium | A script or stylesheet loaded over plain `http://` | Page loads scripts or styles over plain HTTP |
| PL-035 | info | Version numbers in `Server` or `X-Powered-By` | Server headers reveal software versions |
| PL-036 | info | No `Referrer-Policy` | No Referrer-Policy |

The grade is A (90 or more), B (75 or more), C (60 or more), D (40 or more) or F. Each failed check takes 30 points
for high, 15 for medium and 5 for low. An invalid or expired certificate is always F.

`patchlabs headers` makes one plain `http://` GET of the home page, to see whether it redirects to HTTPS. It then
makes one `https://` GET of the home page, and follows redirects on that request, up to five hops. It does not
crawl, and it does not request any other path. A host that resolves to a private or local address is refused.

## Install

Needs Python 3.9 or newer. There are no other dependencies.

```sh
pipx install git+https://github.com/manra399/patchlabs-cli
```

Or run it without installing:

```sh
uvx --from git+https://github.com/manra399/patchlabs-cli patchlabs scan .
```

It also runs as a module: `python3 -m patchlabs_cli scan .`

## Usage

```sh
patchlabs scan                        # the current folder
patchlabs scan ./my-app --offline     # skip the OSV dependency lookup
patchlabs scan . --json               # JSON on stdout
patchlabs scan . --sarif out.sarif    # also write SARIF 2.1.0
patchlabs scan . --fail-on critical   # exit 1 only for critical findings
patchlabs headers https://app.example.com
```

`--fail-on` takes `critical`, `high` (the default), `medium`, `low` or `none`. Exit 1 means a finding at or above
that level exists.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No finding at or above `--fail-on` |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Usage error: a bad flag, a folder that does not exist, a bad address, or a SARIF file that cannot be written |
| 3 | `headers` could not load the site |

## Output

The table shows each finding's id, severity, title and location (file and line, or the page address). Below the
table, each id links to its page on patchlabs.dev, for example `https://patchlabs.dev/findings/pl-019`. Colour is used
only on a terminal. It is switched off when `NO_COLOR` is set to a non-empty value.

The table prints no evidence. The JSON output and the SARIF messages do include a short line of evidence, and
keys, tokens and email addresses in it are masked. Masking is best effort, so check the output before you share it.

## CI: GitHub code scanning

This workflow runs the scan on every push and pull request, and uploads the SARIF file so the findings appear in the
repository's Security tab.

```yaml
name: patchlabs

on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install git+https://github.com/manra399/patchlabs-cli
      - run: patchlabs scan . --sarif patchlabs.sarif --fail-on high
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: patchlabs.sarif
```

## What it does not do

- It does not test access. It reads code and SQL text. It cannot show who can read what in a running database.
- The RLS read only looks at Supabase SQL: files under a `supabase/` folder, or SQL that uses Supabase's `auth.uid()`,
  `anon` / `authenticated` roles or `storage.objects`. A plain Postgres schema for your own server is skipped.
- It does not rebuild your database, and it does not run a copy of your app.
- The hosted check at [patchlabs.dev](https://patchlabs.dev) rebuilds a copy of your database, tests who can read
  what, and re-tests a fix. Fix and Watch are also there. They are paid, and they are not in this tool.
- The dependency check covers npm only: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`,
  `bun.lock`, or exact versions in `package.json`.
- Checks work file by file, with one level of relative imports. Auth in a helper with an unusual name can be missed,
  and a check can flag code that is protected in a file it does not read.
- It is a static reader. It finds patterns. It does not prove a vulnerability and does not replace a review.

## Research

PatchLabs rebuilt 318 public Lovable and Supabase apps in November 2026. 106 of them let the wrong people read
personal data. The method is at [patchlabs.dev/research](https://patchlabs.dev/research).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
