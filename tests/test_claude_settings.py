"""PL-009 for Claude Code settings files. Fixtures are written at run time so no key-shaped string is committed."""
import json
import os
import random
import string
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
os.environ["PATCHLABS_OFFLINE"] = "1"

from patchlabs_cli.codescan import scan  # noqa: E402

RND = random.Random(7)


def tok(n, chars=string.ascii_letters + string.digits):
    return "".join(RND.choice(chars) for _ in range(n))


def make(tmp, settings, package=None, npmignore=None, git=False, name="settings.local.json"):
    os.makedirs(os.path.join(tmp, ".claude"), exist_ok=True)
    with open(os.path.join(tmp, ".claude", name), "w") as fh:
        json.dump(settings, fh, indent=2)
    if package is not None:
        with open(os.path.join(tmp, "package.json"), "w") as fh:
            json.dump(package, fh)
    if npmignore is not None:
        with open(os.path.join(tmp, ".npmignore"), "w") as fh:
            fh.write(npmignore)
    if git:
        subprocess.run(["git", "init", "-q", tmp], check=True)
        subprocess.run(["git", "-C", tmp, "add", "-f", "."], check=True)
    return [(f["severity"], f["title"]) for f in scan(tmp, offline=True)["findings"] if f["id"] == "PL-009"]


def allow(*rules):
    return {"permissions": {"allow": list(rules)}}


class TestClaudeSettings(unittest.TestCase):
    def test_bearer_token_in_allow_rule(self):
        with tempfile.TemporaryDirectory() as t:
            got = make(t, allow('Bash(curl -H "Authorization: Bearer ' + tok(40) + '" https://api.example.com)'))
            self.assertEqual(got, [("high", "Secret saved in a Claude Code settings file")])

    def test_github_token_tracked_by_git_is_critical(self):
        with tempfile.TemporaryDirectory() as t:
            got = make(t, allow("Bash(git push https://x:ghp_" + tok(36) + "@github.com/a/b.git)"), git=True)
            self.assertEqual(got, [("critical", "Secret saved in a Claude Code settings file that git tracks")])

    def test_password_env_and_flag(self):
        with tempfile.TemporaryDirectory() as t:
            got = make(t, {"permissions": {"allow": ["Bash(PGPASSWORD=" + tok(14) + " psql -h db -U app)"]},
                           "env": {"STRIPE_SECRET_KEY": "sk_live_" + tok(30)}})
            self.assertEqual(len(got), 2)
            lines = sorted(f["line_no"] for f in scan(t, offline=True)["findings"] if f["id"] == "PL-009")
            self.assertEqual(lines, [4, 8])

    def test_evidence_is_masked(self):
        with tempfile.TemporaryDirectory() as t:
            secret = tok(40)
            make(t, allow('Bash(curl -H "Authorization: Bearer ' + secret + '" https://x.io)'))
            f = [f for f in scan(t, offline=True)["findings"] if f["id"] == "PL-009"][0]
            self.assertNotIn(secret, f["evidence"])
            self.assertNotIn(secret[:-4], json.dumps(f))

    def test_near_misses_are_clean(self):
        with tempfile.TemporaryDirectory() as t:
            got = make(t, {"permissions": {"allow": [
                "Bash(npm run test *)", "Bash(mkdir -p src/components)", 'Bash(curl -H "Authorization: Bearer $TOKEN" *)',
                "Bash(PGPASSWORD=$DB_PASSWORD psql *)", "Bash(git push origin main)", "Read(./src/**)",
                "Bash(export API_KEY=your_api_key_here)"]},
                "env": {"API_TOKEN": "${API_TOKEN}", "MAX_TOKENS": "4096", "DEBUG": "true"}})
            self.assertEqual(got, [])

    def test_shared_settings_file_checked_too(self):
        with tempfile.TemporaryDirectory() as t:
            got = make(t, allow("Bash(npx vercel --token " + tok(24) + ")"), name="settings.json")
            self.assertEqual([s for s, _ in got], ["high"])

    def test_committed_local_file_without_secret_is_low(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(make(t, allow("Bash(npm test)"), git=True),
                             [("low", "Claude Code local settings file is committed to git")])

    def test_npm_publish_would_ship_it(self):
        with tempfile.TemporaryDirectory() as t:
            got = make(t, allow("Bash(npm test)"), package={"name": "pkg", "version": "1.0.0"})
            self.assertEqual(got, [("medium", "npm publish would ship the Claude Code local settings file")])

    def test_npm_files_list_private_or_npmignore_is_clean(self):
        for kw in ({"package": {"name": "p", "files": ["dist"]}}, {"package": {"name": "p", "private": True}},
                   {"package": {"name": "p"}, "npmignore": ".claude/\n"}):
            with tempfile.TemporaryDirectory() as t:
                self.assertEqual(make(t, allow("Bash(npm test)"), **kw), [], kw)


if __name__ == "__main__":
    unittest.main()
