"""Static RLS read: SQL text in, findings out. Each case is an inline migration."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchlabs_cli import rls, sqlfiles  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.join(HERE, "fixtures", "rls", "project")

CASES = {
    "rls_enabled_no_policy": ("""
create table public.notes (id uuid primary key, body text, user_id uuid);
alter table public.notes enable row level security;
""", [("PL-003", "low")]),
    "rls_off_with_personal_data": ("""
create table public.profiles (id uuid primary key, email text, phone text);
""", [("PL-008", "critical")]),
    "anon_reads_personal_data_with_true": ("""
create table public.profiles (id uuid primary key, email text);
alter table public.profiles enable row level security;
create policy "anyone reads" on public.profiles for select to anon using (true);
""", [("PL-001", "critical")]),
    "using_true_for_all_to_public": ("""
create table public.notes (id uuid primary key, body text, user_id uuid);
alter table public.notes enable row level security;
create policy "open" on public.notes for all to public using (true) with check (true);
""", [("PL-005", "high")]),
    "update_policy_without_with_check": ("""
create table public.notes (id uuid primary key, body text, user_id uuid);
alter table public.notes enable row level security;
create policy "owner update" on public.notes for update to authenticated using (auth.uid() = user_id);
""", [("PL-004", "medium")]),
    "good_owner_policies": ("""
create table public.notes (id uuid primary key, body text, user_id uuid);
alter table public.notes enable row level security;
create policy "owner read" on public.notes for select to authenticated using (auth.uid() = user_id);
create policy "owner write" on public.notes for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);
""", []),
}


def analyse(sql, path="supabase/migrations/001_init.sql"):
    _, raw = rls.analyze([(path, sql)])
    return rls.to_findings(raw)


class TestRlsShapes(unittest.TestCase):
    def test_each_shape(self):
        for name, (sql, expected) in CASES.items():
            with self.subTest(name):
                got = [(f["id"], f["severity"]) for f in analyse(sql)]
                self.assertEqual(got, expected)

    def test_finding_shape_and_redaction(self):
        found = analyse(CASES["anon_reads_personal_data_with_true"][0])
        self.assertEqual(len(found), 1)
        f = found[0]
        self.assertEqual(f["file"], "supabase/migrations/001_init.sql")
        self.assertEqual(f["line_no"], 4)  # the CASES text starts with a blank line
        self.assertEqual(f["line"], "code")
        self.assertFalse(f["proven"])
        self.assertEqual(f["source"], "rls")
        self.assertIn("Personal columns: email", f["evidence"])
        self.assertLessEqual(len(f["evidence"]), 180)
        self.assertTrue(f["fix"])

    def test_quoted_text_does_not_hide_statements(self):
        sql = "create table public.t (id uuid, email text);\ncomment on table public.t is 'a -- not a comment; ok';\n" \
              "alter table public.t enable row level security;\n"
        self.assertEqual([f["id"] for f in analyse(sql)], ["PL-003"])

    def test_dropped_table_is_forgotten(self):
        sql = "create table public.t (id uuid, email text);\ndrop table public.t;\n"
        self.assertEqual(analyse(sql), [])

    def test_table_in_other_schema_is_ignored(self):
        self.assertEqual(analyse("create table auth.profiles (id uuid, email text);"), [])


class TestProjectGrouping(unittest.TestCase):
    def test_project_keys(self):
        self.assertEqual(sqlfiles.project_key("supabase/migrations/001.sql"), "")
        self.assertEqual(sqlfiles.project_key("apps/a/supabase/migrations/001.sql"), "apps/a")
        self.assertEqual(sqlfiles.project_key("db/schema.sql"), "db")
        self.assertEqual(sqlfiles.project_key("schema.sql"), "")

    def test_same_table_name_in_two_apps_is_analysed_separately(self):
        a = ("apps/a/supabase/migrations/001.sql", "create table public.profiles (id uuid, email text);\n"
             "alter table public.profiles enable row level security;\n")
        b = ("apps/b/supabase/migrations/001.sql", "create table public.profiles (id uuid, email text);\n")
        found = []
        for _, group in sqlfiles.group([a, b]).items():
            _, raw = rls.analyze(group)
            found.extend(rls.to_findings(raw))
        self.assertEqual(sorted((f["file"], f["id"]) for f in found),
                         [("apps/a/supabase/migrations/001.sql", "PL-003"), ("apps/b/supabase/migrations/001.sql", "PL-008")])


class TestSqlFileReader(unittest.TestCase):
    def test_project_fixture_reads_migrations(self):
        files, stats = sqlfiles.collect(PROJECT)
        self.assertEqual([p for p, _ in files], ["supabase/migrations/20240101000000_init.sql"])
        self.assertEqual(stats["sql_files"], 1)

    def test_migrations_come_first_and_build_folders_are_skipped(self):
        import shutil
        import tempfile
        d = tempfile.mkdtemp()
        try:
            for rel in ("schema.sql", "supabase/migrations/002.sql", "supabase/migrations/001.sql",
                        "node_modules/pkg/x.sql", "dist/y.sql"):
                os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
                with open(os.path.join(d, rel), "w") as fh:
                    fh.write("select 1;\n")
            files, _ = sqlfiles.collect(d)
            self.assertEqual([p for p, _ in files], ["supabase/migrations/001.sql", "supabase/migrations/002.sql",
                                                     "schema.sql"])
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()


class SupabaseOnlyTest(unittest.TestCase):
    def test_plain_postgres_schema_is_left_out(self):
        from patchlabs_cli import sqlfiles
        plain = "create table users (id uuid primary key, email text);"
        supa = "create table profiles (id uuid); create policy p on profiles for select to anon using (true);"
        groups = sqlfiles.group([("db/schema.sql", plain), ("app/db/init.sql", supa), ("supabase/migrations/1.sql", plain)])
        paths = [p for files in groups.values() for p, _ in files]
        self.assertEqual(sorted(paths), ["app/db/init.sql", "supabase/migrations/1.sql"])
