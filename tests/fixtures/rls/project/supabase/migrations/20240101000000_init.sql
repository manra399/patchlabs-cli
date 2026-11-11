-- Profiles: anyone holding the public key can read every row
create table public.profiles (
  id uuid primary key,
  email text not null,
  display_name text
);
alter table public.profiles enable row level security;
create policy "anyone can read profiles" on public.profiles for select to anon using (true);

create table public.notes (
  id uuid primary key,
  user_id uuid not null,
  body text
);
alter table public.notes enable row level security;
create policy "owner reads notes" on public.notes for select to authenticated using (auth.uid() = user_id);
create policy "owner writes notes" on public.notes for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);
