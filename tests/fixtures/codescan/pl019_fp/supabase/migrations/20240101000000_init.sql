create policy "admins read all" on public.orders for select
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
-- (auth.jwt() -> 'user_metadata') is unsafe, we do not use it
create function public.handle_new_user() returns trigger as $$
begin
  insert into public.profiles (id, full_name) values (new.id, new.raw_user_meta_data->>'full_name');
  return new;
end; $$ language plpgsql security definer;
