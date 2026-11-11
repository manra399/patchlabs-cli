create policy "admins read all" on public.orders for select
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

create function public.handle_new_user() returns trigger as $$
begin
  insert into public.profiles (id, role) values (new.id, new.raw_user_meta_data->>'role');
  return new;
end; $$ language plpgsql security definer;
