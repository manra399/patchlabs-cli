create extension if not exists pgcrypto;
create table public.accounts (
  id uuid primary key,
  password_hash text not null
);
create function public.set_pw(p text) returns text language sql as $$ select crypt(p, gen_salt('bf')) $$;
