create table public.users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password text not null
);
