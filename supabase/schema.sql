-- Shared state for the Barber app (Supabase project "barber", ref miaaynxgowqyyivtdnhs).
-- The browser encrypts the state with a key derived from the site password; the server
-- only stores ciphertext. Writes require a token derived from the same password, whose
-- sha256 is stored in barber_secret (build.mjs prints the update statement).

create extension if not exists pgcrypto with schema extensions;

create table public.barber_state (
  id text primary key default 'main',
  data text not null,
  version integer not null default 1,
  updated_by text,
  updated_at timestamptz not null default now()
);

create table public.barber_secret (
  id text primary key default 'main',
  token_hash text not null
);

alter table public.barber_state enable row level security;
alter table public.barber_secret enable row level security;
revoke all on public.barber_state, public.barber_secret from anon, authenticated;

create or replace function public.barber_load()
returns json language sql security definer set search_path = '' as $$
  select json_build_object('data', s.data, 'version', s.version, 'updated_by', s.updated_by, 'updated_at', s.updated_at)
  from public.barber_state s where s.id = 'main';
$$;

create or replace function public.barber_save(p_token text, p_data text, p_version integer, p_by text)
returns json language plpgsql security definer set search_path = '' as $$
declare
  v_hash text;
  v_cur public.barber_state;
begin
  select token_hash into v_hash from public.barber_secret where id = 'main';
  if v_hash is null or encode(extensions.digest(p_token, 'sha256'), 'hex') <> v_hash then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if length(p_data) > 2000000 then raise exception 'too large'; end if;
  select * into v_cur from public.barber_state where id = 'main' for update;
  if v_cur.id is null then
    insert into public.barber_state (id, data, version, updated_by) values ('main', p_data, 1, left(p_by, 60));
    return json_build_object('ok', true, 'version', 1);
  end if;
  if p_version is distinct from v_cur.version then
    return json_build_object('ok', false, 'conflict', true, 'version', v_cur.version);
  end if;
  update public.barber_state set data = p_data, version = v_cur.version + 1, updated_by = left(p_by, 60), updated_at = now() where id = 'main';
  return json_build_object('ok', true, 'version', v_cur.version + 1);
end;
$$;

revoke all on function public.barber_load() from public;
revoke all on function public.barber_save(text, text, integer, text) from public;
grant execute on function public.barber_load() to anon, authenticated;
grant execute on function public.barber_save(text, text, integer, text) to anon, authenticated;
