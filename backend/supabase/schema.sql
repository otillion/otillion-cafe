-- Otillion multi-tenant backend for Supabase (Postgres + Auth + RLS).
-- Run once in the Supabase SQL editor. Safe to re-run (idempotent where possible).
--
-- Model
--   * Platform admin (the owner of the SaaS) signs in with email + password (Supabase Auth).
--   * Staff accounts are created ONLY by the platform admin through admin_create_account().
--     They sign in with username + password (internally username@staff.otillion.invalid).
--   * Every staff account belongs to exactly one tenant (café) with a server-held role.
--   * Tenant operational data is one JSON document per tenant (tenant_data), readable and
--     writable only by active members of that tenant (and the platform admin).
--   * The manager PIN lives only on the server (bcrypt). Sensitive changes (roles, branches,
--     deactivation) require a recent successful PIN check (step-up, 2 minutes).
--   * Public sign-up MUST be disabled in Auth settings.

create extension if not exists pgcrypto with schema extensions;

-- ---------- tables ----------
create table if not exists public.tenants (
  id text primary key check (id ~ '^[a-z0-9]{2,40}$'),
  name text not null check (char_length(name) between 1 and 60),
  suspended boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.tenant_data (
  tenant_id text primary key references public.tenants(id) on delete cascade,
  data jsonb not null check (pg_column_size(data) < 8000000),
  version bigint not null default 1,
  updated_at timestamptz not null default now(),
  updated_by uuid
);

create table if not exists public.admin_pins (
  tenant_id text primary key references public.tenants(id) on delete cascade,
  pin_hash text not null,
  failed int not null default 0,
  locked_until timestamptz
);

create table if not exists public.platform_admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists public.members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  tenant_id text not null references public.tenants(id) on delete cascade,
  username text not null unique check (username ~ '^[a-z0-9._-]{3,24}$'),
  display_name text not null check (char_length(display_name) between 1 and 40),
  role text not null check (role in ('owner','manager','accountant','cashier','kitchen')),
  branch_id text,
  staff_id text,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  last_login timestamptz
);
create index if not exists members_tenant_idx on public.members(tenant_id);

create table if not exists public.step_ups (
  tenant_id text not null,
  user_id uuid not null,
  valid_until timestamptz not null,
  primary key (tenant_id, user_id)
);

create table if not exists public.audit (
  id bigserial primary key,
  tenant_id text,
  user_id uuid,
  action text not null,
  detail jsonb,
  at timestamptz not null default now()
);

alter table public.tenants enable row level security;
alter table public.tenant_data enable row level security;
alter table public.admin_pins enable row level security;
alter table public.platform_admins enable row level security;
alter table public.members enable row level security;
alter table public.step_ups enable row level security;
alter table public.audit enable row level security;

-- ---------- helpers ----------
create or replace function public.is_platform_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.platform_admins where user_id = auth.uid())
$$;

create or replace function public.is_member(t text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.members m join public.tenants x on x.id = m.tenant_id
    where m.user_id = auth.uid() and m.tenant_id = t and m.active and not x.suspended)
$$;

create or replace function public.member_role(t text) returns text
language sql stable security definer set search_path = public as $$
  select m.role from public.members m join public.tenants x on x.id = m.tenant_id
  where m.user_id = auth.uid() and m.tenant_id = t and m.active and not x.suspended
$$;

create or replace function public.has_step_up(t text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.step_ups s
    where s.tenant_id = t and s.user_id = auth.uid() and s.valid_until > now())
$$;

create or replace function public.log_audit(t text, a text, d jsonb) returns void
language sql security definer set search_path = public as $$
  insert into public.audit(tenant_id, user_id, action, detail) values (t, auth.uid(), a, d)
$$;

create or replace function public.weak_pin(p text) returns boolean
language sql immutable as $$
  select p ~ '^(\d)\1+$' or position(p in '0123456789') > 0 or position(p in '9876543210') > 0
$$;

-- ---------- row level security ----------
drop policy if exists tenants_read on public.tenants;
create policy tenants_read on public.tenants for select to authenticated
  using (public.is_platform_admin() or public.is_member(id));

drop policy if exists data_read on public.tenant_data;
create policy data_read on public.tenant_data for select to authenticated
  using (public.is_platform_admin() or public.is_member(tenant_id));

drop policy if exists data_write on public.tenant_data;
create policy data_write on public.tenant_data for update to authenticated
  using (public.is_platform_admin() or public.is_member(tenant_id))
  with check (public.is_platform_admin() or public.is_member(tenant_id));

drop policy if exists members_read on public.members;
create policy members_read on public.members for select to authenticated
  using (user_id = auth.uid() or public.is_platform_admin());

-- no policies on admin_pins, platform_admins, step_ups, audit: API access is impossible.

create or replace function public.tenant_data_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.tenant_id := old.tenant_id;
  new.version := old.version + 1;
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;
drop trigger if exists tenant_data_guard on public.tenant_data;
create trigger tenant_data_guard before update on public.tenant_data
  for each row execute function public.tenant_data_guard();

-- ---------- identity ----------
-- Returns who the caller is. The very first authenticated user with no membership becomes the
-- platform admin ONLY while no platform admin exists (sign-up must be disabled).
create or replace function public.me() returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.members%rowtype; t public.tenants%rowtype;
begin
  if auth.uid() is null then return null; end if;
  select * into m from public.members where user_id = auth.uid();
  if found then
    select * into t from public.tenants where id = m.tenant_id;
    if not m.active or t.suspended then return jsonb_build_object('blocked', true); end if;
    update public.members set last_login = now() where user_id = m.user_id;
    return jsonb_build_object('admin', false,
      'member', jsonb_build_object('user_id', m.user_id, 'tenant_id', m.tenant_id, 'username', m.username,
        'display_name', m.display_name, 'role', m.role, 'branch_id', m.branch_id, 'staff_id', m.staff_id),
      'tenant', jsonb_build_object('id', t.id, 'name', t.name));
  end if;
  if not exists (select 1 from public.platform_admins) then
    insert into public.platform_admins(user_id) values (auth.uid());
    perform public.log_audit(null, 'admin_bootstrap', '{}');
  end if;
  if public.is_platform_admin() then return jsonb_build_object('admin', true); end if;
  return jsonb_build_object('none', true);
end $$;

-- ---------- platform admin operations ----------
create or replace function public.admin_list() returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  return jsonb_build_object(
    'tenants', coalesce((select jsonb_agg(jsonb_build_object('id', id, 'name', name, 'suspended', suspended) order by created_at) from public.tenants), '[]'),
    'members', coalesce((select jsonb_agg(jsonb_build_object('user_id', user_id, 'tenant_id', tenant_id, 'username', username,
        'display_name', display_name, 'role', role, 'branch_id', branch_id, 'staff_id', staff_id, 'active', active,
        'last_login', last_login) order by created_at) from public.members), '[]'));
end $$;

create or replace function public.admin_create_cafe(p_id text, p_name text, p_pin text, p_data jsonb) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  if p_pin !~ '^\d{4,8}$' or public.weak_pin(p_pin) then raise exception 'weak pin'; end if;
  insert into public.tenants(id, name) values (p_id, left(p_name, 60));
  insert into public.tenant_data(tenant_id, data) values (p_id, p_data);
  insert into public.admin_pins(tenant_id, pin_hash) values (p_id, crypt(p_pin, gen_salt('bf')));
  perform public.log_audit(p_id, 'cafe_created', jsonb_build_object('name', p_name));
end $$;

create or replace function public.admin_create_account(p_tenant text, p_username text, p_password text,
  p_name text, p_role text, p_branch text, p_staff text) returns uuid
language plpgsql security definer set search_path = public, extensions, auth as $$
declare uid uuid := gen_random_uuid(); em text;
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  if not exists (select 1 from public.tenants where id = p_tenant) then raise exception 'no tenant'; end if;
  if p_username !~ '^[a-z0-9._-]{3,24}$' then raise exception 'bad username'; end if;
  if exists (select 1 from public.members where username = p_username) then raise exception 'username taken'; end if;
  if char_length(p_password) < 8 or char_length(p_password) > 64 or lower(p_password) = p_username then raise exception 'bad password'; end if;
  if p_role not in ('owner','manager','accountant','cashier','kitchen') then raise exception 'bad role'; end if;
  em := p_username || '@staff.otillion.invalid';
  insert into auth.users(instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
      raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change, email_change_token_new)
    values ('00000000-0000-0000-0000-000000000000', uid, 'authenticated', 'authenticated', em,
      crypt(p_password, gen_salt('bf')), now(),
      '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');
  insert into auth.identities(id, user_id, identity_data, provider, provider_id, last_sign_in_at, created_at, updated_at)
    values (gen_random_uuid(), uid, jsonb_build_object('sub', uid::text, 'email', em, 'email_verified', true),
      'email', uid::text, now(), now(), now());
  insert into public.members(user_id, tenant_id, username, display_name, role, branch_id, staff_id)
    values (uid, p_tenant, p_username, left(p_name, 40), p_role, p_branch, p_staff);
  perform public.log_audit(p_tenant, 'account_created', jsonb_build_object('username', p_username, 'role', p_role));
  return uid;
end $$;

create or replace function public.admin_reset_password(p_user uuid, p_password text) returns void
language plpgsql security definer set search_path = public, extensions, auth as $$
declare un text;
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  select username into un from public.members where user_id = p_user;
  if un is null then raise exception 'no account'; end if;
  if char_length(p_password) < 8 or char_length(p_password) > 64 or lower(p_password) = un then raise exception 'bad password'; end if;
  update auth.users set encrypted_password = crypt(p_password, gen_salt('bf')), updated_at = now() where id = p_user;
  delete from auth.sessions where user_id = p_user;
  perform public.log_audit(null, 'password_reset', jsonb_build_object('username', un));
end $$;

create or replace function public.admin_set_member_active(p_user uuid, p_active boolean) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  update public.members set active = p_active where user_id = p_user;
  update auth.users set banned_until = case when p_active then null else 'infinity'::timestamptz end where id = p_user;
  if not p_active then delete from auth.sessions where user_id = p_user; end if;
  perform public.log_audit(null, 'account_active', jsonb_build_object('user', p_user, 'active', p_active));
end $$;

create or replace function public.admin_delete_account(p_user uuid) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  if not exists (select 1 from public.members where user_id = p_user) then raise exception 'no account'; end if;
  delete from auth.users where id = p_user;
  perform public.log_audit(null, 'account_deleted', jsonb_build_object('user', p_user));
end $$;

create or replace function public.admin_set_tenant_suspended(p_tenant text, p_suspended boolean) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  update public.tenants set suspended = p_suspended where id = p_tenant;
  if p_suspended then
    delete from auth.sessions where user_id in (select user_id from public.members where tenant_id = p_tenant);
  end if;
  perform public.log_audit(p_tenant, 'cafe_suspended', jsonb_build_object('suspended', p_suspended));
end $$;

create or replace function public.admin_delete_tenant(p_tenant text) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  if not exists (select 1 from public.tenants where id = p_tenant) then raise exception 'no tenant'; end if;
  -- remove every staff login of this cafe (members/tenant_data/admin_pins cascade from tenants)
  delete from auth.users where id in (select user_id from public.members where tenant_id = p_tenant);
  delete from public.step_ups where tenant_id = p_tenant;
  delete from public.tenants where id = p_tenant;
  perform public.log_audit(p_tenant, 'cafe_deleted', '{}');
end $$;

create or replace function public.admin_reset_pin(p_tenant text, p_pin text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  if p_pin !~ '^\d{4,8}$' or public.weak_pin(p_pin) then raise exception 'weak pin'; end if;
  update public.admin_pins set pin_hash = crypt(p_pin, gen_salt('bf')), failed = 0, locked_until = null where tenant_id = p_tenant;
  delete from public.step_ups where tenant_id = p_tenant;
  perform public.log_audit(p_tenant, 'pin_reset_by_admin', '{}');
end $$;

-- ---------- manager PIN (server side) ----------
-- Any active member of the tenant (or the platform admin) can submit a PIN: a manager standing at a
-- cashier's screen authorises a sensitive step. Five wrong tries lock the tenant PIN for 60 seconds.
create or replace function public.verify_admin_pin(p_tenant text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare p public.admin_pins%rowtype;
begin
  if not (public.is_member(p_tenant) or public.is_platform_admin()) then raise exception 'denied'; end if;
  select * into p from public.admin_pins where tenant_id = p_tenant for update;
  if not found then raise exception 'no pin'; end if;
  if p.locked_until is not null and p.locked_until > now() then
    return jsonb_build_object('ok', false, 'wait', ceil(extract(epoch from (p.locked_until - now())))::int);
  end if;
  if p.pin_hash = crypt(coalesce(p_pin, ''), p.pin_hash) then
    update public.admin_pins set failed = 0, locked_until = null where tenant_id = p_tenant;
    insert into public.step_ups(tenant_id, user_id, valid_until) values (p_tenant, auth.uid(), now() + interval '2 minutes')
      on conflict (tenant_id, user_id) do update set valid_until = excluded.valid_until;
    return jsonb_build_object('ok', true);
  end if;
  if p.failed + 1 >= 5 then
    update public.admin_pins set failed = 0, locked_until = now() + interval '60 seconds' where tenant_id = p_tenant;
    perform public.log_audit(p_tenant, 'pin_lockout', '{}');
    return jsonb_build_object('ok', false, 'wait', 60);
  end if;
  update public.admin_pins set failed = failed + 1 where tenant_id = p_tenant;
  perform public.log_audit(p_tenant, 'pin_fail', '{}');
  return jsonb_build_object('ok', false, 'left', 5 - (p.failed + 1));
end $$;

create or replace function public.change_admin_pin(p_tenant text, p_current text, p_new text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v jsonb;
begin
  if coalesce(public.member_role(p_tenant), '') not in ('owner','manager') and not public.is_platform_admin() then
    raise exception 'denied'; end if;
  if p_new !~ '^\d{4,8}$' or public.weak_pin(p_new) then raise exception 'weak pin'; end if;
  v := public.verify_admin_pin(p_tenant, p_current);
  if not (v->>'ok')::boolean then return v; end if;
  update public.admin_pins set pin_hash = crypt(p_new, gen_salt('bf')) where tenant_id = p_tenant;
  delete from public.step_ups where tenant_id = p_tenant;
  perform public.log_audit(p_tenant, 'pin_changed', '{}');
  return jsonb_build_object('ok', true);
end $$;

-- ---------- step-up protected staff changes (manager/owner only, PIN verified in the last 2 min) ----------
create or replace function public.set_staff_role(p_tenant text, p_staff text, p_role text) returns void
language plpgsql security definer set search_path = public as $$
declare tr text;
begin
  if coalesce(public.member_role(p_tenant), '') not in ('owner','manager') and not public.is_platform_admin() then raise exception 'denied'; end if;
  if not public.has_step_up(p_tenant) then raise exception 'pin required'; end if;
  if p_role not in ('manager','accountant','cashier','kitchen') then raise exception 'bad role'; end if;
  select role into tr from public.members where tenant_id = p_tenant and staff_id = p_staff;
  if tr is null or tr = 'owner' then raise exception 'denied'; end if;
  update public.members set role = p_role where tenant_id = p_tenant and staff_id = p_staff;
  perform public.log_audit(p_tenant, 'role_change', jsonb_build_object('staff', p_staff, 'role', p_role));
end $$;

create or replace function public.set_staff_branch(p_tenant text, p_staff text, p_branch text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if coalesce(public.member_role(p_tenant), '') not in ('owner','manager') and not public.is_platform_admin() then raise exception 'denied'; end if;
  if not public.has_step_up(p_tenant) then raise exception 'pin required'; end if;
  update public.members set branch_id = left(p_branch, 20) where tenant_id = p_tenant and staff_id = p_staff and role <> 'owner';
end $$;

create or replace function public.set_staff_active(p_tenant text, p_staff text, p_active boolean) returns void
language plpgsql security definer set search_path = public, auth as $$
declare uid uuid;
begin
  if coalesce(public.member_role(p_tenant), '') not in ('owner','manager') and not public.is_platform_admin() then raise exception 'denied'; end if;
  if not public.has_step_up(p_tenant) then raise exception 'pin required'; end if;
  select user_id into uid from public.members where tenant_id = p_tenant and staff_id = p_staff and role <> 'owner';
  if uid is null then return; end if;
  update public.members set active = p_active where user_id = uid;
  update auth.users set banned_until = case when p_active then null else 'infinity'::timestamptz end where id = uid;
  if not p_active then delete from auth.sessions where user_id = uid; end if;
  perform public.log_audit(p_tenant, 'staff_active', jsonb_build_object('staff', p_staff, 'active', p_active));
end $$;

-- ---------- privileges ----------
revoke all on all tables in schema public from anon, authenticated;
revoke execute on all functions in schema public from public, anon;
grant select on public.tenants, public.members to authenticated;
grant select on public.tenant_data to authenticated;
grant update (data) on public.tenant_data to authenticated;
grant execute on all functions in schema public to authenticated;
-- these must not be called directly from the API
revoke execute on function public.log_audit(text, text, jsonb), public.tenant_data_guard() from authenticated;
