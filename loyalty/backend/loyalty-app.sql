-- Otillion Loyalty — standalone loyalty-card product (separate from the café/POS system).
-- Run once in the Supabase SQL editor of the project that backs THIS app. Safe to re-run.
--
-- Model
--   * The platform admin (you) creates a business, picks its theme, logo, goal/reward and unit,
--     and creates login accounts for that business (username + password).
--   * Business staff (owner, cashier) look customers up, add points, redeem rewards.
--   * Customers are NOT Auth users: they join from the business public link, get a long random token
--     that opens their card, and can only read their own card.
--   * Tables have RLS on and no policies; all access is through the security-definer lp_* functions.
--   * Every staff function derives the business from the caller's own staff row, so one business can
--     never touch another's data.
--   * Public sign-up MUST be disabled in Auth settings.
--   * To make an admin: create the user in Auth (email + password), then run:
--       insert into public.lp_admins select id from auth.users where email = 'YOU@example.com';
--     If lp_admins is empty, the first user who signs in is made admin (fine in a fresh, private project).

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.lp_admins (user_id uuid primary key references auth.users(id) on delete cascade);

create table if not exists public.lp_businesses (
  id text primary key default substr(replace(gen_random_uuid()::text, '-', ''), 1, 12),
  name text not null check (char_length(name) between 1 and 60),
  kind text not null default 'coffee' check (kind in ('coffee','barber','bakery','beauty','restaurant','custom')),
  slug text not null unique check (slug ~ '^[a-z0-9-]{3,30}$'),
  enabled boolean not null default true,
  theme text not null default 'coffee' check (theme in ('coffee','barber','gold','rose','ocean','forest','mono','custom')),
  theme_custom jsonb check (theme_custom is null or (
    theme_custom ? 'bg' and theme_custom ? 'fg' and theme_custom ? 'accent' and theme_custom ? 'card'
    and theme_custom->>'bg' ~ '^#[0-9a-fA-F]{6}$' and theme_custom->>'fg' ~ '^#[0-9a-fA-F]{6}$'
    and theme_custom->>'accent' ~ '^#[0-9a-fA-F]{6}$' and theme_custom->>'card' ~ '^#[0-9a-fA-F]{6}$')),
  logo text check (logo is null or (char_length(logo) <= 140000 and logo ~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$')),
  goal int not null default 6 check (goal between 2 and 30),
  reward text not null default 'Free coffee' check (char_length(reward) between 1 and 60),
  unit text not null default '' check (char_length(unit) <= 20),
  earn text not null default 'visit' check (earn in ('visit','amount')),
  per_amount numeric not null default 100 check (per_amount > 0 and per_amount <= 100000),
  suspended boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.lp_staff (
  user_id uuid primary key references auth.users(id) on delete cascade,
  business_id text not null references public.lp_businesses(id) on delete cascade,
  username text not null unique,
  display_name text not null default '',
  role text not null default 'cashier' check (role in ('owner','cashier')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.lp_customers (
  id uuid primary key default gen_random_uuid(),
  business_id text not null references public.lp_businesses(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 40),
  phone text not null check (phone ~ '^[0-9]{7,15}$'),
  token text not null unique default replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''),
  points int not null default 0 check (points >= 0),
  rewards_ready int not null default 0 check (rewards_ready >= 0),
  total_earned int not null default 0,
  redeemed int not null default 0,
  visits int not null default 0,
  created_at timestamptz not null default now(),
  last_visit timestamptz
);
create unique index if not exists lp_customers_phone_idx on public.lp_customers(business_id, right(phone, 10));
create index if not exists lp_customers_biz_idx on public.lp_customers(business_id, last_visit desc nulls last);

create table if not exists public.lp_events (
  id bigserial primary key,
  business_id text not null references public.lp_businesses(id) on delete cascade,
  customer_id uuid references public.lp_customers(id) on delete cascade,
  kind text not null check (kind in ('join','earn','redeem')),
  delta int not null default 0,
  amount numeric,
  staff uuid,
  at timestamptz not null default now()
);
create index if not exists lp_events_biz_idx on public.lp_events(business_id, at desc);

alter table public.lp_admins enable row level security;
alter table public.lp_businesses enable row level security;
alter table public.lp_staff enable row level security;
alter table public.lp_customers enable row level security;
alter table public.lp_events enable row level security;
revoke all on public.lp_admins, public.lp_businesses, public.lp_staff, public.lp_customers, public.lp_events from anon, authenticated;
revoke all on sequence public.lp_events_id_seq from anon, authenticated;

-- ---------- helpers ----------
create or replace function public.lp_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.lp_admins where user_id = auth.uid())
$$;

create or replace function public.lp_norm_phone(p text) returns text
language sql immutable as $$ select regexp_replace(coalesce(p, ''), '[^0-9]', '', 'g') $$;

-- the caller's own business (active staff of a non-suspended, enabled business), else raises
create or replace function public.lp_my_biz() returns public.lp_businesses
language plpgsql stable security definer set search_path = public as $$
declare b public.lp_businesses%rowtype;
begin
  select bz.* into b from public.lp_staff s join public.lp_businesses bz on bz.id = s.business_id
    where s.user_id = auth.uid() and s.active and not bz.suspended and bz.enabled;
  if not found then raise exception 'denied'; end if;
  return b;
end $$;

create or replace function public.lp_card_json(c public.lp_customers, b public.lp_businesses) returns jsonb
language sql immutable as $$
  select jsonb_build_object('id', c.id, 'name', c.name, 'phone', c.phone, 'points', c.points,
    'ready', c.rewards_ready, 'redeemed', c.redeemed, 'visits', c.visits, 'total', c.total_earned,
    'last_visit', c.last_visit, 'created_at', c.created_at, 'goal', b.goal, 'reward', b.reward, 'unit', b.unit)
$$;

create or replace function public.lp_biz_json(b public.lp_businesses) returns jsonb
language sql immutable as $$
  select jsonb_build_object('name', b.name, 'kind', b.kind, 'slug', b.slug, 'theme', b.theme, 'custom', b.theme_custom,
    'logo', b.logo, 'goal', b.goal, 'reward', b.reward, 'unit', b.unit, 'earn', b.earn, 'per_amount', b.per_amount)
$$;

-- ---------- who am I ----------
create or replace function public.lp_me() returns jsonb
language plpgsql security definer set search_path = public as $$
declare s public.lp_staff%rowtype; b public.lp_businesses%rowtype;
begin
  if auth.uid() is null then return null; end if;
  select * into s from public.lp_staff where user_id = auth.uid();
  if found then
    select * into b from public.lp_businesses where id = s.business_id;
    if not s.active or b.suspended or not b.enabled then return jsonb_build_object('blocked', true); end if;
    return jsonb_build_object('admin', false, 'staff', jsonb_build_object('username', s.username, 'name', s.display_name, 'role', s.role),
      'business', public.lp_biz_json(b));
  end if;
  if not exists (select 1 from public.lp_admins) then insert into public.lp_admins(user_id) values (auth.uid()); end if;
  if public.lp_is_admin() then return jsonb_build_object('admin', true); end if;
  return jsonb_build_object('none', true);
end $$;

-- ---------- platform admin ----------
create or replace function public.lp_admin_list() returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.lp_is_admin() then raise exception 'denied'; end if;
  return coalesce((select jsonb_agg(public.lp_biz_json(b) || jsonb_build_object('id', b.id, 'enabled', b.enabled, 'suspended', b.suspended,
      'customers', (select count(*) from public.lp_customers c where c.business_id = b.id),
      'staff', coalesce((select jsonb_agg(jsonb_build_object('user_id', s.user_id, 'username', s.username, 'name', s.display_name,
          'role', s.role, 'active', s.active) order by s.created_at) from public.lp_staff s where s.business_id = b.id), '[]'::jsonb))
    order by b.created_at) from public.lp_businesses b), '[]'::jsonb);
end $$;

-- p_id null creates. p_logo: null keeps, '' removes, else png/jpeg/webp data URL (<= 140 KB).
create or replace function public.lp_admin_save(p_id text, p_name text, p_kind text, p_slug text, p_enabled boolean,
  p_theme text, p_custom jsonb, p_logo text, p_goal int, p_reward text, p_unit text, p_earn text, p_per numeric) returns text
language plpgsql security definer set search_path = public as $$
declare cur public.lp_businesses%rowtype; sl text; lg text; bid text;
begin
  if not public.lp_is_admin() then raise exception 'denied'; end if;
  if p_id is not null then
    select * into cur from public.lp_businesses where id = p_id;
    if not found then raise exception 'no business'; end if;
  end if;
  sl := lower(trim(coalesce(p_slug, '')));
  if sl !~ '^[a-z0-9-]{3,30}$' then raise exception 'bad slug'; end if;
  if exists (select 1 from public.lp_businesses where slug = sl and id is distinct from p_id) then raise exception 'slug taken'; end if;
  if char_length(trim(coalesce(p_name, ''))) not between 1 and 60 then raise exception 'bad name'; end if;
  if p_goal is null or p_goal < 2 or p_goal > 30 then raise exception 'bad goal'; end if;
  if p_earn not in ('visit','amount') then raise exception 'bad earn'; end if;
  if p_per is null or p_per <= 0 or p_per > 100000 then raise exception 'bad amount'; end if;
  if char_length(trim(coalesce(p_reward, ''))) not between 1 and 60 then raise exception 'bad reward'; end if;
  if char_length(trim(coalesce(p_unit, ''))) > 20 then raise exception 'bad unit'; end if;
  if p_theme = 'custom' and p_custom is null then raise exception 'bad theme'; end if;
  if p_logo is null then lg := cur.logo;
  elsif p_logo = '' then lg := null;
  else
    if char_length(p_logo) > 140000 or p_logo !~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$' then raise exception 'bad logo'; end if;
    lg := p_logo;
  end if;
  if p_id is null then
    insert into public.lp_businesses(name, kind, slug, enabled, theme, theme_custom, logo, goal, reward, unit, earn, per_amount)
      values (trim(p_name), p_kind, sl, coalesce(p_enabled, true), p_theme, case when p_theme = 'custom' then p_custom end, lg,
              p_goal, trim(p_reward), trim(coalesce(p_unit, '')), p_earn, p_per) returning id into bid;
  else
    update public.lp_businesses set name = trim(p_name), kind = p_kind, slug = sl, enabled = coalesce(p_enabled, true), theme = p_theme,
      theme_custom = case when p_theme = 'custom' then p_custom end, logo = lg, goal = p_goal, reward = trim(p_reward),
      unit = trim(coalesce(p_unit, '')), earn = p_earn, per_amount = p_per where id = p_id;
    bid := p_id;
  end if;
  return bid;
end $$;

create or replace function public.lp_admin_set_suspended(p_id text, p_suspended boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.lp_is_admin() then raise exception 'denied'; end if;
  update public.lp_businesses set suspended = coalesce(p_suspended, false) where id = p_id;
end $$;

create or replace function public.lp_admin_delete_business(p_id text) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.lp_is_admin() then raise exception 'denied'; end if;
  delete from auth.users where id in (select user_id from public.lp_staff where business_id = p_id);
  delete from public.lp_businesses where id = p_id;
end $$;

create or replace function public.lp_admin_create_staff(p_business text, p_username text, p_password text, p_name text, p_role text) returns uuid
language plpgsql security definer set search_path = public, extensions, auth as $$
declare uid uuid := gen_random_uuid(); em text;
begin
  if not public.lp_is_admin() then raise exception 'denied'; end if;
  if not exists (select 1 from public.lp_businesses where id = p_business) then raise exception 'no business'; end if;
  if p_username !~ '^[a-z0-9._-]{3,24}$' then raise exception 'bad username'; end if;
  if exists (select 1 from public.lp_staff where username = p_username) then raise exception 'username taken'; end if;
  if char_length(p_password) < 8 or char_length(p_password) > 64 or lower(p_password) = p_username then raise exception 'bad password'; end if;
  if p_role not in ('owner','cashier') then raise exception 'bad role'; end if;
  em := p_username || '@loy.otillion.invalid';
  insert into auth.users(instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
      raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change, email_change_token_new)
    values ('00000000-0000-0000-0000-000000000000', uid, 'authenticated', 'authenticated', em,
      crypt(p_password, gen_salt('bf')), now(),
      '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');
  insert into auth.identities(id, user_id, identity_data, provider, provider_id, last_sign_in_at, created_at, updated_at)
    values (gen_random_uuid(), uid, jsonb_build_object('sub', uid::text, 'email', em, 'email_verified', true),
      'email', uid::text, now(), now(), now());
  insert into public.lp_staff(user_id, business_id, username, display_name, role) values (uid, p_business, p_username, left(coalesce(p_name, ''), 40), p_role);
  return uid;
end $$;

create or replace function public.lp_admin_reset_password(p_user uuid, p_password text) returns void
language plpgsql security definer set search_path = public, extensions, auth as $$
begin
  if not public.lp_is_admin() then raise exception 'denied'; end if;
  if not exists (select 1 from public.lp_staff where user_id = p_user) then raise exception 'no account'; end if;
  if char_length(p_password) < 8 or char_length(p_password) > 64 then raise exception 'bad password'; end if;
  update auth.users set encrypted_password = crypt(p_password, gen_salt('bf')), updated_at = now() where id = p_user;
end $$;

create or replace function public.lp_admin_set_staff_active(p_user uuid, p_active boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.lp_is_admin() then raise exception 'denied'; end if;
  update public.lp_staff set active = coalesce(p_active, true) where user_id = p_user;
end $$;

create or replace function public.lp_admin_delete_staff(p_user uuid) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.lp_is_admin() then raise exception 'denied'; end if;
  if not exists (select 1 from public.lp_staff where user_id = p_user) then raise exception 'no account'; end if;
  delete from auth.users where id = p_user;
end $$;

-- ---------- business staff (business comes from the caller, never from a parameter) ----------
create or replace function public.lp_staff_overview() returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare b public.lp_businesses%rowtype;
begin
  b := public.lp_my_biz();
  return public.lp_biz_json(b) || jsonb_build_object(
    'stats', jsonb_build_object(
      'customers', (select count(*) from public.lp_customers where business_id = b.id),
      'ready', (select coalesce(sum(rewards_ready), 0) from public.lp_customers where business_id = b.id),
      'redeemed', (select coalesce(sum(redeemed), 0) from public.lp_customers where business_id = b.id),
      'new7', (select count(*) from public.lp_customers where business_id = b.id and created_at > now() - interval '7 days'),
      'earn7', (select count(*) from public.lp_events where business_id = b.id and kind = 'earn' and at > now() - interval '7 days')),
    'recent', coalesce((select jsonb_agg(public.lp_card_json(c, b) order by c.last_visit desc nulls last, c.created_at desc)
      from (select * from public.lp_customers where business_id = b.id
            order by last_visit desc nulls last, created_at desc limit 20) c), '[]'::jsonb));
end $$;

create or replace function public.lp_staff_search(p_q text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare b public.lp_businesses%rowtype; q text := trim(coalesce(p_q, '')); d text := public.lp_norm_phone(p_q);
begin
  b := public.lp_my_biz();
  if char_length(q) < 2 then return '[]'::jsonb; end if;
  return coalesce((select jsonb_agg(public.lp_card_json(c, b) order by c.last_visit desc nulls last, c.name)
    from (select * from public.lp_customers
          where business_id = b.id
            and (lower(name) like '%' || replace(replace(lower(q), '%', ''), '_', '') || '%'
                 or (char_length(d) >= 3 and phone like '%' || d || '%'))
          order by last_visit desc nulls last, name limit 20) c), '[]'::jsonb);
end $$;

create or replace function public.lp_staff_add_customer(p_name text, p_phone text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare b public.lp_businesses%rowtype; c public.lp_customers%rowtype; ph text := public.lp_norm_phone(p_phone);
begin
  b := public.lp_my_biz();
  if char_length(trim(coalesce(p_name, ''))) not between 1 and 40 then raise exception 'bad name'; end if;
  if ph !~ '^[0-9]{7,15}$' then raise exception 'bad phone'; end if;
  select * into c from public.lp_customers where business_id = b.id and right(phone, 10) = right(ph, 10);
  if not found then
    insert into public.lp_customers(business_id, name, phone) values (b.id, trim(p_name), ph) returning * into c;
    insert into public.lp_events(business_id, customer_id, kind, staff) values (b.id, c.id, 'join', auth.uid());
  end if;
  return public.lp_card_json(c, b);
end $$;

create or replace function public.lp_staff_add(p_customer uuid, p_amount numeric) returns jsonb
language plpgsql security definer set search_path = public as $$
declare b public.lp_businesses%rowtype; c public.lp_customers%rowtype; n int; pts int; rw int;
begin
  b := public.lp_my_biz();
  select * into c from public.lp_customers where id = p_customer and business_id = b.id for update;
  if not found then raise exception 'no customer'; end if;
  if c.last_visit is not null and c.last_visit > now() - interval '10 seconds' then raise exception 'too fast'; end if;
  if b.earn = 'amount' then
    if p_amount is null or p_amount <= 0 or p_amount > 1000000 then raise exception 'bad amount'; end if;
    n := floor(p_amount / b.per_amount)::int;
  else
    n := 1;
  end if;
  if n < 1 then raise exception 'no points'; end if;
  pts := c.points + n; rw := c.rewards_ready;
  while pts >= b.goal loop pts := pts - b.goal; rw := rw + 1; end loop;
  update public.lp_customers set points = pts, rewards_ready = rw, total_earned = total_earned + n,
    visits = visits + 1, last_visit = now() where id = c.id returning * into c;
  insert into public.lp_events(business_id, customer_id, kind, delta, amount, staff)
    values (b.id, c.id, 'earn', n, case when b.earn = 'amount' then p_amount end, auth.uid());
  return public.lp_card_json(c, b);
end $$;

create or replace function public.lp_staff_redeem(p_customer uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare b public.lp_businesses%rowtype; c public.lp_customers%rowtype;
begin
  b := public.lp_my_biz();
  select * into c from public.lp_customers where id = p_customer and business_id = b.id for update;
  if not found then raise exception 'no customer'; end if;
  if c.rewards_ready < 1 then raise exception 'no reward'; end if;
  update public.lp_customers set rewards_ready = rewards_ready - 1, redeemed = redeemed + 1 where id = c.id returning * into c;
  insert into public.lp_events(business_id, customer_id, kind, delta, staff) values (b.id, c.id, 'redeem', -1, auth.uid());
  return public.lp_card_json(c, b);
end $$;

-- ---------- public (customers, no login) ----------
create or replace function public.lp_public_biz(p_slug text) returns jsonb
language sql stable security definer set search_path = public as $$
  select public.lp_biz_json(b) from public.lp_businesses b
  where b.slug = lower(coalesce(p_slug, '')) and b.enabled and not b.suspended
$$;

create or replace function public.lp_public_join(p_slug text, p_name text, p_phone text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare b public.lp_businesses%rowtype; c public.lp_customers%rowtype; ph text := public.lp_norm_phone(p_phone);
begin
  select * into b from public.lp_businesses where slug = lower(coalesce(p_slug, '')) and enabled and not suspended;
  if not found then raise exception 'no business'; end if;
  if char_length(trim(coalesce(p_name, ''))) not between 1 and 40 then raise exception 'bad name'; end if;
  if ph !~ '^[0-9]{7,15}$' then raise exception 'bad phone'; end if;
  if (select count(*) from public.lp_events where business_id = b.id and kind = 'join' and at > now() - interval '10 minutes') >= 30 then
    raise exception 'busy'; end if;
  if exists (select 1 from public.lp_customers where business_id = b.id and right(phone, 10) = right(ph, 10)) then
    raise exception 'already registered'; end if;
  insert into public.lp_customers(business_id, name, phone) values (b.id, trim(p_name), ph) returning * into c;
  insert into public.lp_events(business_id, customer_id, kind) values (b.id, c.id, 'join');
  return jsonb_build_object('token', c.token, 'card', public.lp_card_json(c, b));
end $$;

create or replace function public.lp_public_card(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare b public.lp_businesses%rowtype; c public.lp_customers%rowtype;
begin
  if p_token is null or p_token !~ '^[a-f0-9]{64}$' then return null; end if;
  select * into c from public.lp_customers where token = p_token;
  if not found then return null; end if;
  select * into b from public.lp_businesses where id = c.business_id and enabled and not suspended;
  if not found then return null; end if;
  return jsonb_build_object('card', public.lp_card_json(c, b), 'biz', public.lp_biz_json(b));
end $$;

-- ---------- privileges ----------
-- only touches this app's own lp_* functions (safe in a project shared with other apps)
do $$ declare r record; begin
  for r in select p.oid::regprocedure as f from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'public' and p.proname like 'lp\_%' loop
    execute format('revoke execute on function %s from public, anon, authenticated', r.f);
  end loop;
end $$;
grant execute on function public.lp_me(), public.lp_admin_list(),
  public.lp_admin_save(text, text, text, text, boolean, text, jsonb, text, int, text, text, text, numeric),
  public.lp_admin_set_suspended(text, boolean), public.lp_admin_delete_business(text),
  public.lp_admin_create_staff(text, text, text, text, text), public.lp_admin_reset_password(uuid, text),
  public.lp_admin_set_staff_active(uuid, boolean), public.lp_admin_delete_staff(uuid),
  public.lp_staff_overview(), public.lp_staff_search(text), public.lp_staff_add_customer(text, text),
  public.lp_staff_add(uuid, numeric), public.lp_staff_redeem(uuid)
  to authenticated;
grant execute on function public.lp_public_biz(text), public.lp_public_join(text, text, text), public.lp_public_card(text)
  to anon, authenticated;
