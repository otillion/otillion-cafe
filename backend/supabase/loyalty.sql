-- Otillion Loyalty module (stamp / points cards for each café's own customers).
-- Run AFTER backend/supabase/schema.sql, in the Supabase SQL editor. Safe to re-run.
--
-- Model
--   * The platform admin turns loyalty on per café and sets: goal (e.g. 6 points = 1 free), reward text,
--     logo, brand colour, public slug, and how points are earned (per visit or per amount spent).
--   * Café staff (owner, manager, cashier) look customers up and add points / redeem rewards.
--   * Customers are NOT Supabase Auth users. They join from the café's public link, get a long random
--     token that opens their card (kept on their phone), and can only ever read their own card.
--   * All tables have RLS on and no policies: every access goes through the security-definer functions below.
--   * Tenant isolation: each function checks membership of the tenant in the call, and customer rows
--     always carry tenant_id.

-- ---------- tables ----------
create table if not exists public.loyalty_settings (
  tenant_id text primary key references public.tenants(id) on delete cascade,
  enabled boolean not null default true,
  slug text not null unique check (slug ~ '^[a-z0-9-]{3,30}$'),
  brand_name text not null default '' check (char_length(brand_name) <= 40),
  color text not null default '#000000' check (color ~ '^#[0-9a-fA-F]{6}$'),
  logo text check (logo is null or (char_length(logo) <= 140000 and logo ~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$')),
  goal int not null default 6 check (goal between 2 and 30),
  reward text not null default 'Free coffee' check (char_length(reward) between 1 and 60),
  earn text not null default 'visit' check (earn in ('visit','amount')),
  per_amount numeric not null default 100 check (per_amount > 0 and per_amount <= 100000),
  updated_at timestamptz not null default now()
);

create table if not exists public.loyalty_customers (
  id uuid primary key default gen_random_uuid(),
  tenant_id text not null references public.tenants(id) on delete cascade,
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
-- one card per phone number; comparing the last 10 digits makes +90 5xx.. and 05xx.. the same person
create unique index if not exists loyalty_customers_phone_idx on public.loyalty_customers(tenant_id, right(phone, 10));
create index if not exists loyalty_customers_tenant_idx on public.loyalty_customers(tenant_id, last_visit desc nulls last);

create table if not exists public.loyalty_events (
  id bigserial primary key,
  tenant_id text not null references public.tenants(id) on delete cascade,
  customer_id uuid references public.loyalty_customers(id) on delete cascade,
  kind text not null check (kind in ('join','earn','redeem')),
  delta int not null default 0,
  amount numeric,
  staff uuid,
  at timestamptz not null default now()
);
create index if not exists loyalty_events_tenant_idx on public.loyalty_events(tenant_id, at desc);

alter table public.loyalty_settings enable row level security;
alter table public.loyalty_customers enable row level security;
alter table public.loyalty_events enable row level security;
revoke all on public.loyalty_settings, public.loyalty_customers, public.loyalty_events from anon, authenticated;
revoke all on sequence public.loyalty_events_id_seq from anon, authenticated;

-- ---------- helpers ----------
create or replace function public.loyalty_can_serve(t text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_platform_admin()
      or (coalesce(public.member_role(t), '') in ('owner','manager','cashier'))
$$;

create or replace function public.loyalty_norm_phone(p text) returns text
language sql immutable as $$
  select regexp_replace(coalesce(p, ''), '[^0-9]', '', 'g')
$$;

create or replace function public.loyalty_card_json(c public.loyalty_customers, s public.loyalty_settings) returns jsonb
language sql immutable as $$
  select jsonb_build_object('id', c.id, 'name', c.name, 'phone', c.phone, 'points', c.points,
    'ready', c.rewards_ready, 'redeemed', c.redeemed, 'visits', c.visits, 'total', c.total_earned,
    'last_visit', c.last_visit, 'created_at', c.created_at, 'goal', s.goal, 'reward', s.reward)
$$;

-- ---------- platform admin ----------
create or replace function public.admin_loyalty_list() returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('tenant_id', tenant_id, 'enabled', enabled, 'slug', slug,
      'brand_name', brand_name, 'color', color, 'logo', logo, 'goal', goal, 'reward', reward, 'earn', earn,
      'per_amount', per_amount,
      'customers', (select count(*) from public.loyalty_customers c where c.tenant_id = s.tenant_id))
    order by tenant_id) from public.loyalty_settings s), '[]'::jsonb);
end $$;

-- p_logo: null keeps the current logo, '' removes it, otherwise a png/jpeg/webp data URL (<= 140 KB).
create or replace function public.admin_loyalty_set(p_tenant text, p_enabled boolean, p_slug text, p_brand text,
  p_color text, p_logo text, p_goal int, p_reward text, p_earn text, p_per numeric) returns void
language plpgsql security definer set search_path = public as $$
declare cur public.loyalty_settings%rowtype; sl text; lg text;
begin
  if not public.is_platform_admin() then raise exception 'denied'; end if;
  if not exists (select 1 from public.tenants where id = p_tenant) then raise exception 'no tenant'; end if;
  select * into cur from public.loyalty_settings where tenant_id = p_tenant;
  sl := lower(coalesce(nullif(trim(p_slug), ''), cur.slug, p_tenant));
  if sl !~ '^[a-z0-9-]{3,30}$' then raise exception 'bad slug'; end if;
  if exists (select 1 from public.loyalty_settings where slug = sl and tenant_id <> p_tenant) then raise exception 'slug taken'; end if;
  if p_color !~ '^#[0-9a-fA-F]{6}$' then raise exception 'bad color'; end if;
  if p_goal is null or p_goal < 2 or p_goal > 30 then raise exception 'bad goal'; end if;
  if p_earn not in ('visit','amount') then raise exception 'bad earn'; end if;
  if p_per is null or p_per <= 0 or p_per > 100000 then raise exception 'bad amount'; end if;
  if char_length(trim(coalesce(p_reward, ''))) not between 1 and 60 then raise exception 'bad reward'; end if;
  if char_length(coalesce(p_brand, '')) > 40 then raise exception 'bad brand'; end if;
  if p_logo is null then lg := cur.logo;
  elsif p_logo = '' then lg := null;
  else
    if char_length(p_logo) > 140000 or p_logo !~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$' then raise exception 'bad logo'; end if;
    lg := p_logo;
  end if;
  insert into public.loyalty_settings(tenant_id, enabled, slug, brand_name, color, logo, goal, reward, earn, per_amount, updated_at)
    values (p_tenant, coalesce(p_enabled, true), sl, trim(coalesce(p_brand, '')), p_color, lg, p_goal, trim(p_reward), p_earn, p_per, now())
  on conflict (tenant_id) do update set enabled = excluded.enabled, slug = excluded.slug, brand_name = excluded.brand_name,
    color = excluded.color, logo = excluded.logo, goal = excluded.goal, reward = excluded.reward, earn = excluded.earn,
    per_amount = excluded.per_amount, updated_at = now();
  perform public.log_audit(p_tenant, 'loyalty_settings', jsonb_build_object('enabled', p_enabled, 'goal', p_goal, 'earn', p_earn));
end $$;

-- ---------- café staff ----------
create or replace function public.loyalty_staff_overview(p_tenant text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare s public.loyalty_settings%rowtype;
begin
  if not public.loyalty_can_serve(p_tenant) then raise exception 'denied'; end if;
  select * into s from public.loyalty_settings where tenant_id = p_tenant;
  if not found then return jsonb_build_object('enabled', false); end if;
  return jsonb_build_object('enabled', s.enabled, 'slug', s.slug, 'brand_name', s.brand_name, 'color', s.color,
    'logo', s.logo, 'goal', s.goal, 'reward', s.reward, 'earn', s.earn, 'per_amount', s.per_amount,
    'stats', jsonb_build_object(
      'customers', (select count(*) from public.loyalty_customers where tenant_id = p_tenant),
      'ready', (select coalesce(sum(rewards_ready), 0) from public.loyalty_customers where tenant_id = p_tenant),
      'redeemed', (select coalesce(sum(redeemed), 0) from public.loyalty_customers where tenant_id = p_tenant),
      'new7', (select count(*) from public.loyalty_customers where tenant_id = p_tenant and created_at > now() - interval '7 days'),
      'earn7', (select count(*) from public.loyalty_events where tenant_id = p_tenant and kind = 'earn' and at > now() - interval '7 days')),
    'recent', coalesce((select jsonb_agg(public.loyalty_card_json(c, s) order by c.last_visit desc nulls last, c.created_at desc)
      from (select * from public.loyalty_customers where tenant_id = p_tenant
            order by last_visit desc nulls last, created_at desc limit 20) c), '[]'::jsonb));
end $$;

create or replace function public.loyalty_staff_search(p_tenant text, p_q text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare s public.loyalty_settings%rowtype; q text := trim(coalesce(p_q, '')); d text := public.loyalty_norm_phone(p_q);
begin
  if not public.loyalty_can_serve(p_tenant) then raise exception 'denied'; end if;
  select * into s from public.loyalty_settings where tenant_id = p_tenant;
  if not found or char_length(q) < 2 then return '[]'::jsonb; end if;
  return coalesce((select jsonb_agg(public.loyalty_card_json(c, s) order by c.last_visit desc nulls last, c.name)
    from (select * from public.loyalty_customers
          where tenant_id = p_tenant
            and (lower(name) like '%' || replace(replace(lower(q), '%', ''), '_', '') || '%'
                 or (char_length(d) >= 3 and phone like '%' || d || '%'))
          order by last_visit desc nulls last, name limit 20) c), '[]'::jsonb);
end $$;

create or replace function public.loyalty_staff_add_customer(p_tenant text, p_name text, p_phone text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare s public.loyalty_settings%rowtype; c public.loyalty_customers%rowtype; ph text := public.loyalty_norm_phone(p_phone);
begin
  if not public.loyalty_can_serve(p_tenant) then raise exception 'denied'; end if;
  select * into s from public.loyalty_settings where tenant_id = p_tenant and enabled;
  if not found then raise exception 'loyalty off'; end if;
  if char_length(trim(coalesce(p_name, ''))) not between 1 and 40 then raise exception 'bad name'; end if;
  if ph !~ '^[0-9]{7,15}$' then raise exception 'bad phone'; end if;
  select * into c from public.loyalty_customers where tenant_id = p_tenant and right(phone, 10) = right(ph, 10);
  if not found then
    insert into public.loyalty_customers(tenant_id, name, phone) values (p_tenant, trim(p_name), ph) returning * into c;
    insert into public.loyalty_events(tenant_id, customer_id, kind, staff) values (p_tenant, c.id, 'join', auth.uid());
  end if;
  return public.loyalty_card_json(c, s);
end $$;

-- Adds points. 'visit' mode: +1 per call. 'amount' mode: floor(amount / per_amount).
-- When the points reach the goal they roll over into a ready reward.
create or replace function public.loyalty_staff_add(p_tenant text, p_customer uuid, p_amount numeric) returns jsonb
language plpgsql security definer set search_path = public as $$
declare s public.loyalty_settings%rowtype; c public.loyalty_customers%rowtype; n int; pts int; rw int;
begin
  if not public.loyalty_can_serve(p_tenant) then raise exception 'denied'; end if;
  select * into s from public.loyalty_settings where tenant_id = p_tenant and enabled;
  if not found then raise exception 'loyalty off'; end if;
  select * into c from public.loyalty_customers where id = p_customer and tenant_id = p_tenant for update;
  if not found then raise exception 'no customer'; end if;
  if c.last_visit is not null and c.last_visit > now() - interval '10 seconds' then raise exception 'too fast'; end if;
  if s.earn = 'amount' then
    if p_amount is null or p_amount <= 0 or p_amount > 1000000 then raise exception 'bad amount'; end if;
    n := floor(p_amount / s.per_amount)::int;
  else
    n := 1;
  end if;
  if n < 1 then raise exception 'no points'; end if;
  pts := c.points + n; rw := c.rewards_ready;
  while pts >= s.goal loop pts := pts - s.goal; rw := rw + 1; end loop;
  update public.loyalty_customers set points = pts, rewards_ready = rw, total_earned = total_earned + n,
    visits = visits + 1, last_visit = now() where id = c.id returning * into c;
  insert into public.loyalty_events(tenant_id, customer_id, kind, delta, amount, staff)
    values (p_tenant, c.id, 'earn', n, case when s.earn = 'amount' then p_amount end, auth.uid());
  return public.loyalty_card_json(c, s);
end $$;

create or replace function public.loyalty_staff_redeem(p_tenant text, p_customer uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare s public.loyalty_settings%rowtype; c public.loyalty_customers%rowtype;
begin
  if not public.loyalty_can_serve(p_tenant) then raise exception 'denied'; end if;
  select * into s from public.loyalty_settings where tenant_id = p_tenant and enabled;
  if not found then raise exception 'loyalty off'; end if;
  select * into c from public.loyalty_customers where id = p_customer and tenant_id = p_tenant for update;
  if not found then raise exception 'no customer'; end if;
  if c.rewards_ready < 1 then raise exception 'no reward'; end if;
  update public.loyalty_customers set rewards_ready = rewards_ready - 1, redeemed = redeemed + 1 where id = c.id returning * into c;
  insert into public.loyalty_events(tenant_id, customer_id, kind, delta, staff) values (p_tenant, c.id, 'redeem', -1, auth.uid());
  return public.loyalty_card_json(c, s);
end $$;

-- ---------- public (customers, no login) ----------
create or replace function public.loyalty_public_cafe(p_slug text) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('name', coalesce(nullif(s.brand_name, ''), t.name), 'color', s.color, 'logo', s.logo,
    'goal', s.goal, 'reward', s.reward, 'earn', s.earn, 'per_amount', s.per_amount)
  from public.loyalty_settings s join public.tenants t on t.id = s.tenant_id
  where s.slug = lower(coalesce(p_slug, '')) and s.enabled and not t.suspended
$$;

create or replace function public.loyalty_public_join(p_slug text, p_name text, p_phone text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare s public.loyalty_settings%rowtype; c public.loyalty_customers%rowtype; ph text := public.loyalty_norm_phone(p_phone);
begin
  select s2.* into s from public.loyalty_settings s2 join public.tenants t on t.id = s2.tenant_id
    where s2.slug = lower(coalesce(p_slug, '')) and s2.enabled and not t.suspended;
  if not found then raise exception 'no cafe'; end if;
  if char_length(trim(coalesce(p_name, ''))) not between 1 and 40 then raise exception 'bad name'; end if;
  if ph !~ '^[0-9]{7,15}$' then raise exception 'bad phone'; end if;
  if (select count(*) from public.loyalty_events where tenant_id = s.tenant_id and kind = 'join' and at > now() - interval '10 minutes') >= 30 then
    raise exception 'busy'; end if;
  if exists (select 1 from public.loyalty_customers where tenant_id = s.tenant_id and right(phone, 10) = right(ph, 10)) then
    raise exception 'already registered'; end if;
  insert into public.loyalty_customers(tenant_id, name, phone) values (s.tenant_id, trim(p_name), ph) returning * into c;
  insert into public.loyalty_events(tenant_id, customer_id, kind) values (s.tenant_id, c.id, 'join');
  return jsonb_build_object('token', c.token, 'card', public.loyalty_card_json(c, s));
end $$;

create or replace function public.loyalty_public_card(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare s public.loyalty_settings%rowtype; c public.loyalty_customers%rowtype; tn text;
begin
  if p_token is null or p_token !~ '^[a-f0-9]{64}$' then return null; end if;
  select * into c from public.loyalty_customers where token = p_token;
  if not found then return null; end if;
  select s2.* into s from public.loyalty_settings s2 join public.tenants t on t.id = s2.tenant_id
    where s2.tenant_id = c.tenant_id and s2.enabled and not t.suspended;
  if not found then return null; end if;
  select name into tn from public.tenants where id = c.tenant_id;
  return jsonb_build_object('card', public.loyalty_card_json(c, s),
    'cafe', jsonb_build_object('name', coalesce(nullif(s.brand_name, ''), tn), 'color', s.color, 'logo', s.logo,
      'goal', s.goal, 'reward', s.reward, 'slug', s.slug));
end $$;

-- ---------- privileges ----------
revoke execute on function
  public.loyalty_can_serve(text), public.loyalty_norm_phone(text),
  public.loyalty_card_json(public.loyalty_customers, public.loyalty_settings),
  public.admin_loyalty_list(), public.admin_loyalty_set(text, boolean, text, text, text, text, int, text, text, numeric),
  public.loyalty_staff_overview(text), public.loyalty_staff_search(text, text), public.loyalty_staff_add_customer(text, text, text),
  public.loyalty_staff_add(text, uuid, numeric), public.loyalty_staff_redeem(text, uuid),
  public.loyalty_public_cafe(text), public.loyalty_public_join(text, text, text), public.loyalty_public_card(text)
  from public, anon, authenticated;
grant execute on function
  public.admin_loyalty_list(), public.admin_loyalty_set(text, boolean, text, text, text, text, int, text, text, numeric),
  public.loyalty_staff_overview(text), public.loyalty_staff_search(text, text), public.loyalty_staff_add_customer(text, text, text),
  public.loyalty_staff_add(text, uuid, numeric), public.loyalty_staff_redeem(text, uuid)
  to authenticated;
grant execute on function
  public.loyalty_public_cafe(text), public.loyalty_public_join(text, text, text), public.loyalty_public_card(text)
  to anon, authenticated;
-- helpers stay callable only by other security-definer functions (owner), never from the API.
