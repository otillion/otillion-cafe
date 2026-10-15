-- Fincan multi-tenant schema for Supabase (Postgres + RLS).
-- DRAFT: review and test on a staging database before production use.

create extension if not exists pgcrypto;

create type app_role as enum ('owner','manager','accountant','cashier','kitchen');

create table tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table branches (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  name text not null
);

create table memberships (
  tenant_id uuid not null references tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role app_role not null,
  branch_id uuid references branches(id),   -- null = all branches (owner/manager/accountant)
  active boolean not null default true,
  primary key (tenant_id, user_id)
);

-- Admin PIN (bcrypt) kept apart; never readable by clients.
create table admin_pins (
  tenant_id uuid primary key references tenants(id) on delete cascade,
  pin_hash text not null,
  failed int not null default 0,
  locked_until timestamptz
);
create table step_ups (
  tenant_id uuid not null, user_id uuid not null,
  valid_until timestamptz not null,
  primary key (tenant_id, user_id)
);

create table menu_items (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  name text not null, category text, price numeric(12,2) not null check (price >= 0),
  station text not null default 'kitchen' check (station in ('kitchen','bar'))
);
create table ingredients (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  branch_id uuid not null references branches(id),
  name text not null, unit text not null,
  qty numeric(14,3) not null default 0, min_qty numeric(14,3) not null default 0
);
-- costs separated so cashiers/kitchen cannot read them
create table ingredient_costs (
  ingredient_id uuid primary key references ingredients(id) on delete cascade,
  tenant_id uuid not null references tenants(id) on delete cascade,
  unit_cost numeric(14,4) not null check (unit_cost >= 0)
);
create table recipes (
  item_id uuid references menu_items(id) on delete cascade,
  ingredient_id uuid references ingredients(id) on delete cascade,
  tenant_id uuid not null references tenants(id) on delete cascade,
  qty numeric(14,4) not null check (qty > 0),
  primary key (item_id, ingredient_id)
);

create table orders (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  branch_id uuid not null references branches(id),
  table_label text, kind text not null default 'dine_in' check (kind in ('dine_in','takeaway')),
  status text not null default 'open' check (status in ('open','paid','void')),
  opened_by uuid references auth.users(id), opened_at timestamptz not null default now(),
  closed_at timestamptz
);
create table order_lines (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references orders(id) on delete cascade,
  tenant_id uuid not null references tenants(id) on delete cascade,
  item_id uuid not null references menu_items(id),
  qty int not null check (qty > 0), unit_price numeric(12,2) not null,
  sent boolean not null default false, state text not null default 'new'
);
create table payments (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  order_id uuid not null references orders(id),
  method text not null check (method in ('cash','card')),
  amount numeric(12,2) not null check (amount > 0),
  by_user uuid references auth.users(id), at timestamptz not null default now()
);

create table shifts     (id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade, branch_id uuid references branches(id), user_id uuid not null, starts_at timestamptz not null, ends_at timestamptz not null);
create table attendance (id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade, user_id uuid not null, clock_in timestamptz not null, clock_out timestamptz);
create table leaves     (id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade, user_id uuid not null, from_date date not null, to_date date not null, status text not null default 'pending' check (status in ('pending','approved','rejected')));

-- Append-only audit log
create table audit_log (
  id bigserial primary key,
  tenant_id uuid not null, user_id uuid, action text not null, detail jsonb,
  at timestamptz not null default now()
);

-- ---------- helpers ----------
create or replace function my_role(t uuid) returns app_role
language sql stable security definer set search_path = public as $$
  select role from memberships where tenant_id = t and user_id = auth.uid() and active
$$;
create or replace function can_see_branch(t uuid, b uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from memberships m
    where m.tenant_id = t and m.user_id = auth.uid() and m.active
      and (m.branch_id is null or m.branch_id = b))
$$;
create or replace function has_step_up(t uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from step_ups s where s.tenant_id = t and s.user_id = auth.uid() and s.valid_until > now())
$$;

-- Enable RLS everywhere
do $$ declare r record; begin
  for r in select tablename from pg_tables where schemaname='public' loop
    execute format('alter table %I enable row level security', r.tablename);
  end loop; end $$;

-- tenant read access: any active member
create policy t_read  on tenants     for select using (my_role(id) is not null);
create policy b_read  on branches    for select using (my_role(tenant_id) is not null);
create policy m_read  on memberships for select using (user_id = auth.uid() or my_role(tenant_id) in ('owner','manager'));
-- NO insert/update/delete policies on memberships, admin_pins, step_ups:
-- changes go only through security-definer functions below.

create policy menu_read  on menu_items for select using (my_role(tenant_id) is not null);
create policy menu_write on menu_items for all
  using (my_role(tenant_id) in ('owner','manager')) with check (my_role(tenant_id) in ('owner','manager'));

create policy ing_read  on ingredients for select using (can_see_branch(tenant_id, branch_id));
create policy cost_read on ingredient_costs for select using (my_role(tenant_id) in ('owner','manager','accountant'));
create policy rec_read  on recipes for select using (my_role(tenant_id) is not null);

create policy ord_read   on orders for select using (can_see_branch(tenant_id, branch_id));
create policy ord_insert on orders for insert with check (can_see_branch(tenant_id, branch_id) and my_role(tenant_id) in ('owner','manager','cashier'));
create policy ord_update on orders for update using (can_see_branch(tenant_id, branch_id) and my_role(tenant_id) in ('owner','manager','cashier'));
create policy line_read   on order_lines for select using (my_role(tenant_id) is not null);
create policy line_write  on order_lines for insert with check (my_role(tenant_id) in ('owner','manager','cashier'));
-- kitchen may only advance line state (use a function; no direct update policy for kitchen)

create policy pay_read on payments for select using (my_role(tenant_id) in ('owner','manager','accountant','cashier'));
-- payments are inserted only by pay_order()

create policy shift_read on shifts for select using (user_id = auth.uid() or my_role(tenant_id) in ('owner','manager'));
create policy att_read   on attendance for select using (user_id = auth.uid() or my_role(tenant_id) in ('owner','manager'));
create policy leave_read on leaves for select using (user_id = auth.uid() or my_role(tenant_id) in ('owner','manager'));
create policy leave_ins  on leaves for insert with check (user_id = auth.uid());

create policy audit_read on audit_log for select using (my_role(tenant_id) in ('owner','manager'));
-- no insert/update/delete policy: only triggers/functions write the log

-- ---------- sensitive operations ----------
create or replace function log_event(t uuid, a text, d jsonb) returns void
language sql security definer set search_path = public as $$
  insert into audit_log(tenant_id, user_id, action, detail) values (t, auth.uid(), a, d)
$$;

-- Verify admin PIN: bcrypt compare, 5 failures => 60s lock, grants 2 min step-up
create or replace function verify_admin_pin(t uuid, pin text) returns boolean
language plpgsql security definer set search_path = public as $$
declare p admin_pins%rowtype;
begin
  if my_role(t) not in ('owner','manager') then
    perform log_event(t,'denied','{"fn":"verify_admin_pin"}'); return false; end if;
  select * into p from admin_pins where tenant_id = t for update;
  if p.locked_until is not null and p.locked_until > now() then return false; end if;
  if p.pin_hash = crypt(pin, p.pin_hash) then
    update admin_pins set failed = 0, locked_until = null where tenant_id = t;
    insert into step_ups values (t, auth.uid(), now() + interval '2 minutes')
      on conflict (tenant_id, user_id) do update set valid_until = excluded.valid_until;
    perform log_event(t,'pin_ok','{}'); return true;
  end if;
  update admin_pins set failed = failed + 1,
    locked_until = case when failed + 1 >= 5 then now() + interval '60 seconds' end,
    failed = case when failed + 1 >= 5 then 0 else failed + 1 end
  where tenant_id = t;
  perform log_event(t,'pin_fail','{}'); return false;
end $$;

-- Change a member's role: step-up required; nobody can grant above their own rank;
-- only the owner can create owners.
create or replace function set_member_role(t uuid, target uuid, new_role app_role, new_branch uuid)
returns void language plpgsql security definer set search_path = public as $$
declare me app_role := my_role(t);
begin
  if me not in ('owner','manager') or not has_step_up(t) then
    perform log_event(t,'denied', jsonb_build_object('fn','set_member_role','target',target));
    raise exception 'not allowed'; end if;
  if new_role = 'owner' and me <> 'owner' then raise exception 'owner only'; end if;
  update memberships set role = new_role, branch_id = new_branch where tenant_id = t and user_id = target;
  perform log_event(t,'role_change', jsonb_build_object('target',target,'role',new_role,'branch',new_branch));
end $$;

-- TODO (to implement next): send_order() [deducts stock by recipe],
-- pay_order(), void_line() [step-up], apply_stock_count() [step-up],
-- invite_member() [step-up], kitchen_advance_line().

revoke all on function verify_admin_pin, set_member_role from public;
grant execute on function verify_admin_pin, set_member_role to authenticated;
