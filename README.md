-- JEMITHA Inteligencia Comercial 1.0 | Supabase PostgreSQL
-- Ejecutar en un proyecto NUEVO o en un esquema aislado; no modifica módulos existentes.
create extension if not exists pgcrypto;
create table if not exists public.ic_workspaces (
 id uuid primary key default gen_random_uuid(), name text not null, owner_id uuid not null references auth.users(id), created_at timestamptz not null default now()
);
create table if not exists public.ic_members (
 id uuid primary key default gen_random_uuid(), workspace_id uuid not null references public.ic_workspaces(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade, role text not null check(role in ('owner','admin','supervisor','agent','viewer')),
 unique(workspace_id,user_id)
);
create table if not exists public.ic_prospects (
 id uuid primary key default gen_random_uuid(), workspace_id uuid not null references public.ic_workspaces(id) on delete cascade,
 name text not null, phone text, email text, business_name text, source text, interest text, stage text not null default 'new' check(stage in ('new','contacted','qualified','proposal','won','lost')),
 notes text, consent_to_contact boolean not null default false, assigned_agent text, next_followup_at timestamptz,
 created_by uuid references auth.users(id), created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.ic_conversations (
 id uuid primary key default gen_random_uuid(), workspace_id uuid not null references public.ic_workspaces(id) on delete cascade,
 prospect_id uuid references public.ic_prospects(id) on delete set null, channel text not null default 'internal', external_thread_id text,
 status text not null default 'open', assigned_agent text, created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.ic_messages (
 id uuid primary key default gen_random_uuid(), workspace_id uuid not null references public.ic_workspaces(id) on delete cascade,
 conversation_id uuid not null references public.ic_conversations(id) on delete cascade, sender_type text not null check(sender_type in ('customer','human','ai','system')),
 agent_name text, body text not null, metadata jsonb not null default '{}', created_at timestamptz not null default now()
);
create table if not exists public.ic_tasks (
 id uuid primary key default gen_random_uuid(), workspace_id uuid not null references public.ic_workspaces(id) on delete cascade,
 prospect_id uuid references public.ic_prospects(id) on delete cascade, title text not null, due_at timestamptz, status text not null default 'pending',
 assigned_to uuid references auth.users(id), created_at timestamptz not null default now()
);
create table if not exists public.ic_agent_runs (
 id uuid primary key default gen_random_uuid(), workspace_id uuid not null references public.ic_workspaces(id) on delete cascade,
 agent_name text not null, trigger_type text, status text not null default 'queued', input_summary text, output_summary text,
 requires_approval boolean not null default false, approved_by uuid references auth.users(id), created_at timestamptz not null default now(), finished_at timestamptz
);
create table if not exists public.ic_audit_log (
 id uuid primary key default gen_random_uuid(), workspace_id uuid not null references public.ic_workspaces(id) on delete cascade,
 actor_id uuid references auth.users(id), action text not null, entity_type text, entity_id uuid, details jsonb not null default '{}', created_at timestamptz not null default now()
);
create index if not exists ic_prospects_workspace_stage_idx on public.ic_prospects(workspace_id,stage);
create index if not exists ic_prospects_followup_idx on public.ic_prospects(workspace_id,next_followup_at);
create index if not exists ic_messages_conversation_idx on public.ic_messages(conversation_id,created_at);
create index if not exists ic_tasks_workspace_due_idx on public.ic_tasks(workspace_id,due_at);
-- RLS base: activar políticas de membresía antes de exponer el API.
alter table public.ic_workspaces enable row level security;
alter table public.ic_members enable row level security;
alter table public.ic_prospects enable row level security;
alter table public.ic_conversations enable row level security;
alter table public.ic_messages enable row level security;
alter table public.ic_tasks enable row level security;
alter table public.ic_agent_runs enable row level security;
alter table public.ic_audit_log enable row level security;
-- No se crean políticas permisivas deliberadamente. Las políticas de lectura/escritura
-- deben comprobar auth.uid() contra ic_members para el workspace correspondiente.

-- Catálogo comercial con autorización explícita del propietario/administrador.
-- No insertar precios de ejemplo: iniciar vacío evita que un agente comunique importes ficticios.
create table if not exists public.ic_price_catalog (
 id uuid primary key default gen_random_uuid(),
 workspace_id uuid not null references public.ic_workspaces(id) on delete cascade,
 package_name text not null,
 description text not null default '',
 amount numeric(12,2) not null check(amount >= 0),
 currency text not null default 'MXN' check(currency = 'MXN'),
 status text not null default 'pending' check(status in ('pending','approved','retired')),
 version integer not null default 1 check(version > 0),
 created_by uuid references auth.users(id),
 approved_by uuid references auth.users(id),
 approved_at timestamptz,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 constraint ic_price_approval_consistency check (
   (status = 'approved' and approved_by is not null and approved_at is not null)
   or (status <> 'approved' and approved_by is null and approved_at is null)
 )
);
create index if not exists ic_price_workspace_status_idx on public.ic_price_catalog(workspace_id,status);
alter table public.ic_price_catalog enable row level security;

create or replace function public.ic_is_commercial_admin(target_workspace uuid)
returns boolean language sql stable security definer set search_path = public
as $$
 select exists (
   select 1 from public.ic_members m
   where m.workspace_id = target_workspace and m.user_id = auth.uid()
     and m.role in ('owner','admin')
 );
$$;
revoke all on function public.ic_is_commercial_admin(uuid) from public;
grant execute on function public.ic_is_commercial_admin(uuid) to authenticated;

-- Los empleados/agentes solo pueden leer precios aprobados. Administradores pueden ver todo.
drop policy if exists ic_prices_read_policy on public.ic_price_catalog;
create policy ic_prices_read_policy on public.ic_price_catalog for select to authenticated
using (status = 'approved' or public.ic_is_commercial_admin(workspace_id));
drop policy if exists ic_prices_insert_policy on public.ic_price_catalog;
create policy ic_prices_insert_policy on public.ic_price_catalog for insert to authenticated
with check (public.ic_is_commercial_admin(workspace_id) and status = 'pending' and approved_by is null and approved_at is null);
drop policy if exists ic_prices_update_policy on public.ic_price_catalog;
create policy ic_prices_update_policy on public.ic_price_catalog for update to authenticated
using (public.ic_is_commercial_admin(workspace_id))
with check (public.ic_is_commercial_admin(workspace_id));
drop policy if exists ic_prices_delete_policy on public.ic_price_catalog;
create policy ic_prices_delete_policy on public.ic_price_catalog for delete to authenticated
using (public.ic_is_commercial_admin(workspace_id));

-- Cualquier cambio comercial invalida la aprobación anterior.
create or replace function public.ic_reset_price_approval_on_change()
returns trigger language plpgsql set search_path = public
as $$
begin
 if new.package_name is distinct from old.package_name
    or new.description is distinct from old.description
    or new.amount is distinct from old.amount
    or new.currency is distinct from old.currency then
   new.status := 'pending';
   new.version := old.version + 1;
   new.approved_by := null;
   new.approved_at := null;
 end if;
 new.updated_at := now();
 return new;
end;
$$;
drop trigger if exists ic_price_change_requires_approval on public.ic_price_catalog;
create trigger ic_price_change_requires_approval before update on public.ic_price_catalog
for each row execute function public.ic_reset_price_approval_on_change();

-- Única operación de aprobación recomendada para la aplicación. Requiere sesión admin.
create or replace function public.ic_approve_price(price_id uuid)
returns public.ic_price_catalog language plpgsql security invoker set search_path = public
as $$
declare p public.ic_price_catalog;
begin
 select * into p from public.ic_price_catalog where id = price_id for update;
 if not found then raise exception 'Paquete no encontrado'; end if;
 if not public.ic_is_commercial_admin(p.workspace_id) then raise exception 'Solo el propietario o administrador puede autorizar precios'; end if;
 if p.status <> 'pending' then raise exception 'El paquete no está pendiente de autorización'; end if;
 update public.ic_price_catalog set status='approved', approved_by=auth.uid(), approved_at=now()
 where id=price_id returning * into p;
 insert into public.ic_audit_log(workspace_id,actor_id,action,entity_type,entity_id,details)
 values(p.workspace_id,auth.uid(),'price_approved','price',p.id,jsonb_build_object('package_name',p.package_name,'amount',p.amount,'currency',p.currency,'version',p.version));
 return p;
end;
$$;
grant execute on function public.ic_approve_price(uuid) to authenticated;
