-- Stack & Ship: Supabase Data API grants check (for the 30 Oct 2026 change)
-- Paste into the Supabase SQL Editor and run. It is one SELECT over catalog views
-- (pg_class, pg_namespace, pg_policy, pg_proc, pg_default_acl): it only reads catalog views and makes no changes.
-- Schemas checked: edit the list in `exposed` if you expose more than `public` through the Data API.
-- Result: one row per finding (FAIL / WARN / INFO), plus a PASS row for each check with no findings.
-- MIT licence. https://edtrackai.github.io/supabase-oct-30-grants
with exposed(nspname) as (values ('public')),
api_roles(rolname) as (select rolname from pg_roles where rolname in ('anon', 'authenticated')),
tbl as (
  select c.oid, n.nspname, c.relname, c.relrowsecurity as rls, format('%I.%I', n.nspname, c.relname) as obj
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where c.relkind in ('r', 'p') and n.nspname in (select nspname from exposed)
    and not exists (select 1 from pg_depend d where d.classid = 'pg_class'::regclass and d.objid = c.oid and d.deptype = 'e')
),
priv as (  -- which table privileges each API role holds (directly, via PUBLIC or via membership)
  select t.oid, r.rolname, p.priv
  from tbl t cross join api_roles r cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE')) p(priv)
  where has_table_privilege(r.rolname, t.oid, p.priv)
),
pol as (  -- policies, with the roles they apply to (PUBLIC = 0 means every role)
  select p.polrelid as oid, p.polname,
    case p.polcmd when 'r' then 'SELECT' when 'a' then 'INSERT' when 'w' then 'UPDATE' when 'd' then 'DELETE' else 'ALL' end as cmd,
    p.polroles
  from pg_policy p join tbl t on t.oid = p.polrelid
),
pol_role as (
  select pol.oid, pol.polname, pol.cmd, r.rolname, (0 = any(pol.polroles)) as to_public
  from pol cross join api_roles r
  where 0 = any(pol.polroles) or (select oid from pg_roles where rolname = r.rolname) = any(pol.polroles)
),
findings as (
  -- C1: RLS off on a table an API role can reach
  select 'C1 RLS off on API-reachable table' as check_name, 'FAIL' as status, t.obj as object,
    'RLS is off and ' || string_agg(distinct p.rolname || ':' || p.priv, ', ') || ' is granted' as detail,
    format('alter table %s enable row level security;  -- then add policies before keeping any grant', t.obj) as suggested_fix
  from tbl t join priv p on p.oid = t.oid where not t.rls group by t.obj
  union all
  -- C2: write privileges held by anon
  select 'C2 anon can write', 'WARN', t.obj,
    'anon holds ' || string_agg(p.priv, ', ' order by p.priv) || case when t.rls then ' (RLS on: policies decide rows; TRUNCATE ignores RLS)' else ' (RLS off)' end,
    format('revoke insert, update, delete, truncate on %s from anon;  -- keep only what a signed-out visitor needs', t.obj)
  from tbl t join priv p on p.oid = t.oid where p.rolname = 'anon' and p.priv <> 'SELECT' group by t.obj, t.rls
  union all
  -- C3: write privileges held by authenticated (normal with RLS + policies; review)
  select 'C3 authenticated can write', case when t.rls and bool_and(p.priv <> 'TRUNCATE') then 'INFO' else 'WARN' end, t.obj,
    'authenticated holds ' || string_agg(p.priv, ', ' order by p.priv) || case when t.rls then '' else ' (RLS off)' end,
    format('grant only the commands your policies cover; revoke truncate on %s from authenticated;', t.obj)
  from tbl t join priv p on p.oid = t.oid where p.rolname = 'authenticated' and p.priv <> 'SELECT' group by t.obj, t.rls
  union all
  -- C4: policy for a role that lacks the matching grant (the Data API returns 42501)
  select 'C4 policy without grant', 'WARN', t.obj,
    format('policy "%s" (%s) applies to %s, which has no %s privilege: requests get 42501',
      pr.polname, pr.cmd, pr.rolname, case pr.cmd when 'ALL' then 'SELECT/INSERT/UPDATE/DELETE' else pr.cmd end),
    format('grant %s on %s to %s;  -- only if this role should use the Data API for it',
      lower(case pr.cmd when 'ALL' then 'select, insert, update, delete' else pr.cmd end), t.obj, pr.rolname)
  from pol_role pr join tbl t on t.oid = pr.oid
  where not pr.to_public
    and not exists (select 1 from priv p where p.oid = pr.oid and p.rolname = pr.rolname and (p.priv = pr.cmd or (pr.cmd = 'ALL' and p.priv <> 'TRUNCATE')))
  union all
  select 'C4 policy without grant', 'WARN', t.obj,
    format('policy "%s" (%s) applies to every role, but neither anon nor authenticated has the %s privilege: requests get 42501',
      p0.polname, p0.cmd, case p0.cmd when 'ALL' then 'SELECT/INSERT/UPDATE/DELETE' else p0.cmd end),
    format('grant %s on %s to authenticated;  -- or anon, only if signed-out visitors need it',
      lower(case p0.cmd when 'ALL' then 'select, insert, update, delete' else p0.cmd end), t.obj)
  from pol p0 join tbl t on t.oid = p0.oid
  where 0 = any(p0.polroles) and exists (select 1 from api_roles)
    and not exists (select 1 from priv p where p.oid = p0.oid and (p.priv = p0.cmd or (p0.cmd = 'ALL' and p.priv <> 'TRUNCATE')))
  union all
  -- C5: grant with RLS on but no policy for that role and command (all rows denied; grant has no effect)
  select 'C5 grant without policy', 'INFO', t.obj,
    format('%s holds %s but no policy covers it, so RLS denies every row', p.rolname, p.priv),
    'add a policy for this role and command, or revoke the grant if it is not needed'
  from tbl t join priv p on p.oid = t.oid
  where t.rls and p.priv <> 'TRUNCATE'
    and not exists (select 1 from pol_role pr where pr.oid = t.oid and pr.rolname = p.rolname and pr.cmd in (p.priv, 'ALL'))
  union all
  -- C6: SECURITY DEFINER function in an exposed schema that anon or authenticated can execute
  select 'C6 public SECURITY DEFINER function', case when has_function_privilege('anon', f.oid, 'EXECUTE') then 'FAIL' else 'WARN' end,
    format('%I.%I(%s)', n.nspname, f.proname, pg_get_function_identity_arguments(f.oid)),
    'SECURITY DEFINER runs as its owner (RLS usually bypassed) and is callable by '
      || concat_ws(' and ', case when has_function_privilege('anon', f.oid, 'EXECUTE') then 'anon' end,
                            case when has_function_privilege('authenticated', f.oid, 'EXECUTE') then 'authenticated' end)
      || case when coalesce(array_to_string(f.proconfig, ','), '') like '%search_path=%' then '' else '; search_path is not pinned' end,
    format('revoke execute on function %I.%I(%s) from public, anon;  -- or make it security invoker / move it to a private schema',
      n.nspname, f.proname, pg_get_function_identity_arguments(f.oid))
  from pg_proc f join pg_namespace n on n.oid = f.pronamespace
  where f.prosecdef and n.nspname in (select nspname from exposed)
    and exists (select 1 from api_roles)
    and (has_function_privilege('anon', f.oid, 'EXECUTE') or has_function_privilege('authenticated', f.oid, 'EXECUTE'))
    and not exists (select 1 from pg_depend d where d.classid = 'pg_proc'::regclass and d.objid = f.oid and d.deptype = 'e')
  union all
  -- C7: default privileges: are new tables in exposed schemas still granted to API roles automatically?
  select 'C7 new tables auto-exposed', 'INFO', format('default privileges in %I', e.nspname),
    'new tables created in this schema (by the role that set the default privileges) are still granted to API roles automatically; Supabase''s changelog schedules this to stop for existing projects on 30 Oct 2026 (date may move; see the page)',
    'add explicit grants to every migration that creates a table (enable RLS, add policies, then grant the minimum)'
  from exposed e
  where exists (select 1 from pg_default_acl d join pg_namespace n on n.oid = d.defaclnamespace
                where n.nspname = e.nspname and d.defaclobjtype = 'r'
                  and exists (select 1 from aclexplode(d.defaclacl) a join api_roles r on (select oid from pg_roles where rolname = r.rolname) = a.grantee))
),
checks(check_name) as (values ('C1 RLS off on API-reachable table'), ('C2 anon can write'), ('C3 authenticated can write'),
  ('C4 policy without grant'), ('C5 grant without policy'), ('C6 public SECURITY DEFINER function'), ('C7 new tables auto-exposed'))
select check_name, status, object, detail, suggested_fix from findings
union all
select c.check_name, 'PASS', '-', 'no findings', '-' from checks c where not exists (select 1 from findings f where f.check_name = c.check_name)
order by 1, 2, 3;
