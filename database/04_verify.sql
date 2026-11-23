-- Read-only checks. Run before creating your own users/configuration.
-- Expected: three application schemas; zero rows; no tables without RLS.
select schemaname, count(*) as table_count
from pg_tables where schemaname in ('public','restricted','accounting')
group by schemaname order by schemaname;

-- Exact counts rather than planner estimates. No rows = empty application.
select schemaname, tablename,
 (xpath('/row/n/text()', query_to_xml(
  format('select count(*) as n from %I.%I',schemaname,tablename),false,true,'')))[1]::text::bigint as row_count
from pg_tables where schemaname in ('public','restricted','accounting')
order by schemaname,tablename;

select n.nspname as schema_name,c.relname as table_without_rls
from pg_class c join pg_namespace n on n.oid=c.relnamespace
where n.nspname in ('public','restricted','accounting')
and c.relkind='r' and not c.relrowsecurity;

select table_schema,table_name,constraint_name
from information_schema.table_constraints
where table_schema in ('public','restricted','accounting')
and constraint_type='FOREIGN KEY'
order by table_schema,table_name,constraint_name;
