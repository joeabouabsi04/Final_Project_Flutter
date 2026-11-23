-- One-row summary of 04_verify.sql (read-only). Good for a single screenshot.
-- Expected: 142 | 6 | 17 | 0 | 0 | (some number > 0)
select
 (select count(*) from pg_tables where schemaname='public')     as public_tables,
 (select count(*) from pg_tables where schemaname='restricted') as restricted_tables,
 (select count(*) from pg_tables where schemaname='accounting') as accounting_tables,
 (select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace
   where n.nspname in ('public','restricted','accounting')
   and c.relkind='r' and not c.relrowsecurity)                  as tables_without_rls,
 (select coalesce(sum((xpath('/row/n/text()', query_to_xml(
   format('select count(*) as n from %I.%I',schemaname,tablename),false,true,'')))[1]::text::bigint),0)
   from pg_tables where schemaname in ('public','restricted','accounting')) as total_rows,
 (select count(*) from information_schema.table_constraints
   where table_schema in ('public','restricted','accounting')
   and constraint_type='FOREIGN KEY')                           as foreign_keys;
