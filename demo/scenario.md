# Demo scenario: retail on-prem source

Instance `onprem`, 127.0.0.1:55432, database `retail`, trust auth
(localhost demo only). Seeded deterministically by seed_demo.py with
RNG seed 42: customers 100000, products 5000, orders 200000,
order_items 300000, audit_log 50000.

## Planted findings (the pipeline must catch every one)

### Structure and strategy (since v0.1.0)

| Finding | Where planted | Must surface in |
|---|---|---|
| audit_log has no primary key | DDL in seed_demo.py | assess risk register; plan strategy discussion (blocks UPDATE/DELETE under logical replication; insert-only question) |
| wal_level = replica | pg create default | assess; plan lists the source change for logical_replication |
| hstore extension in use | products.attributes | assess; compatibility matrix row; BigQuery maps it to JSON via hstore_to_json |
| materialized view sales_by_product | POST DDL | assess; refreshed during migrate-data; validated non-empty; BigQuery materialized view or plain view with a warning |
| roles app_rw, app_ro, reporting | POST DDL | assess; pre-created on target during provision; each needs a BigQuery principal |
| sequences behind explicit-id COPY | seed uses setval | validated (dump_restore) or bumped at cutover (logical); no equivalent on BigQuery (noted) |

### Security (since v0.2.0)

| Finding | Where planted | Must surface in |
|---|---|---|
| orders.region column with values us-east, us-west, eu | DDL | the row-level security predicate target |
| orders has RLS enabled; policy orders_region_eu FOR SELECT TO reporting USING (region = 'eu') | POST | security inventory; auto-translated BigQuery row access policy rls_reporting |
| policy orders_all_rw ON orders TO app_rw USING (true) | POST | row access policy rls_app_rw with FILTER USING (TRUE); demonstrates that once any policy exists, unnamed principals see no rows |
| audit_log has RLS enabled; policy audit_self FOR SELECT TO app_ro USING (actor = current_user) | POST | translation to SESSION_USER() with an identity-format note; probe expects zero rows because actors are role-style names, not emails |
| policy audit_all_rw ON audit_log TO app_rw USING (true) | POST | row access policy rls_app_rw on audit_log |
| app_ro loses table SELECT on customers and gets column SELECT on (id, full_name, created_at) | POST | restricted column customers.email; policy tag customers__email readable by app_rw only; app_ro keeps dataViewer on the table |
| GRANT app_ro TO reporting | POST | membership flattening: reporting inherits app_ro's privileges and policies (audit_self applies to reporting too) |
| ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO app_ro | POST | default privileges NOTE (no automatic dataset-wide binding, to avoid widening access) |
| postgres is a superuser and owns every relation | initdb | bypass role: unmapped by default (INFO superuser_unmapped), dataOwner plus bypass row policies when mapped (WARNING superuser_mapped) |
