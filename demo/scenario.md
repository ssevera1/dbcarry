# Demo scenario: retail on-prem source

Instance `onprem`, 127.0.0.1:55432, database `retail`, trust auth
(localhost demo only). Seeded deterministically by seed_demo.py with
RNG seed 42: customers 100000, products 5000, orders 200000,
order_items 300000, audit_log 50000.

## Planted findings (the pipeline must catch every one)

| Finding | Where planted | Must surface in |
|---|---|---|
| audit_log has no primary key | DDL in seed_demo.py | assess risk register; plan strategy discussion (blocks UPDATE/DELETE under logical replication; insert-only question) |
| wal_level = replica | pg create default | assess; plan lists the source change for logical_replication |
| hstore extension in use | products.attributes | assess; compatibility matrix row |
| materialized view sales_by_product | POST DDL | assess; refreshed during migrate-data; validated non-empty |
| roles app_rw, app_ro, reporting | POST DDL | assess; pre-created on target during provision |
| sequences behind explicit-id COPY | seed uses setval | validated (dump_restore) or bumped at cutover (logical) |
