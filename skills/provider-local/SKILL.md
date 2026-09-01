---
name: provider-local
description: Local stand-in cloud provider backed by a portable PostgreSQL instance
---

# Provider: local (demo stand-in)

Provisions a second portable PostgreSQL instance on this machine to play
the role of the cloud target. The provider contract is identical to the
cloud providers; only the adapter differs.

## Capability matrix (verified 2026-09-01, local portable build)

| Dimension | Support |
|---|---|
| Engine versions | The pinned portable version (17.x) |
| Extensions | Everything in contrib, including hstore |
| Superuser | Yes (postgres) |
| Logical replication target | Yes (CREATE SUBSCRIPTION) |
| wal_level control | Full (set-conf + restart) |

## Provision

Instance name MUST be `target-<migration>`; port default 55433.

1. `python "$SCRIPTS" pg create --name target-<migration> --port 55433`
2. `python "$SCRIPTS" pg start --name target-<migration>`
3. Create the database:
   `python "$SCRIPTS" ... ` is not needed; use psql via the pg helper:
   run SQL `CREATE DATABASE "<dbname>"` against dbname postgres on the
   target port (see pg.run_sql; the provision playbook shows the exact
   invocation).
4. Pre-create every role from inventory.json roles[] on the target:
   for each, SQL
   `DO $$ BEGIN CREATE ROLE "<name>" <LOGIN|NOLOGIN>;
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;`
5. Smallest viable instance: not applicable; record "local" as the
   instance class.

## Connect

host 127.0.0.1, port 55433, user postgres, trust auth (password_env
empty). target.json records exactly these.

## Teardown

`pg stop --name target-<migration>` then
`pg destroy --name target-<migration> --yes`. Irreversible; the caller
must have collected the typed migration name first.

## Cost

Free. Disk only.
