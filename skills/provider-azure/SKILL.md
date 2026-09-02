---
name: provider-azure
description: Azure Database for PostgreSQL Flexible Server target provider for db-drift
---

# Provider: Azure Database for PostgreSQL Flexible Server

> DOCUMENTED, NOT LIVE-TESTED. Written 2026-09-01 from documentation
> knowledge. Verify against learn.microsoft.com/azure/postgresql
> before the first real run. Cloud resources cost money the moment
> they exist.

## Prerequisites check

`az account show` succeeds and names the intended subscription; a
resource group exists or the user names one to create. Fail the
provision phase if any check fails.

## Capability matrix (verify against current docs; dated 2026-09-01)

| Dimension | Support |
|---|---|
| Engine versions | PostgreSQL 13 through 17 |
| hstore extension | Yes, but must be added to the azure.extensions server parameter allowlist first |
| Extensions generally | Allowlist via azure.extensions parameter |
| Superuser | No; azure_pg_admin role |
| Logical replication target | Yes (native subscription supported) |
| Source for logical decoding | Server parameter wal_level=logical plus restart |
| Roles | CREATE ROLE allowed; no SUPERUSER attribute |

## Provision

Server name: `dbdrift-<migration>` (globally unique; append a random
suffix on collision). Admin password from a user-named env var.

1. `az postgres flexible-server create --name dbdrift-<migration>
   --resource-group <rg> --location <location> --tier Burstable
   --sku-name Standard_B1ms --storage-size 32 --version 17
   --admin-user dbdrift --admin-password "$env:<PASSWORD_ENV>"
   --public-access <operator public IP>` (minutes; long timeout or
   background)
2. Allow needed extensions before schema restore:
   `az postgres flexible-server parameter set --server-name
   dbdrift-<migration> --resource-group <rg> --name azure.extensions
   --value HSTORE` (comma-append every extension from inventory that
   the matrix allows)
3. `az postgres flexible-server db create --server-name
   dbdrift-<migration> --resource-group <rg> --database-name <dbname>`
4. Pre-create inventory roles via psql once connected.
5. Endpoint host is `dbdrift-<migration>.postgres.database.azure.com`
   -> target.json.

## Connect

Endpoint host, port 5432, user dbdrift, TLS required
(PGSSLMODE=require), password_env as named by the user.

## Teardown

`az postgres flexible-server delete --name dbdrift-<migration>
--resource-group <rg> --yes` after typed confirmation of the
migration name. Permanent.

## Cost

Standard_B1ms runs on the order of $0.02/hour plus storage (verify
current pricing). State the estimate in the plan and provision report.

## Known limitations

Azure Database for PostgreSQL Flexible Server creates its own
`azure_sys` schema, with its own tables, in every database. `inventory`,
`objcount`, and `checksum snapshot` filter out only `pg_catalog` and
`information_schema`; they do not currently filter `azure_sys`. Under
phase-schema.md's equal-count requirement, this means a real migration
against this provider will show the target with one extra schema's
worth of tables that the source never had. An operator should expect to
manually account for this discrepancy in the schema and data
equal-count checks (a future `--exclude-schema` flag is the real fix;
not in scope for v0.1.0).

## MySQL flavor (engine mysql; execution deferred in v1)

Azure Database for MySQL Flexible Server exists with the same
provisioning shape (az mysql flexible-server create). db-drift v1 can
assess and plan against it but does not execute; say so if
migration.yaml names engine mysql.
