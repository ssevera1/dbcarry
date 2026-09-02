---
name: provider-gcp
description: GCP Cloud SQL for PostgreSQL target provider for db-drift
---

# Provider: GCP Cloud SQL for PostgreSQL

> DOCUMENTED, NOT LIVE-TESTED. Command sequences and the capability
> matrix were written 2026-09-01 from documentation knowledge. Before
> the first real run: verify each claim against
> cloud.google.com/sql/docs/postgres, and dry-read every command with
> `--help`. Cloud resources cost money the moment they exist.

## Prerequisites check

`gcloud auth list` shows an active account; `gcloud config get-value
project` returns the intended project; the Cloud SQL Admin API is
enabled. Fail the provision phase if any check fails.

## Capability matrix (verify against current docs; dated 2026-09-01)

| Dimension | Support |
|---|---|
| Engine versions | PostgreSQL 13 through 17 |
| hstore extension | Yes (on the supported-extensions list) |
| Extensions generally | Allowlist only; check the supported list |
| Superuser | No; cloudsqlsuperuser role, no superuser-only features |
| Logical replication target | Yes (native subscription supported) |
| Source for logical decoding | Needs flag cloudsql.logical_decoding=on |
| Roles | CREATE ROLE allowed; no SUPERUSER attribute |

## Provision

Instance id: `dbdrift-<migration>`. Region: ask the user. Password for
the postgres user comes from an env var the user names; pass it with
`--root-password` via shell env expansion, never pasted into the
command text in chat.

1. `gcloud sql instances create dbdrift-<migration>
   --database-version=POSTGRES_17 --edition=enterprise
   --tier=db-g1-small --storage-size=10 --region=<region>
   --authorized-networks=<operator public IP>/32
   --root-password="$env:<PASSWORD_ENV>"`
   (takes minutes; use a long timeout or background execution)
2. `gcloud sql databases create <dbname>
   --instance=dbdrift-<migration>`
3. Pre-create inventory roles: for login roles,
   `gcloud sql users create <role> --instance=dbdrift-<migration>
   --password="$env:<ROLE_PASSWORD_ENV>"` (one operator-supplied env
   var per role); NOLOGIN roles via psql `CREATE ROLE <role> NOLOGIN`
   once connected.
4. Endpoint: `gcloud sql instances describe dbdrift-<migration>
   --format="value(ipAddresses[0].ipAddress)"` -> target.json host,
   port 5432, instance id as `instance`.

## Connect

Public IP with authorized network, TLS required
(`sslmode=require`; libpq env PGSSLMODE=require). password_env is the
user-named env var.

## Teardown

`gcloud sql instances delete dbdrift-<migration>` after typed
confirmation of the migration name. This deletes the instance and its
data permanently.

## Cost

db-g1-small runs on the order of $0.05/hour plus storage (verify
current pricing). State the estimate in the plan and provision report.

## Known limitations

Managed Cloud SQL instances may add their own schemas or objects beyond
what the source ever had. `inventory`, `objcount`, and `checksum
snapshot` filter out only `pg_catalog` and `information_schema`; they do
not currently filter Cloud SQL's own additions. An operator running a
real migration against this provider should expect to manually account
for any resulting discrepancy in the schema and data equal-count checks
(a future `--exclude-schema` flag is the real fix; not in scope for
v0.1.0).

## MySQL flavor (engine mysql; execution deferred in v1)

Cloud SQL for MySQL exists with the same provisioning shape
(--database-version=MYSQL_8_4). db-drift v1 can assess and plan against
it but does not execute; say so if migration.yaml names engine mysql.
