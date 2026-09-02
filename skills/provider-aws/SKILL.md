---
name: provider-aws
description: AWS RDS for PostgreSQL target provider for db-drift
---

# Provider: AWS RDS for PostgreSQL

> DOCUMENTED, NOT LIVE-TESTED. Written 2026-09-01 from documentation
> knowledge. Verify against docs.aws.amazon.com/rds before the first
> real run. Cloud resources cost money the moment they exist.

## Prerequisites check

`aws sts get-caller-identity` succeeds; `aws configure get region`
returns the intended region; the caller can create RDS instances and
security groups. Fail the provision phase if any check fails.

## Capability matrix (verify against current docs; dated 2026-09-01)

| Dimension | Support |
|---|---|
| Engine versions | PostgreSQL 13 through 17 |
| hstore extension | Yes |
| Extensions generally | Allowlist; check rds-supported extensions |
| Superuser | No; rds_superuser role |
| Logical replication target | Yes (native subscription supported) |
| Source for logical decoding | Parameter rds.logical_replication=1 plus reboot |
| Roles | CREATE ROLE allowed; no SUPERUSER attribute |

## Provision

Instance id: `dbdrift-<migration>`. Master password from a user-named
env var, expanded by the shell, never echoed.

1. Security group allowing inbound 5432 from the operator IP:
   `aws ec2 create-security-group --group-name dbdrift-<migration>
   --description "db-drift migration target"` then
   `aws ec2 authorize-security-group-ingress --group-name
   dbdrift-<migration> --protocol tcp --port 5432
   --cidr <operator public IP>/32`
2. `aws rds create-db-instance
   --db-instance-identifier dbdrift-<migration> --engine postgres
   --engine-version 17 --db-instance-class db.t4g.micro
   --allocated-storage 20 --master-username dbdrift
   --master-user-password "$env:<PASSWORD_ENV>"
   --publicly-accessible --vpc-security-group-ids <sg id>`
3. `aws rds wait db-instance-available
   --db-instance-identifier dbdrift-<migration>` (minutes; long
   timeout or background)
4. Endpoint: `aws rds describe-db-instances --db-instance-identifier
   dbdrift-<migration> --query
   "DBInstances[0].Endpoint.Address" --output text` -> target.json.
5. Create the database and pre-create inventory roles via psql once
   connected (CREATE DATABASE, CREATE ROLE).

## Connect

Endpoint host, port 5432, user dbdrift, TLS required
(PGSSLMODE=require), password_env as named by the user.

## Teardown

`aws rds delete-db-instance --db-instance-identifier
dbdrift-<migration> --skip-final-snapshot` plus deleting the security
group, after typed confirmation of the migration name. Permanent.

## Cost

db.t4g.micro runs on the order of $0.016/hour plus storage (verify
current pricing). State the estimate in the plan and provision report.

## Known limitations

Managed RDS instances may add their own schemas or objects beyond what
the source ever had. `inventory`, `objcount`, and `checksum snapshot`
filter out only `pg_catalog` and `information_schema`; they do not
currently filter RDS's own additions. An operator running a real
migration against this provider should expect to manually account for
any resulting discrepancy in the schema and data equal-count checks (a
future `--exclude-schema` flag is the real fix; not in scope for
v0.1.0).

## MySQL flavor (engine mysql; execution deferred in v1)

RDS for MySQL exists with the same provisioning shape
(--engine mysql --engine-version 8.4). db-drift v1 can assess and plan
against it but does not execute; say so if migration.yaml names engine
mysql.
