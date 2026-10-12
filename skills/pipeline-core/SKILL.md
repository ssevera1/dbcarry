---
name: pipeline-core
description: Shared rules for dbcarry migration phases, state, gates, and scripts
---

# dbcarry pipeline core

dbcarry migrates an on-prem PostgreSQL database to a cloud target as a
phased pipeline. Phases: assess, plan, provision, migrate_schema,
migrate_security, migrate_data, validate, cutover. Two human gates:
plan_approval (before provision) and cutover_approval (before cutover).

Providers local, gcp, aws, and azure are PostgreSQL targets (strategies
dump_restore and logical_replication). Provider bigquery is a Google
BigQuery target (strategy bulk_load) with a mode set in migration.yaml:
`emulated`, a JSON model on local disk that needs no GCP account and is
what the acceptance run proves, or `live`, which shells out to bq and
gcloud. Live mode is NOT LIVE-TESTED: no GCP credentials existed where
this was built. Label every emulated number as emulated in reports and
in chat.

Engine `mysql` is accepted by init and flows through config and state,
and provider skills note each cloud's MySQL flavor, but v1 execution
scripts are PostgreSQL-only (MySQL equivalents: mysqldump for
dump_restore, binlog replication for the low-downtime strategy). Tell
the user this plainly if they configure mysql.

## Hard rules

1. NEVER edit state.json by hand. Every state change goes through the
   state CLI, which enforces transitions and appends to the decision
   log. A PreToolUse hook blocks hand edits, any shell command that
   names state.json outside a read-only form (cat, grep, jq,
   Get-Content, the state CLI), and any command that removes, moves,
   copies, or writes into a migrations directory; a report whose text
   quotes state.json is written with the Write tool, never a heredoc.
2. The source database is read-only to this pipeline. Scripts enforce it
   (PGOPTIONS default_transaction_read_only). The only exceptions, each
   allowed only when the approved plan explicitly lists it: creating a
   publication and replication slot (logical_replication strategy),
   quiescing writes at cutover in demo mode, reverting that quiesce
   during a rollback, and dropping the publication and slot once
   replication is no longer needed (at cutover or during rollback).
3. Secrets: only env var NAMES appear in migration.yaml, artifacts, and
   output. Never echo passwords, tokens, or full connection URLs. bq
   and gcloud use their own credentials; nothing about them is written
   anywhere.
4. Gates run in the main session, never in a subagent. Record outcomes
   with `state approve-gate` or `state decline-gate` before moving on.
5. Every phase: `state start-phase` before work, then `state
   complete-phase` on success or `state fail-phase --reason` on failure.
   A phase is not complete until its playbook's verification step passed.

Security rules, binding every phase that touches access controls:

6. Never widen access beyond the source. Every role, binding, tag
   reader, and row access policy the pipeline applies corresponds to a
   source privilege. PUBLIC never becomes allUsers or
   allAuthenticatedUsers. Anything the target can only express more
   broadly is a WARNING that Gate 1 shows.
7. A review-flagged predicate or view body is applied only after a
   recorded resolution in artifacts/translation-resolutions.json, and
   Gate 1 shows every resolution with its rationale. The apply verbs
   refuse otherwise; never work around them.
8. Security controls are applied before any data lands:
   migrate_security runs on empty tables, before migrate_data.
9. Verification reads back from the target. The apply log,
   security-applied.json, and bq-operations.log are never taken as
   proof; `bq-security verify` and `security diff` are.

## Workspace resolution

Commands take a migration name argument. When empty: if exactly one
directory exists under ./migrations, use it; otherwise list candidates
and ask. The workspace is ./migrations/<name>/ relative to the user's
project directory (the shell CWD), never inside the plugin.

## Running scripts

$SCRIPTS = ${CLAUDE_PLUGIN_ROOT}/scripts/dbcarry.py, invoked as
`python "$SCRIPTS" <verb> ...`. When the plugin checkout is itself the
project directory, use the relative form `python scripts/dbcarry.py`,
which the project's permission allowlist covers.

Connection-flag verbs (inventory, dump, restore, objcount, checksum,
replicate, security): read source connection parameters from
migration.yaml and pass them as CLI flags (--host, --port, --dbname,
--user, --password-env). Target connection parameters come from
artifacts/target.json after provision (PostgreSQL targets only).

Workspace verbs (state, bq-schema, bq-security, bq-load, bq-validate,
bq-backend): take `--root` (default `.`) and `--migration <name>` and
resolve <root>/migrations/<name>/; run them from the user's project
directory so the default --root is right. The bq-* verbs accept --root
and --migration before or after their sub-verb (except `bq-validate
compare`, which takes no workspace flags); for `state` the two flags go
before the sub-verb. Sub-verbs and flags:
`bq-schema translate | apply [--datasets-only] | verify`;
`bq-security plan [--template] [--force] [--review-out PATH] | apply |
verify | probes [--run] [--no-source]`;
`bq-load export | load | run`, each with `[--table schema.name]`, and
load and run also `[--cleanup] [--force]`;
`bq-validate fingerprint --side source|target [--table schema.name]
--out PATH` and `bq-validate compare --left A --right B [--out PATH]`;
`bq-backend status | reset [--yes]`. Read a verb's `--help` before using
any flag not listed here; never guess one.

Target connection for provider bigquery: there is none. Every bq-* verb
reads the bigquery block of migration.yaml (mode, project, location,
dataset_map, principal_map, admin_principal, public_principal,
column_security, binding_granularity, gcs_bucket). artifacts/target.json
carries project, location, mode, datasets, and the taxonomy name for
reports and rollback, and no connection flags.

Every phase begins with
`python "$SCRIPTS" state --migration <name> verify` and stops on a
non-zero exit.

## Artifacts

Write phase reports to artifacts/ using the numbered names:
01-assessment.md, 02-plan.md, 03-provision.md, 04-schema-report.md,
04b-security-report.md, 05-data-report.md, 06-validation.md,
06b-security-validation.md (bigquery only), 07-cutover-runbook.md.
Machine outputs sit beside them: inventory.json, security.json,
target.json, checksums, timings, security-target.json (PostgreSQL
targets), and for bigquery schema-plan.json, security-plan.json,
security-plan.md, translation-review.json,
translation-resolutions.json, bq-apply/, schema-applied.json,
schema-verify.json, security-applied.json, security-verify.json,
load-report.json, export/ (plain-text rows, staging only),
fingerprint-*.json (validate), cutover-source-fingerprint.json,
cutover-target-fingerprint.json, cutover-fingerprint-compare.json
(cutover), security-probes.json, bq-operations.log, and in live mode
bq-work/ (the table schema and dataset access documents that bq
update reads from files).
Reports state facts with numbers and never claim success without the
verification output that proves it.

## Command map

| Command | Playbook |
|---|---|
| /dbcarry:init | references/phase-init.md |
| /dbcarry:assess | references/phase-assess.md |
| /dbcarry:plan | references/phase-plan.md |
| /dbcarry:provision | references/phase-provision.md |
| /dbcarry:migrate-schema | references/phase-schema.md |
| /dbcarry:security | references/phase-security.md |
| /dbcarry:migrate-data | references/phase-data.md |
| /dbcarry:validate | references/phase-validate.md |
| /dbcarry:cutover | references/phase-cutover.md |
| /dbcarry:rollback | references/phase-rollback.md |
| /dbcarry:status | references/status.md |
| /dbcarry:autopilot | references/autopilot.md |
| /dbcarry:demo | references/demo.md |
