---
name: pipeline-core
description: Shared rules for db-drift migration phases, state, gates, and scripts
---

# db-drift pipeline core

db-drift migrates an on-prem PostgreSQL database to a cloud target as a
phased pipeline. Phases: assess, plan, provision, migrate_schema,
migrate_data, validate, cutover. Two human gates: plan_approval (before
provision) and cutover_approval (before cutover).

Engine `mysql` is accepted by init and flows through config and state,
and provider skills note each cloud's MySQL flavor, but v1 execution
scripts are PostgreSQL-only (MySQL equivalents: mysqldump for
dump_restore, binlog replication for the low-downtime strategy). Tell
the user this plainly if they configure mysql.

## Hard rules

1. NEVER edit state.json by hand. Every state change goes through the
   state CLI, which enforces transitions and appends to the decision log.
2. The source database is read-only to this pipeline. Scripts enforce it
   (PGOPTIONS default_transaction_read_only). The only exceptions, each
   allowed only when the approved plan explicitly lists it: creating a
   publication and replication slot (logical_replication strategy),
   quiescing writes at cutover in demo mode, and reverting that quiesce
   during a rollback.
3. Secrets: only env var NAMES appear in migration.yaml, artifacts, and
   output. Never echo passwords or full connection URLs.
4. Gates run in the main session, never in a subagent. Record outcomes
   with `state approve-gate` or `state decline-gate` before moving on.
5. Every phase: `state start-phase` before work, then `state
   complete-phase` on success or `state fail-phase --reason` on failure.
   A phase is not complete until its playbook's verification step passed.

## Workspace resolution

Commands take a migration name argument. When empty: if exactly one
directory exists under ./migrations, use it; otherwise list candidates
and ask. The workspace is ./migrations/<name>/ relative to the user's
project directory (the shell CWD), never inside the plugin.

## Running scripts

$SCRIPTS = ${CLAUDE_PLUGIN_ROOT}/scripts/dbdrift.py, invoked as
`python "$SCRIPTS" <verb> ...`. Read source connection parameters from
migration.yaml and pass them as CLI flags (--host, --port, --dbname,
--user, --password-env). Target connection parameters come from
artifacts/target.json after provision.

Every phase begins with
`python "$SCRIPTS" state --migration <name> verify` and stops on a
non-zero exit.

## Artifacts

Write phase reports to artifacts/ using the numbered names:
01-assessment.md, 02-plan.md, 03-provision.md, 04-schema-report.md,
05-data-report.md, 06-validation.md, 07-cutover-runbook.md. Machine
outputs (inventory.json, target.json, checksums, timings) sit beside
them. Reports state facts with numbers and never claim success without
the verification output that proves it.

## Command map

| Command | Playbook |
|---|---|
| /db-drift:init | references/phase-init.md |
| /db-drift:assess | references/phase-assess.md |
| /db-drift:plan | references/phase-plan.md |
| /db-drift:provision | references/phase-provision.md |
| /db-drift:migrate-schema | references/phase-schema.md |
| /db-drift:migrate-data | references/phase-data.md |
| /db-drift:validate | references/phase-validate.md |
| /db-drift:cutover | references/phase-cutover.md |
| /db-drift:rollback | references/phase-rollback.md |
| /db-drift:status | references/status.md |
| /db-drift:autopilot | references/autopilot.md |
| /db-drift:demo | references/demo.md |
