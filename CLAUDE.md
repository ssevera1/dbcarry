# dbcarry

dbcarry migrates an on-prem PostgreSQL database to a cloud target through
eight phases, two human approval gates, and scripts that do every
database-touching operation. Version 0.2.0 adds Google BigQuery as a target
with security parity: the pipeline reads the roles, grants, column privileges,
and row-level security policies on the source and produces, applies, and
verifies the equivalent BigQuery controls (IAM bindings, policy tags, row
access policies). It runs offline through an emulated BigQuery backend and
ships to IT partners as a Claude Code project.

## Claude Code is the runtime

This repository is a Claude Code plugin and a Claude Code project at the same
time. For development, open it with `claude --plugin-dir .` so the commands,
agents, and skills load from the working tree.

- `commands/` are thin routers. Each `/dbcarry:<verb>` reads
  `skills/pipeline-core/SKILL.md` and executes one playbook under
  `skills/pipeline-core/references/`.
- `agents/` do judgment work only: read a schema, narrate a security
  inventory, resolve a flagged SQL translation, try to break a finished
  migration. They never move state and never approve gates.
- `scripts/dbcarry.py` does exact work (inventory, dump, restore, checksums,
  translation, apply, verify). Use its verbs and the plugin's commands rather
  than improvising SQL or `bq` calls. Playbooks call it as
  `python "$SCRIPTS" <verb>` with `$SCRIPTS` = `${CLAUDE_PLUGIN_ROOT}/scripts/dbcarry.py`.
- `skills/provider-*/` hold one provider contract each (provision, connect,
  teardown, cost). `skills/security-mapping/` is the security-phase rulebook.

Migration workspaces live under `migrations/<name>/` in the user's project
directory (the shell CWD) and are never committed to this repository
(`migrations/` and `sandbox/` are gitignored). `sandbox/` is scratch space
for acceptance runs.

## Hard rules

The five pipeline rules, restated from `skills/pipeline-core/SKILL.md`:

1. Never edit `state.json` by hand. Every transition goes through
   `python scripts/dbcarry.py state --migration <name> <verb>`, which validates
   it and logs it; `scripts/hooks/guard_state.py` blocks hand edits mechanically.
2. The source database is read-only. Scripts enforce it through PGOPTIONS;
   the only writes are the ones an approved plan lists.
3. Secrets never appear in output. Only env var names go into `migration.yaml`,
   artifacts, and printed text; never echo passwords, tokens, or connection URLs.
4. Gates run in the main session, never in a subagent. Record the outcome
   with `state approve-gate` or `state decline-gate` before moving on.
5. A phase is complete only after its playbook's verification step passed:
   `start-phase` before work, `complete-phase` after the checks,
   `fail-phase --reason` otherwise.

The four security-phase rules:

6. Never widen access beyond the source. Every binding, tag reader, and row
   policy corresponds to a source privilege. PUBLIC never becomes `allUsers`
   or `allAuthenticatedUsers`.
7. Never apply a review-flagged predicate or view without a recorded
   resolution in `artifacts/translation-resolutions.json`. Gate 1 shows
   every resolution and its rationale.
8. Security controls are applied before any data loads.
9. Verification reads back from the target; the apply log is never trusted.

## Phases and commands

| Phase | Command | Playbook |
|---|---|---|
| (workspace) | `/dbcarry:init` | `phase-init.md` |
| assess | `/dbcarry:assess` | `phase-assess.md` |
| plan (Gate 1) | `/dbcarry:plan` | `phase-plan.md` |
| provision | `/dbcarry:provision` | `phase-provision.md` |
| migrate_schema | `/dbcarry:migrate-schema` | `phase-schema.md` |
| migrate_security | `/dbcarry:security` | `phase-security.md` |
| migrate_data | `/dbcarry:migrate-data` | `phase-data.md` |
| validate | `/dbcarry:validate` | `phase-validate.md` |
| cutover (Gate 2) | `/dbcarry:cutover` | `phase-cutover.md` |

Plus `/dbcarry:rollback`, `/dbcarry:status`, `/dbcarry:autopilot` (every
phase in order, pausing at the gates), and `/dbcarry:demo` (`setup` or
`teardown` of the local demo source).

## CLI verbs

Everything is `python scripts/dbcarry.py <verb> ...`. Workspace-aware verbs
take `--root` (default `.`) and `--migration <name>` and resolve
`<root>/migrations/<name>/`; artifacts go to `<workspace>/artifacts/`.

- v0.1.0: `state`, `pg`, `seed`, `inventory`, `dump`, `restore`, `objcount`,
  `checksum`, `replicate`.
- `security`: `inventory`, `diff`, `sync-roles` (PostgreSQL side).
- `bq-schema`: `translate`, `apply`, `verify`.
- `bq-security`: `plan`, `apply`, `verify`, `probes`.
- `bq-load`: `export`, `load`, `run`. `bq-validate`: `fingerprint`, `compare`.
- `bq-backend`: `status`, `reset --yes` (emulated only).

Read each module's `main` parser for exact flags; do not guess them.

## Tests and the emulated demo

```
python -m pytest -q -p no:cacheprovider
```

The suite is unit tests with no database and must be green before any task
is called done. The emulated demo needs no GCP account:

1. `/dbcarry:demo setup` seeds the local "on-prem" PostgreSQL 17 source
   (127.0.0.1:55432, database `retail`, trust auth) including the planted
   security findings listed in `demo/scenario.md`.
2. `/dbcarry:init <name>` with provider `bigquery` and mode `emulated`.
3. `/dbcarry:autopilot`, approving Gate 1 and Gate 2 when presented.

`bq-backend status --migration <name>` shows what the emulator holds and
`bq-backend reset --migration <name> --yes` clears it. Emulated mode proves
pipeline logic and export fidelity, not BigQuery's behavior: label every
emulated number as emulated.

## Prose style

No em dashes or en dashes anywhere you write: docs, comments, commit
messages, reports, chat. Use a period, a colon, commas, or parentheses;
number ranges use a plain hyphen (`10-15`). Also avoid the related tells:
the "it isn't X, it's Y" construction (state the thing directly), middle-dot
separators, long semicolon chains, and rule-of-three parallelism. Never
alter dashes inside code, string literals, fixtures, data, or quoted material.

## Repository layout

```
.claude-plugin/plugin.json      plugin manifest
.claude/settings.json           permission allowlist and the PreToolUse hook
hooks/hooks.json                the same PreToolUse hook, shipped with the plugin
commands/                       one thin router per verb
agents/                         six subagents (discovery, compatibility, validator, three security)
skills/pipeline-core/           shared rules and the per-phase playbooks
skills/provider-*/              provider contracts (local, gcp, aws, azure, bigquery)
skills/security-mapping/        mapping rules, RLS translation, policy tags, verification
scripts/dbcarry.py              the CLI entrypoint; modules in scripts/db_carry/, hook in scripts/hooks/
demo/scenario.md                the retail demo schema and planted findings
docs/                           spec, plan, handoff, roadmap, security-mapping prose
tests/                          one test module per script module plus the hook
```

## When in doubt, read the spec

- Design: `docs/superpowers/specs/2026-09-08-postgres-to-bigquery-security-design.md`
- Plan: `docs/superpowers/plans/2026-09-08-postgres-to-bigquery-security.md`
- v0.1.0 Postgres path: `docs/superpowers/specs/2026-09-01-db-drift-design.md`.
  Contributor workflow: `CONTRIBUTING.md`. Partner handoff: `docs/HANDOFF.md`.
