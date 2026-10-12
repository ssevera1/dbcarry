# dbcarry v0.2.0 handoff

For the IT partner team receiving this repository as a starter Claude Code
project.

## What you are receiving

A working prototype of a PostgreSQL to BigQuery migration pipeline whose
distinguishing feature is security parity: it inventories the roles,
grants, column privileges, and row-level security policies on a PostgreSQL
source, plans the equivalent BigQuery controls (IAM bindings, enforced
policy tags, row access policies), applies them before any data lands, and
verifies them by reading the target back. The pipeline is a Claude Code
plugin: slash commands route into playbooks, playbooks call deterministic
Python scripts for everything exact and dispatch subagents for everything
that needs judgment. What has been proven is the **emulated** path: the
whole pipeline runs on a laptop against an emulated BigQuery backend, the
unit suite (1000 tests) covers every v0.2.0 module plus the v0.1.0 state,
config, pg, inventory, and checksum modules and the guard hook (cli,
dump_restore, portable_pg, replicate, and seed_demo have no test module of
their own and are exercised by the demo), and the acceptance block in
`README.md` is where the emulated run of the demo through cutover is
recorded. The
**live** path (`bq`, `gcloud`, the Data Catalog REST API) is written from
documentation, rendered command by command, and mock-tested against a fake
runner, but it is NOT LIVE-TESTED: no GCP credentials existed where this
was built. Your first task is that first live run.

## Prerequisites

- Python 3.10 or newer (developed on 3.13, Windows first; Linux and macOS
  work). The runtime has no third-party dependencies; `pytest` is the only
  dev dependency (`python -m pip install pytest`).
- Claude Code, current release, with permission to run shell commands.
- The portable PostgreSQL 17 toolchain for the demo source:
  `python scripts/dbcarry.py pg ensure-tools` downloads roughly 300 MB
  under `~/.dbcarry/pg/` on first use (override the location with the
  `DBCARRY_HOME` environment variable). The unit suite does not need it.
- Optional, live mode only: the Google Cloud SDK (`gcloud` and `bq` on
  `PATH`) and a sandbox GCP project you can afford to break.

## Open the repository as a Claude Code project

```
git clone <your fork> dbcarry
cd dbcarry
python -m pytest -q -p no:cacheprovider     # expect 1000 passed
claude --plugin-dir .
```

`claude --plugin-dir .` loads the commands, agents, and skills from the
working tree, so `/dbcarry:<verb>` is available immediately and edits to
a playbook take effect on the next command.

What is already configured for you:

- `CLAUDE.md` at the root tells Claude Code what the project is, the nine
  hard rules (five pipeline rules, four security-phase rules), the phase
  and command map, how to run tests and the demo, the prose style, and
  where to look when in doubt. It also tells Claude to use the plugin's
  verbs rather than improvising SQL or `bq` calls.
- `.claude/settings.json` carries two things. First, a permission
  allowlist: `python scripts/dbcarry.py`, `python -m pytest`, read-only
  `git`, and read-only `bq` and `gcloud` verbs (`bq show`, `bq ls`,
  `bq get-iam-policy`, `gcloud auth list`, `gcloud config get-value`,
  `gcloud projects get-iam-policy`, `gcloud data-catalog taxonomies list`).
  Every mutating BigQuery call the pipeline makes goes through
  `scripts/dbcarry.py`. The allow rule matches the relative form
  `python scripts/dbcarry.py ...`, which is what the pipeline runs when
  this checkout is the project directory (the setup above). When the
  plugin is loaded from another directory, the playbooks call
  `python "<plugin root>/scripts/dbcarry.py"` and that absolute form is
  not covered, so expect one permission prompt per script call or add an
  entry for that path. Widen it for hand checks by adding
  entries such as `"Bash(bq query:*)"` or `"Bash(gcloud data-catalog
  taxonomies describe:*)"` to `permissions.allow`; put personal additions
  in `.claude/settings.local.json` and add that file to `.gitignore`.
  Second, a `PreToolUse` hook on `Edit`, `Write`, `MultiEdit`,
  `NotebookEdit`, `Bash`, and `PowerShell` that runs
  `scripts/hooks/guard_state.py`.
- The guard hook refuses (exit 2, reason on stderr) any edit of a
  `state.json` under a `migrations` directory (8.3 short names, symlinks,
  and junctions are resolved first), any shell command that mentions
  `state.json` unless every part of it is a known read-only form (`cat`,
  `grep`, `jq`, `Get-Content`, `git diff`, the state CLI, and the like,
  with no redirect other than to a null device and no pipe into a
  writer), and any command that removes, moves, copies, or writes into a
  `migrations` directory or through a glob that could match `state.json`.
  The practical consequences: use `python scripts/dbcarry.py state
  --migration <name> <verb>` for every state change and `state show` or
  `state verify` to read it, and produce any report whose text quotes
  `state.json` with the Write tool, since a shell heredoc that mentions
  it is refused. The rules and their tests are in `tests/test_hooks.py`.
  The hook is registered twice: `.claude/settings.json` covers this
  checkout used as the project directory, and `hooks/hooks.json` ships
  with the plugin so an install from another directory gets the same
  guard through `${CLAUDE_PLUGIN_ROOT}`.

Migration workspaces live under `migrations/<name>/` in the directory
where you run Claude Code, never inside the plugin, and `migrations/` and
`sandbox/` are gitignored.

## Run the emulated demo end to end

Everything below runs offline. Run the commands from your project
directory inside Claude Code.

1. `/dbcarry:demo setup`. First run downloads the PostgreSQL toolchain,
   then creates the `onprem` instance on 127.0.0.1:55432 (trust auth,
   localhost only, wal_level deliberately left at `replica`) and seeds
   database `retail` with 655,000 rows and the planted findings in
   `demo/scenario.md`. Seeding takes a few minutes.
2. `/dbcarry:init demo-bq`. Answer the interview with engine `postgres`,
   provider `bigquery`, downtime tolerance `flexible`, the demo source
   defaults (127.0.0.1, 55432, retail, postgres, empty password env), and
   for the `bigquery` block mode `emulated`, project `emulated-project`,
   location `US`, dataset map `public: retail`, and an `admin_principal`
   such as `user:operator@example.com`. Init writes
   `migrations/demo-bq/migration.yaml` and runs a read-only connectivity
   check.
3. `/dbcarry:autopilot`. It executes each phase's own playbook and stops
   only at the gates and on failure. Expect these prompts:
   - After assess, the pipeline has written
     `migrations/demo-bq/security/principal-map.yaml` with `app_ro`,
     `app_rw`, and `reporting` and empty principals (`postgres` is listed
     in a comment as a superuser). Fill in one principal per role before
     Gate 1; any `group:` address works in emulated mode, for example
     `group:retail-app-ro@example.com`. A role left empty is planned as
     unmapped (WARNING, no bindings), which is deny-by-default rather than
     an error, but it makes for a dull demo.
   - **Gate 1** (plan approval) presents strategy `bulk_load`, the dataset
     and project, unmapped roles (`postgres` by design), every WARNING (none
     when the three roles are mapped), every translation resolution (none:
     the demo's view bodies and predicates all translate with confidence
     `auto`), and the cost line. Approve it.
   - **Gate 2** (cutover approval) presents the runbook. Approve it. In
     emulated mode the quiesce runs against the demo source, the delta
     check re-reads the now read-only demo source and compares each
     table's count with `loaded` in `load-report.json`, and the smoke
     fingerprints then run against the emulator.
4. When autopilot reports the migration complete, look at the artifacts:

   ```
   migrations/demo-bq/
     migration.yaml
     state.json                          written only by the state CLI
     security/principal-map.yaml
     artifacts/
       decision-log.md                   every transition and gate decision
       01-assessment.md  inventory.json  inventory-notes.md  compatibility-notes.md
       security.json  security-notes.md
       02-plan.md  schema-plan.json  security-plan.json  security-plan.md
       translation-review.json  (translation-resolutions.json when the translator ran)
       bq-apply/  10-datasets.sh  20-tables.sql  30-iam.sh  40-policy-tags.sh
                  50-row-policies.sql  70-identity-notes.md
                  (60-masking-requests.json with column_security: policy_tags_with_masking)
       03-provision.md  target.json
       04-schema-report.md  schema-applied.json  schema-verify.json
       04b-security-report.md  security-applied.json  security-verify.json
       05-data-report.md  load-report.json  export/<schema>.<table>.ndjson.gz
       06-validation.md  fingerprint-source.json  fingerprint-target.json  fingerprint-compare.json
       06b-security-validation.md  security-probes.json
       07-cutover-runbook.md  cutover-source-fingerprint.json  cutover-target-fingerprint.json
                              cutover-fingerprint-compare.json
       bq-operations.log                 one JSON line per backend operation
   ```

   With the three roles mapped, the demo plan holds 12 bindings, 1 policy
   tag (`customers__email`, reader `app_rw`), 5 row access policies, 1
   authorized view, and 13 findings (9 INFO, 4 NOTE, 0 WARNING);
   `bq-security verify` reports 23 checks with enforcement active, and
   the probe set holds 18 probes. `docs/security-mapping.md` walks through
   every one of them.
   One warning even in emulated mode: `artifacts/export/` holds every
   exported row in plain text, including the restricted `email` column
   and the RLS-protected rows. It is staging for the load, not a product.
   `--cleanup` only works on the run that loads: `bq-load run --migration
   demo-bq --cleanup` deletes each table's copy right after its counts
   match, and the autopilot data phase does not pass it. Running `bq-load
   load --cleanup` afterwards loads nothing and deletes nothing, because a
   table that already holds rows is refused (exit 1). Once validation
   passes, delete `artifacts/export/` by hand; the cutover runbook's last
   step says the same.
5. The emulator's state lives under `~/.dbcarry/bq-emulated/demo-bq/`.
   `python scripts/dbcarry.py bq-backend --migration demo-bq status`
   prints it as JSON; `bq-backend --migration demo-bq reset --yes` deletes
   it. `/dbcarry:rollback` does the same through the playbook after you
   type the migration name, and `/dbcarry:demo teardown` removes the
   `onprem` instance after you type `teardown`.

How long it takes: the script steps finish in seconds each (the whole
655,000-row load took 14 s emulated); the subagent phases took 5 min 30 s
(assess, three subagents) and 6 min 1 s (validate, two subagents) in the
v0.2.0 acceptance run recorded in `README.md`, and the gate waits are
yours.

## Switch to live mode

NOT LIVE-TESTED. Every step below is what the code does and what the
documentation says the CLIs accept; nobody has yet watched it succeed.

1. Use a sandbox project with nothing else in it. Enable the BigQuery API
   and the Data Catalog API (`bigquery.googleapis.com`,
   `datacatalog.googleapis.com`); verify the current service names.
2. Authenticate: `gcloud auth login`, then `gcloud config set project
   <sandbox>`. Every `bq` and `gcloud` call runs as the active gcloud
   account, with two exceptions. The Data Catalog REST calls (taxonomy
   and policy tag creation, taxonomy deletion) carry a token from `gcloud
   auth print-access-token` in the Authorization header, and the backend
   scrubs it from every logged response and error. Live probes mint an
   impersonated token (`gcloud auth print-access-token
   --impersonate-service-account=<probe_sa>`) and pass it to `bq query
   --oauth_access_token=`, which `bq-operations.log` redacts. Neither
   token is written to a file. Application default credentials (`gcloud
   auth application-default login`) are not required by the pipeline but
   are convenient for hand checks.
3. IAM the operator identity needs (verify against current documentation):
   - `roles/bigquery.admin` on the project, for datasets, tables, loads,
     table IAM, and row access policy DDL.
   - Permission to create taxonomies and policy tags and set their IAM;
     `roles/datacatalog.admin` covers it.
   - `roles/resourcemanager.projectIamAdmin`, for the project-level
     `roles/bigquery.jobUser` bindings.
   - `roles/iam.serviceAccountTokenCreator` on each probe service
     account.
   - When `gcs_bucket` is set, object write on that bucket for the
     `gcloud storage cp` staging step.
4. Edit `migrations/<name>/migration.yaml`: `mode: live`, `project`,
   `location` (Data Catalog locations are lower case; the backend lowers
   it for you), `dataset_map`, `admin_principal`, optionally `gcs_bucket`.
5. Fill `security/principal-map.yaml` with one Google Group per PostgreSQL
   role (`group:retail-app-ro@example.com` and so on) and, for every role
   you want probed, a `probe_service_account` that is a member of that
   group and nothing else, so the probe holds exactly the role's access.
   The pipeline does not create groups or service accounts; see
   `70-identity-notes.md` after the plan phase for what to create.
6. First live run checklist:
   - Read `skills/provider-bigquery/SKILL.md` and its "Not live-tested"
     banner.
   - Verify every command against `--help` on your installed `bq` and
     `gcloud` before the run: `bq mk --dataset`, `bq update --source`, `bq
     add-iam-policy-binding`, `bq ls --row_access_policies`, `bq load
     --source_format=NEWLINE_DELIMITED_JSON`, `gcloud projects
     add-iam-policy-binding --condition=None`, `gcloud data-catalog
     taxonomies describe`, `gcloud data-catalog taxonomies policy-tags
     add-iam-policy-binding`, and the Data Catalog REST endpoints for
     taxonomy and policy tag creation (gcloud has no create verb for
     them). The exact argv the backend renders is in
     `scripts/db_carry/bq_backend.py` and asserted in
     `tests/test_bq_backend.py`; `artifacts/bq-apply/*.sh` shows the same
     operations as a shell script for reading, not for running.
   - Run phase by phase (`/dbcarry:assess`, `/dbcarry:plan`, and so on)
     rather than autopilot, and read `artifacts/bq-operations.log` after
     each phase.
   - Read the Gate 1 plan slowly. The security plan is the product.
   - After `migrate_security`, open the BigQuery console and confirm by eye
     what `security-verify.json` says: the taxonomy shows enforcement
     active, the tagged column carries the tag, the row access policies
     exist with the right principals.
   - After validate, read `06b-security-validation.md` and
     `security-probes.json`. In live mode a role without a
     `probe_service_account` gets no probes at all, so compare the probe
     set against the mapped roles, and treat `SECURITY PROBES SKIPPED`
     (the file says `skipped: true`, `pass: false`) as a failure. The
     `unevaluable` status belongs to emulated mode: it marks a predicate
     the emulator cannot evaluate, and it never passes.
   - Run `/dbcarry:rollback` at the end. It deletes only the datasets in
     `target.json` and the migration's taxonomy (datasets first, because
     a tag still attached to a column cannot be deleted), after you type
     the migration name. The project-level `roles/bigquery.jobUser`
     bindings are left in place and reported; remove them yourself if the
     sandbox should be clean. Confirm in the console that nothing else
     changed.
   - Delete the staging files. `artifacts/export/*.ndjson.gz` and any
     copies under `gs://<gcs_bucket>/dbcarry/<migration>/` hold every row
     in plain text, restricted columns and RLS-protected rows included.
     Only the run that loads can remove them (`bq-load run --migration
     <name> --cleanup` deletes each table's copies once its counts
     match); a later `bq-load load --cleanup` refuses the already loaded
     tables and deletes nothing. After the fact, remove them by hand:
     the local directory, and `gcloud storage rm -r
     gs://<gcs_bucket>/dbcarry/<migration>/` for the bucket copies.
   - Record what happened in `docs/live-evidence.md` (see task 1 below),
     including every command that needed a fix.

## Where to change what

| Concern | File(s) | Test |
|---|---|---|
| Type map, identifier sanitizing, export expressions | `scripts/db_carry/bq_types.py` | `tests/test_bq_types.py` |
| Mapping rules (how a privilege, policy, or role attribute becomes a BigQuery control) and finding codes | `scripts/db_carry/bq_security.py` (`plan_security` and `_Planner`), restated in `skills/security-mapping/references/mapping-rules.md` and `docs/security-mapping.md` | `tests/test_bq_security.py` |
| Predicate and view-body translator, the auto and review rules | `scripts/db_carry/bq_predicate.py` (`AUTO_FUNCTIONS`, `REVIEW_FUNCTIONS`) | `tests/test_bq_predicate.py` |
| DDL shape, load schemas, view ordering, matview eligibility | `scripts/db_carry/bq_schema.py` | `tests/test_bq_schema.py` |
| Backend command forms (`bq`, `gcloud`, REST), the emulator's enforcement rules | `scripts/db_carry/bq_backend.py` (`LiveBackend`, `EmulatedBackend`) | `tests/test_bq_backend.py` |
| NDJSON export, load, staging cleanup, the controls-before-data guard | `scripts/db_carry/bq_load.py` | `tests/test_bq_load.py` |
| Fingerprint metrics and normalization | `scripts/db_carry/bq_validate.py` | `tests/test_bq_validate.py` |
| Security inventory queries, diff, Postgres role sync | `scripts/db_carry/security.py` | `tests/test_security.py` |
| Phases, strategies, providers, gate positions | `scripts/db_carry/state.py` | `tests/test_state.py` |
| `migration.yaml` defaults and the principal map loader | `scripts/db_carry/config.py` (`BQ_DEFAULTS`) | `tests/test_config.py` |
| Playbooks (what Claude does step by step per phase) | `skills/pipeline-core/references/phase-*.md`, `autopilot.md`, `status.md` | driven by hand in the acceptance run |
| Subagent charters | `agents/*.md` | same |
| Provider contracts | `skills/provider-*/SKILL.md` | same |
| Demo data and planted findings | `scripts/db_carry/seed_demo.py`, `demo/scenario.md`, fixtures `tests/fixtures/demo-inventory.json` and `demo-security.json` | every `demo_*` fixture test |
| Permission allowlist and the guard hook | `.claude/settings.json`, `hooks/hooks.json`, `scripts/hooks/guard_state.py` | `tests/test_hooks.py` |

`CONTRIBUTING.md` describes the workflow for a new mapping rule (code,
rulebook, reviewer prose, test, and a planted demo finding when needed).

## First three iteration tasks

### 1. First live run against a sandbox project

Follow "Switch to live mode" above against a sandbox project and the demo
source, phase by phase, ending with rollback. Acceptance:

- `docs/live-evidence.md` exists and records, per phase: the date, the
  `bq` and `gcloud` versions, every command the backend ran (from
  `bq-operations.log`, tokens redacted), and whether it succeeded as
  rendered or needed a change.
- `security-verify.json` from the live run passes with
  `enforcement_active: true`, and the console screenshots or `bq show`
  output confirming the taxonomy, the tagged column, and the five row
  access policies are attached or quoted.
- The probe set ran with real probe service accounts and every probe
  passed or is explained (identity predicates are reported, not compared).
- Every command that needed a change is fixed in `bq_backend.py` with its
  argv assertion updated in `tests/test_bq_backend.py`, and the "Not
  live-tested" banners in `skills/provider-bigquery/SKILL.md` and
  `README.md` are replaced by a dated "live-tested against <project> on
  <date>" line. The suite stays green.
- Rollback removed only the datasets and the taxonomy; the evidence file
  says what was checked.

### 2. Datastream CDC strategy

Add a `datastream` strategy so a source with low downtime tolerance is
kept in sync until cutover instead of bulk-loaded once. Acceptance:

- `state.STRATEGIES` gains `datastream`. The plan playbook chooses it when
  `downtime_tolerance: low` and the provider is `bigquery`, and records
  the source-side changes it needs (logical decoding, a replication slot,
  a publication) under "Source-side changes requiring approval" at
  Gate 1. When the source cannot support it, the playbook falls back to
  `bulk_load` with a NOTE.
- `migrate_data` provisions the stream through the backend, waits for the
  backfill, and reports lag; cutover waits for zero lag before the
  quiesce, then stops the stream.
- Security still precedes data: the stream is created only after
  `security-verify.json` passes.
- Emulated mode gets an emulation that replays the source's changes into
  the emulator's NDJSON so the suite and the demo cover the strategy
  without GCP; live mode is labeled not live-tested until task 1's
  process is repeated for it.

### 3. Identity automation with Cloud Identity groups

Turn `70-identity-notes.md` into something the pipeline can execute when
asked. Acceptance:

- A new `bq-security identities` verb (or a flag on `plan`) reads the
  principal map and, for every `group:` principal that does not exist,
  renders the Cloud Identity Groups API requests (create group, add the
  probe service account as a member, mirror PostgreSQL memberships as
  nested groups where the plan's identity notes say so) to
  `artifacts/bq-apply/80-identities.json`.
- Execution is opt-in (`--apply`), goes through the backend so the
  emulator can record it and the live backend can log it, and is
  presented at Gate 1 like any other change.
- Nested-group mirroring removes the flattened duplicate bindings the plan
  would otherwise emit, and `bq-security verify` still passes.
- Nothing in the feature creates a `user:` principal or touches a group
  the principal map does not name.

## How to get help

- The design: `docs/superpowers/specs/2026-09-08-postgres-to-bigquery-security-design.md`.
  Sections 7 (mapping model), 11 (backends), 17 (safety), and 18 (known
  limitations) answer most "why does it do that" questions.
- The implementation plan: `docs/superpowers/plans/2026-09-08-postgres-to-bigquery-security.md`,
  with the interfaces and the per-task test lists. Where the plan and the
  code disagree, the code is right and the tests say so.
- The decision log of a run: `migrations/<name>/artifacts/decision-log.md`,
  one line per transition and gate decision, written by the state CLI.
- The operation log of a run: `migrations/<name>/artifacts/bq-operations.log`,
  one JSON line per backend operation, tokens redacted, failed commands
  included with their stderr.
- The security plan of a run, in prose: `artifacts/security-plan.md`; the
  same model explained for a reviewer with the demo as the example:
  `docs/security-mapping.md`.
- The backlog and why each item waited: `docs/ROADMAP.md`.
- Contributor workflow and house style: `CONTRIBUTING.md`.
