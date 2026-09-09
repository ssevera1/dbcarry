---
name: security-mapping
description: PostgreSQL to BigQuery security parity rulebook for db-drift, roles to principals, grants to IAM, column privileges to policy tags, row-level security to row access policies, and how every control is verified
---

# Security mapping (PostgreSQL to BigQuery)

The rulebook the plan, migrate_security, and validate playbooks follow
and the security-analyst, sql-translator, and security-validator agents
read. The code is the authority: `scripts/db_drift/bq_security.py`
(planner, apply scripts, apply, verify, probes), `bq_predicate.py`
(translator), `bq_backend.py` (emulated and live backends), and
`security.py` (inventory, diff, role sync). This file and its references
restate the code; where they disagree, the code wins and the document
gets fixed.

Everything about live BigQuery here is NOT LIVE-TESTED (no GCP
credentials existed where this was built). The emulated mode is what the
acceptance run proves; see `skills/provider-bigquery/SKILL.md`.

## The model in ten points

1. The source of truth is the PostgreSQL security inventory
   (`artifacts/security.json`): roles and attributes, memberships (with
   the PostgreSQL 16 per-membership INHERIT option), schema, relation,
   and column privileges, RLS flags, policies with their USING and WITH
   CHECK text, default privileges, and security-barrier views. It comes
   from read-only catalog queries and reads no data rows.
2. Each role maps to exactly one Google principal named by the operator
   in `security/principal-map.yaml`: `user:`, `group:`,
   `serviceAccount:`, `domain:`, or `specialGroup:` (the last only for
   projectOwners, projectReaders, projectWriters). An unmapped role
   receives nothing and a WARNING listing what it would have received.
   PUBLIC maps to `bigquery.public_principal` or stays unmapped; it
   never becomes `allUsers` or `allAuthenticatedUsers`, which the
   backend refuses in every spelling.
3. Memberships are flattened. A role holds the union of its own grants
   and, transitively, the grants of every group it inherits from (the
   membership's own inherit option on PostgreSQL 16 and later, the
   role's INHERIT attribute before that). PUBLIC's grants are folded into
   every role. A membership without inheritance is left out and flagged.
4. Relation privileges become IAM bindings. SELECT on a table, view, or
   materialized view gives `roles/bigquery.dataViewer` on it; any of
   INSERT, UPDATE, DELETE, TRUNCATE on a table gives
   `roles/bigquery.dataEditor` instead (never both), with WARNING
   `editor_widens` when the role lacks any of SELECT, INSERT, UPDATE,
   DELETE; USAGE on a schema with no relation grant in it gives
   `roles/bigquery.metadataViewer` on the dataset; CREATE on a schema
   gives dataEditor on the dataset with a WARNING. Every member with a
   binding gets `roles/bigquery.jobUser` on the project once.
   With `binding_granularity: auto` a role moves to dataset scope only
   when the member holds it on every relation of that dataset.
5. Column privileges become policy tags. For each table, a column that
   some reader of the table cannot read is restricted; restricted
   columns with the same allowed-reader set share one tag named
   `<table>__<first_column>` (plus `_and_<k>_more`) under the taxonomy
   `dbdrift_<migration>`, created with `activatedPolicyTypes:
   FINE_GRAINED_ACCESS_CONTROL`, which is what makes tags enforced.
   Each allowed reader's principal gets
   `roles/datacatalog.categoryFineGrainedReader` on the tag; the tag is
   attached through the table schema.
6. Row-level security becomes one row access policy per (RLS table,
   mapped role that can read it), named `rls_<role>`, granted to the
   role's principal, with the predicate `(perm_1) OR (perm_2) ... AND
   (restr_1) AND (restr_2) ...` combined from the source policies that
   apply to the role (named directly, through PUBLIC, or through a group
   it inherits from) with command SELECT or ALL. A single permissive
   predicate stands as written. No applicable permissive policy means no
   BigQuery policy and therefore no rows, which matches the source.
   Bypass roles (BYPASSRLS, the owner when RLS is not forced, a mapped
   superuser) get `rls_bypass_<role>` with `FILTER USING (TRUE)`. An RLS
   table where no mapped role gets a policy receives `rls_deny_all`
   with `FILTER USING (FALSE)` for `admin_principal`, because a BigQuery
   table with no policy at all shows every row.
7. Predicates and view bodies pass through the rule-based translator.
   An `auto` result applies as is. A `review` result blocks apply until
   the sql-translator agent records a resolution in
   `artifacts/translation-resolutions.json` and the plan is run again;
   the resolution shows at Gate 1 with its rationale.
8. A view a role can read without reading every base table becomes an
   authorized view entry on each such base dataset, which is how
   BigQuery lets a view work without base access.
9. Apply runs in a fixed, idempotent order: taxonomy, policy tags, tag
   readers, project bindings, dataset access entries (bindings and
   authorized views), table bindings, column tag attachment, row access
   policies. It refuses to start while any row policy is at `review`.
   Controls land on empty tables: migrate_security precedes
   migrate_data, and in live mode `bq-load` refuses to load without a
   passing `security-verify.json`.
10. Verification never trusts the apply log. `bq-security verify` reads
    every binding, authorized view, the taxonomy's activation, every
    tag, reader, and column attachment, and every row policy's members
    and filter back from the target, and fails on extra readers or
    extra row policies on planned resources. Probes then query as each
    mapped principal and compare status, and row counts where the two
    engines can agree, with what the plan promised and the source holds.

## Artifacts

All under `<workspace>/artifacts/` unless noted. Every JSON file is
written with indent 2, UTF-8, and a trailing newline. The files
`bq-security` writes use LF; `security.json` and
`security-target.json` (from `security inventory`) and
`translation-review.json` as `bq-schema translate` leaves it take the
platform's line ending (CRLF on Windows).

| File | Written by | Meaning |
|---|---|---|
| `security.json` | `security inventory --out` (assess, through security-analyst) | The PostgreSQL security inventory, spec section 6 shape; input to every plan |
| `security/principal-map.yaml` (workspace root) | `bq-security plan --template` (assess), then the operator | One principal per non-system, non-superuser role, plus an optional `probe_service_account`; empty principal means unmapped |
| `security-plan.json` | `bq-security plan` only | The machine plan: principals, bindings, policy_tags, row_policies, authorized_views, identity_notes, nesting_notes, masking, findings, effective privileges per role, context_tables. Apply never rewrites it: the taxonomy and tag resource names land in `security-applied.json`, and verify injects them into the plan in memory for the `tag_resource` cross-check |
| `security-plan.md` | `bq-security plan` | The same plan as tables for Gate 1 and the reports |
| `translation-review.json` | `bq-schema translate` (`views`) and `bq-security plan` (`policies`) | Review-flagged items for the sql-translator: per item the source SQL, the partial auto translation, the notes, and the table context. Empty `policies` means nothing blocks apply |
| `translation-resolutions.json` | the sql-translator agent | `{"views": {"schema.name": {"sql", "rationale"}}, "policies": {"schema.table/policy": {"sql", "rationale"}}}`; read by both translate and plan on the next run |
| `security-applied.json` | `bq-security apply` | The taxonomy resource name, tag name to resource name map, operation count, mode. Verify uses it only to cross-check tag resource names, never as proof of existence |
| `security-verify.json` | `bq-security verify` | `checks` (name, expected, actual, pass), `enforcement_active`, `pass`, mode. Live `bq-load` refuses without `pass: true` |
| `security-probes.json` | `bq-security probes` (`--run` executes) | The probe set with expected and, after a run, actual results and per-probe pass; `ran`, `pass`, `skipped` at the top |
| `bq-apply/30-iam.sh`, `40-policy-tags.sh`, `50-row-policies.sql`, `60-masking-requests.json` (masking mode only), `70-identity-notes.md` | `bq-security plan` | The plan rendered as commands for hand review; apply performs the same operations through the backend. 50 comments out review policies; 60 is never executed; 70 is documentation (memberships, principals, identity predicates, probe setup). `10-datasets.sh` and `20-tables.sql` come from `bq-schema translate` |
| `bq-operations.log` | both backends | One JSON line per mutating operation and per failed command, tokens redacted; the dry record of what happened |
| `bq-work/` (live only) | LiveBackend | Schema and access documents `bq update` reads from files |
| `security-target.json` (Postgres targets) | `security inventory --out` on the target | The target inventory that `security diff` compares with `security.json` |
| `04b-security-report.md`, `06b-security-validation.md` | the migrate_security playbook, the security-validator agent | Phase reports; every table header says "(emulated)" in emulated mode |

## Invariants

1. Never widen access. Every binding, tag reader, and row policy traces
   to a source privilege through the flattening rules above. Anything
   BigQuery can only express more broadly is emitted with a WARNING
   (`editor_widens`, `schema_create_widens`, `widened_by_granularity`,
   `view_write_widens`, `view_column_grant_widens`, `superuser_mapped`)
   so Gate 1 sees it. PUBLIC never becomes an everyone-principal.
2. Review before apply. A review-flagged predicate or view body is
   never applied. `bq-security apply` and `bq-schema apply` refuse
   until `translation-resolutions.json` carries a resolution and the
   plan has been regenerated; each resolution is a NOTE at Gate 1.
3. Controls before data. migrate_security runs before migrate_data,
   apply attaches tags and creates row policies on empty tables, and
   live `bq-load` checks `security-verify.json` (`--force` overrides
   and is recorded in the load report).
4. Verify by read-back. The verify verdict comes from reading the
   target back (the apply log plays no part); the probe verdict comes
   from queries run as the principals. `unevaluable` and `error` never
   count as a pass, and an empty probe set never passes.

Every judgment the planner makes is a finding with a severity (WARNING,
INFO, NOTE), a subject, a message, and an action. The plan phase
presents every WARNING at Gate 1; only `translation_review` blocks
apply. The full code list is in `references/mapping-rules.md`.

## Command sequence

`$SCRIPTS` is `${CLAUDE_PLUGIN_ROOT}/scripts/dbdrift.py`. `--root` and
`--migration` are accepted before or after the verb on every `bq-*`
module. The `security` module takes connection flags instead
(`--host`, `--port`, `--dbname`, `--user`, `--password-env`), as
`inventory` does.

BigQuery target, by phase:

- assess: `python "$SCRIPTS" security inventory --host <h> --port <p>
  --dbname <d> --user <u> [--password-env <e>] --out
  <workspace>/artifacts/security.json` (the security-analyst's one
  database access), then `python "$SCRIPTS" bq-security plan --migration
  <name> --template` to write `security/principal-map.yaml`. When the
  file already exists the command refuses with exit 1: that is the
  operator's file, and `--force` (overwrite) is for the operator alone,
  never for a playbook. The operator fills the map in before Gate 1.
- plan: `python "$SCRIPTS" bq-schema translate --migration <name>`, then
  `python "$SCRIPTS" bq-security plan --migration <name>` (add
  `--review-out <path>` to write the review items elsewhere). When
  `translation-review.json` has any view or policy, dispatch the
  sql-translator agent, then run both again so the resolutions take
  effect. Gate 1 in the main session.
- provision: `python "$SCRIPTS" bq-schema apply --migration <name>
  --datasets-only`.
- migrate_schema: `python "$SCRIPTS" bq-schema apply --migration <name>`,
  then `python "$SCRIPTS" bq-schema verify --migration <name>`.
- migrate_security: `python "$SCRIPTS" state --migration <name>
  start-phase --phase migrate_security`; `python "$SCRIPTS" bq-security
  apply --migration <name>` (writes `security-applied.json`); `python
  "$SCRIPTS" bq-security verify --migration <name>` (writes
  `security-verify.json`, prints `SECURITY VERIFY PASSED` or `FAILED`,
  exit 1 on any miss); write `04b-security-report.md`; then `state
  complete-phase --phase migrate_security` only on a pass, otherwise
  `state fail-phase --phase migrate_security --reason <first failed
  check>`.
- migrate_data: `python "$SCRIPTS" bq-load run --migration <name>`
  (live mode refuses without a passing verify).
- validate: the security-validator runs `python "$SCRIPTS" bq-security
  probes --migration <name> --run` (`--no-source` skips the PostgreSQL
  count queries; statuses and the fixed expectations, 0 rows where no
  policy names the principal, are still compared) and writes
  `06b-security-validation.md`; the migration-validator runs
  `bq-validate fingerprint --migration <name> --side source --out
  <path>`, the same with `--side target`, then `bq-validate compare
  --left <a> --right <b>`.
- rollback: the provider skill's Teardown section, after typed
  confirmation.

Postgres target (local, gcp, aws, azure), migrate_security only:

1. `python "$SCRIPTS" security sync-roles --from
   <workspace>/artifacts/security.json --host <th> --port <tp> --dbname
   <d> --user <u> [--password-env <e>]`, with `--no-bypassrls` for every
   provider except local (BYPASSRLS needs superuser). `--dry-run` prints
   the statements without executing.
2. `python "$SCRIPTS" security inventory <target flags> --out
   <workspace>/artifacts/security-target.json`.
3. `python "$SCRIPTS" security diff --left
   <workspace>/artifacts/security.json --right
   <workspace>/artifacts/security-target.json` (`--ignore-roles` skips
   role attribute differences; memberships are still compared). Exit 0
   with `"match": true` completes the phase; anything else fails it with
   the first difference as the reason.

## References

- `references/mapping-rules.md`: spec sections 7.1 to 7.5 as rule
  tables, and every finding code the planner emits with its severity.
- `references/rls-translation.md`: the translator's rules with one
  worked example each, the combined-predicate rule, the SESSION_USER()
  caveat, and what a review result means for the sql-translator.
- `references/policy-tags.md`: taxonomy activation, tag grouping, the
  fine-grained reader role, the `SELECT *` consequence, masking, and the
  no-column-level-write limit.
- `references/verification.md`: the verify check names, the probe
  protocol, what `unevaluable` means, and what emulated mode proves
  against what only a live run can prove.
