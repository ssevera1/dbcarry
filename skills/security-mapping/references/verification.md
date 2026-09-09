# Verification and probes

Two independent checks stand between apply and cutover. `bq-security
verify` (migrate_security) reads every planned control back from the
target; `bq-security probes --run` (validate, through the
security-validator agent) queries as each mapped principal. Neither
reads `bq-operations.log` or `security-applied.json` as evidence of
anything. Code: `verify_plan`, `probe_set`, `run_probes`, `probes_pass`
in `scripts/db_drift/bq_security.py`; `probe` in `bq_backend.py`.

## Verify protocol

`python "$SCRIPTS" bq-security verify --migration <name>` reads
`security-plan.json` (and `security-applied.json` only for the tag
resource cross-check), opens the backend, and writes
`security-verify.json`: `{"checks": [{"name", "expected", "actual",
"pass"}], "enforcement_active": bool, "pass": bool, "mode",
"migration"}`. It prints every failed check, then `SECURITY VERIFY
PASSED (<mode>): N checks, enforcement active` or `SECURITY VERIFY
FAILED (<mode>): N checks, K failed, enforcement active: <bool>`, and
exits 1 on failure. Checks are sorted by name.

| Check name | Expected | Read back through |
|---|---|---|
| `project_binding:<role>:<member>` | `present` | project IAM policy (live: `gcloud projects get-iam-policy`) |
| `dataset_access:<dataset>:<role>:<member>` | `present` | dataset access list (live: `bq show`; legacy READER, WRITER, OWNER map to the IAM roles) |
| `table_binding:<dataset>.<table>:<role>:<member>` | `present` | table IAM policy (live: `bq get-iam-policy`) |
| `authorized_view:<dataset>:<view>` | `present` | the base dataset's access list |
| `taxonomy` | the display name `dbdrift_<migration>`; actual is the resource name or `missing` | taxonomy list by display name |
| `taxonomy_enforcement` | `FINE_GRAINED_ACCESS_CONTROL` | `describe_taxonomy`; actual lists the activated types or `none` |
| `policy_tag:<tag>` | `present` | the taxonomy's tag list by display name |
| `tag_resource:<tag>` | only emitted when the resource name apply recorded differs from the one read back (project segment ignored) | tag list |
| `tag_reader:<tag>:<member>` | `present` | the tag's IAM policy, role `roles/datacatalog.categoryFineGrainedReader` |
| `tag_reader_extra:<tag>:<member>` | `absent` (a fine-grained reader the plan does not list) | the tag's IAM policy |
| `column_tag:<dataset>.<table>.<column>` | the tag resource name without its project segment | the table schema's `policyTags.names` |
| `row_policy:<dataset>.<table>/<name>` | `GRANT TO (<members sorted>) FILTER USING (<filter, whitespace normalized>)` | the table's row access policy list; members compared as sets, filters compared after whitespace normalization |
| `row_policy_extra:<dataset>.<table>/<name>` | `absent` (a policy on a planned table that the plan does not name) | the table's row access policy list |

Member comparison treats `user:` and `serviceAccount:` alike (bq stores
both as userByEmail) and compares emails without case. A backend error
during a read becomes the check's `actual` text and fails it; one
failed read never hides the others.

`enforcement_active` is true when `FINE_GRAINED_ACCESS_CONTROL` is in
the taxonomy's activated types, and true by definition when no tags
were planned. `pass` is true only when every check passes and
`enforcement_active` is true. The migrate_security playbook completes
the phase only on `pass: true`; live `bq-load` refuses to load without
it.

## Probe protocol

`python "$SCRIPTS" bq-security probes --migration <name>` builds the
set and writes `security-probes.json` with `ran: false`; `--run`
executes it, `--no-source` skips the PostgreSQL counts (statuses are
still compared). Output: `{"mode", "migration", "ran", "pass",
"skipped", "probes": [...]}`, one line per failed probe, then
`SECURITY PROBES PASSED (<mode>): P of N probes` or `FAILED`, exit 1
on failure. An empty set prints `SECURITY PROBES SKIPPED` and records
`pass: false`, because nothing ran and nothing was validated; the
validate playbook treats that as not a pass.

Who is probed: every role in the principal map with a principal; in
live mode only those that also name a `probe_service_account` (the
backend mints a token with `gcloud auth print-access-token
--impersonate-service-account=<sa>` and runs `bq query` with it; the
token appears in argv only and is redacted from the log). Views are not
probed.

| Kind | When | Columns | Expected |
|---|---|---|---|
| `table_denied` | the plan grants the principal no data read role (dataViewer, dataEditor, dataOwner, admin) at table, dataset, or project scope | none | `denied` |
| `row_count` | otherwise, one per table | the columns the role may read on the source, minus restricted columns whose tag it cannot read | `ok`, with a PostgreSQL count where the engines can agree |
| `column_allowed` | per restricted column whose tag lists the principal as a reader | that column | `ok`, same count expectation as the table |
| `column_denied` | per restricted column whose tag does not list the principal | that column | `denied` |

Expected counts come from the source, computed read-only as the
pipeline user (owner or superuser, so RLS does not filter them):

- Table without RLS: `SELECT count(*) FROM "schema"."table"`.
- RLS table with a `TRUE` policy naming the principal: the whole table.
- RLS table with policies but none naming the principal: 0, no query.
- RLS table with predicate policies naming the principal: `SELECT
  count(*) FROM "schema"."table" WHERE <the source USING clauses,
  combined the way the plan combined them>`. Resolved and review
  predicates use the source clause as ground truth, with a note.
- Identity predicate (`SESSION_USER()`): reported without a source
  comparison (`row_count` stays null with `IDENTITY_PROBE_NOTE`).
- RLS table with no policy in the plan at all: no count; the note
  points at the `rls_deny_all` findings.
- Access the source never granted but the plan did (`editor_widens`,
  `widened_by_granularity`, `schema_create_widens`,
  `superuser_mapped`, `principal_shared`): `ok` with no count and a note
  naming the finding; no `column_denied` probe for that table.

A probe passes when the actual status is `ok` or `denied`, equals the
expected status, and, when both counts are known, the counts are equal.
`unevaluable` and `error` never pass. A PostgreSQL count that fails
(for example a predicate reading a session setting) marks that probe
`error` with the message in its note and lets the rest run.

Demo, emulated, from `tests/test_bq_security.py`: `reporting` on
`orders` counts the `region = 'eu'` rows on both sides; `app_rw` on
`orders` sees every row; `app_ro` on `orders` expects and gets 0 (no
policy names it); `app_ro` is denied `customers.email` and `app_rw` is
allowed it; `app_ro` on `customers` selects `id`, `full_name`,
`created_at` and counts the table; `app_ro` on `audit_log` is reported
without comparison. No `table_denied` probes: every mapped role reads
every table at some scope.

## What `unevaluable` means

The backend could not answer, so the probe fails and the verdict must
say why, never pass:

- Emulated: the table is a view or materialized view (no SQL engine);
  or a row policy naming the principal has a predicate outside the
  emulator's subset. The subset is `TRUE`, `FALSE`, `col = 'lit'`, `col
  <> 'lit'`, `col != 'lit'`, `col IN ('a', 'b')`, `col NOT IN (...)`,
  `col = SESSION_USER()`, `AND`, `OR`, `NOT`, and parentheses, where
  `col` is a scalar STRING column of the table; NULL follows SQL
  three-valued logic. A comparison against an INT64 or other non-STRING
  column, `LIKE`, a function call, a number literal, or an identifier
  outside `[A-Za-z0-9_]` is unevaluable, with the predicate quoted in
  the reason. Such a predicate can only be proved live.
- Live: never for a missing `probe_service_account`. A role without one
  gets no probes at all (`probe_set` skips it), and when no role has one
  the run prints `SECURITY PROBES SKIPPED` and records `pass: false`.
  Add the service account to the principal map and re-run.

A denial the plan did not expect, or an `ok` where `denied` was
expected, is a real finding: the target does not enforce what the plan
claims. The security-validator writes it up as a FAIL with the probe's
reason text, never softened.

## What emulated mode proves, and what only a live run proves

| Claim | Emulated | Live (NOT LIVE-TESTED in this repository) |
|---|---|---|
| The plan is a faithful map of the source inventory (flattening, restricted columns, combined predicates, findings) | proved: `plan_security` is pure and identical in both modes | same |
| Apply performs the planned operations in order and is idempotent | proved against the JSON model | proved only if bq, gcloud, and the REST calls accept the rendered forms |
| Every control is present after apply, by read-back | proved against the JSON model | proved against BigQuery, including IAM propagation timing |
| The taxonomy is activated for enforcement | proved as recorded state | proved as BigQuery reports it |
| A principal without the tag reader role cannot read the column | proved as a structural rule the emulator enforces | proved by a real access error from BigQuery |
| A table with policies denies principals no policy names | proved as a structural rule | proved by a real empty result |
| A predicate filters the rows it should | proved for the subset above, against the loaded NDJSON | proved for any predicate BigQuery accepts, including `SESSION_USER()` against real identities |
| Views and authorized views work for their readers | recorded, never evaluated | proved by querying the view |
| The export is complete and faithful (row counts, fingerprints) | proved: fingerprints are computed over the loaded NDJSON by an implementation independent of the PostgreSQL SQL (one limit: NUMERIC beyond about 15 significant digits loses precision in the emulator, which shows as a mismatch, never a false pass) | proved by BigQuery's own aggregates |
| `bq load` accepts the NDJSON and the schema | not proved | proved |
| Quotas, pricing, command syntax, API field names | not proved | proved or refuted on the first run |
| Impersonated probes hold exactly the role's access | not applicable (the emulator checks its own bindings) | proved only if the service account is a member of the role's group and nothing else |

Every report line that carries an emulated number says "(emulated)".
