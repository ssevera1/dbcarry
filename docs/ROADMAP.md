# db-drift roadmap

The backlog after v0.2.0, with the reason each item matters, the seam in
the code where it attaches, and why it was deferred. Items are in the
order the handoff suggests taking them; the first three match the tasks in
`docs/HANDOFF.md`.

## 1. Live-test evidence

**Why.** Everything about live BigQuery in this repository is written from
CLI and API documentation and mock-tested against a fake runner. Until a
real run exists, "NOT LIVE-TESTED" is the most important sentence in the
README, and every downstream item below inherits the label.

**Seam.**

- `scripts/db_drift/bq_backend.py` (`LiveBackend`), whose every method
  renders one argv or REST call and records it in the operation log.
- `tests/test_bq_backend.py`, which asserts the exact argv per method.
- `skills/provider-bigquery/SKILL.md`, which carries the banner.
- A new `docs/live-evidence.md` that records, per phase, the commands
  that ran and whether they needed a change.

**Why deferred.** No GCP credentials existed where v0.2.0 was built.

## 2. Datastream CDC strategy

**Why.** The shipped strategy is `bulk_load`: one export, one load, and a
row-count delta check with reload of drifted tables inside the cutover
window. A source with low downtime tolerance needs continuous replication
so the window is a lag check rather than a reload. Datastream is Google's
managed change-data-capture service for PostgreSQL into BigQuery.

**Seam.**

- `state.STRATEGIES` in `scripts/db_drift/state.py`.
- The strategy rule in `skills/pipeline-core/references/phase-plan.md`
  (today the bigquery branch records the downtime tolerance and, when it
  is `low`, emits a NOTE pointing here).
- `phase-data.md` and `phase-cutover.md` for the sync and the zero-lag
  wait.
- `bq_load.run_all` for the backfill path.
- A `Backend` method pair for creating and stopping a stream, so the
  emulator can replay source changes into its NDJSON store and keep the
  demo offline.

**Why deferred.** Datastream needs a real project, logical decoding on the
source, and network reachability; none of that can be proven in emulated
mode, and shipping a strategy whose only test is a mock would have
contradicted the honesty rule the rest of the release follows.

## 3. Identity automation with Cloud Identity groups

**Why.** The plan maps each PostgreSQL role to a principal the operator
names, and `70-identity-notes.md` tells the operator which Google Groups to
create, which probe service account to add to each, and where nesting a
group would mirror a PostgreSQL membership. That is hand work on every
migration, and hand work drifts.

**Seam.**

- `render_apply_scripts` in `scripts/db_drift/bq_security.py`, which
  already renders the identity notes from `plan["identity_notes"]` and
  `plan["principals"]`.
- `bq-security plan --template`, which writes the principal map.
- A new `Backend` method for group creation and membership, so the
  emulator records it and the live backend calls the Cloud Identity
  Groups API.
- Gate 1, which must show group creation as a change like any other.

**Why deferred.** Creating identities is a different trust boundary from
granting them access, and the spec's non-goals kept v0.2.0 on the access
side of it. The membership-flattening rule (7.1) also means nested groups
would duplicate bindings the plan emits directly, so automation has to
remove those duplicates, which needs the live evidence from item 1 first.

## 4. Masking execution through the BigQuery Data Policy API

**Why.** Policy tags with deny-by-default semantics match PostgreSQL column
privileges, so they are the default. Some teams prefer that a reader
without column access sees NULL instead of an error. With `column_security:
policy_tags_with_masking` the plan already emits the request bodies
(`60-masking-requests.json`: one data policy per tag, `ALWAYS_NULL`,
`roles/bigquerydatapolicy.maskedReader` for principals that read the
table but not the column) and states that nothing executes them.

**Seam.**

- `plan["masking"]` in `bq_security.plan_security`.
- The `60-masking-requests.json` renderer in `render_apply_scripts`.
- A new `Backend.create_data_policy` method calling
  `bigquerydatapolicy.googleapis.com` (there is no `bq` or `gcloud` verb
  for it, the same situation as taxonomy creation, solved the same way
  through the REST helper in `LiveBackend`).
- An apply step after tag readers in `apply_plan`.
- A `verify_plan` check that reads the data policy back.

**Why deferred.** No CLI surface, no way to test it in emulated mode
beyond recording the request, and the masking semantics (a masked reader
sees NULL, so `SELECT *` succeeds where PostgreSQL would error) change what
the probes must expect. The planner side is done so a reviewer can see the
shape today.

## 5. Security-barrier view translation

**Why.** PostgreSQL teams implement conditional column visibility with
`security_barrier` views: the view exposes a column only for rows the
caller may see, or exposes different columns to different roles. Policy
tags are per column, not per (column, condition), so the plan flags such
views with the WARNING `security_barrier_view` and leaves them untranslated.

**Seam.** The `security_barrier_views` section of `security.json`
(`scripts/db_drift/security.py`); the `security_barrier_view` finding in
`bq_security.py`; view translation in `bq_schema.translate_schema`, which
already routes view bodies through `bq_predicate.translate` with table
context. A translation would decompose the view's WHERE into a row access
policy on the base table and its column list into a policy tag group, or
emit an authorized view whose body carries the predicate, with a finding
that names which of the two it chose.

**Why deferred.** The decomposition is not always faithful (a view can
join and filter in ways no single row policy expresses), and a translation
that is sometimes wrong is worse than a WARNING that is always honest. The
demo has no security-barrier view, so nothing exercises the path yet.

## 6. Partitioning and clustering advisor

**Why.** The DDL clusters each table by up to four primary key columns and
never partitions. On a large fact table (the demo's `orders` has an
`ordered_at` timestamp and a `region` column that the row policies filter
on) the right partition column cuts query cost and makes the row access
policy cheaper to evaluate.

**Seam.** `translate_schema` in `scripts/db_drift/bq_schema.py`, where
`cluster_by` is chosen and rendered; the `columns` section of
`inventory.json` (types and nullability); the row policy predicates in
`security-plan.json` (a column that every policy filters on is a clustering
candidate). An advisor would add `partition_by` and a widened `cluster_by`
to each table plan with a NOTE per choice, and Gate 1 would show them.

**Why deferred.** A wrong partition choice is expensive to undo after data
lands, and the pipeline has no query history to reason from. Fixed,
predictable DDL was the safer v0.2.0 choice.

## 7. MySQL execution

**Why.** `init` accepts `engine: mysql`, the provider skills name each
cloud's MySQL flavor, and the state machine carries the engine through,
but every execution script (inventory, security inventory, dump, restore,
checksum, replicate, export) is PostgreSQL-only.

**Seam.**

- `scripts/db_drift/cli.py` dispatch.
- The `QUERIES` dictionaries in `inventory.py` and `security.py`. Catalog
  queries would need `information_schema` and `mysql.*` equivalents, and
  MySQL has no row-level security, so the security phase would map only
  grants and column privileges.
- `dump_restore.py` (`mysqldump`).
- `bq_load.export_table`. The `\copy` of `row_to_json` has no MySQL twin,
  so export would go through `SELECT ... INTO OUTFILE` or a client-side
  JSON writer.

**Why deferred.** Two engines double every test fixture, and the security
parity story that defines v0.2.0 depends on PostgreSQL features (RLS,
column ACLs, role inheritance) MySQL lacks in the same form.

## Smaller items, no order

Finding codes added in the post-acceptance review round, for readers of
older reports: `bq_schema` emits `view_resolution_ignored`,
`view_resolution_unjustified`, and `view_resolution_stale`, and
`bq_security` emits `translation_resolution_ignored`,
`translation_resolution_unjustified`, `translation_resolution_stale`,
`translation_resolution_malformed`, `column_grant_unknown_column`, and
`public_rls_denied`; `bq-security verify` gained the `*_extra` checks at
project, dataset, and table scope and `dataset_owner_identity`.

- `--exclude-schema` for `inventory`, `objcount`, and `checksum snapshot`
  so managed Postgres targets that add their own schemas do not show as
  drift (noted in `skills/provider-gcp/SKILL.md` since v0.1.0).
- Per-table dataset mapping. `dataset_map` maps PostgreSQL schemas to
  datasets one to one; a table-level override would let one schema split
  across datasets when access boundaries call for it. Seam:
  `bq_types.dataset_for` and `relation_index` in `bq_security.py`.
- Non-ASCII identifiers on Windows. Every `psql -c` call passes argv in the
  ANSI code page, so a table or column name outside ASCII cannot be
  exported or fingerprinted there; the fix is to pass every statement
  through stdin, which `bq_validate` already does.
- Workforce-pool principals (`principal://`, `principalSet://`) in the
  principal map. The backend's member check accepts six kinds today; the
  seam is `_check_member` in `bq_backend.py` and `canonical_principal`
  in `bq_security.py`, plus the IAM member form in `_member_to_access`.
- Content-level BYTES validation. Fingerprints check null count and byte
  length for BYTES; a cross-engine hash of the base64 text would close
  the gap. Seam: `fingerprint_spec` in `bq_validate.py`.
- Freshness of `security-verify.json` before a load. `bq-load` in live
  mode refuses without a passing verify artifact but does not check its
  age, so after a rollback that recreated the datasets a stale pass file
  would let a load run before the controls are re-applied. The state
  machine orders the phases, so the exposure needs a rollback plus a
  manual `bq-load`; the fix is a timestamp and the taxonomy name in the
  verify artifact, refused when `schema-applied.json` or
  `security-plan.json` is newer. Seam: `security_verified` in
  `bq_load.py`.
- Locking in the emulator. Two `bq-load` runs on one table at the same
  time each see an empty table and both append; the state file is now
  written atomically, but nothing serializes loads. A lock file under the
  emulator root for the duration of a load would close it. Seam:
  `EmulatedBackend.load_ndjson` in `bq_backend.py`.
