# Migrate-schema playbook

Preconditions: `state verify`;
`state start-phase --phase migrate_schema` succeeds.

## Providers: local, gcp, aws, azure

Read migration.yaml (source conn) and artifacts/target.json (target
conn). Build source flags and target flags for the scripts from them.

1. `python "$SCRIPTS" dump schema --out <workspace>/artifacts/schema.dump
   <source flags>`
2. `python "$SCRIPTS" restore pre-data --dump .../schema.dump
   <target flags>`
3. `python "$SCRIPTS" objcount <source flags>` and again with target
   flags. Compare: tables, views, matviews, sequences MUST be equal.
   indexes and constraints are expected to differ here (they arrive
   with post-data during migrate-data); record both values. Note: some
   cloud provider targets add their own schemas or objects that are not
   migration drift (Azure's `azure_sys`, for example); consult the
   target provider's SKILL.md "Known limitations" section before
   treating a count mismatch as a failure.
4. Write artifacts/04-schema-report.md: timing records, both objcount
   JSON lines, the equal/deferred comparison verdict, and any restore
   warnings verbatim.
5. Equal -> `state complete-phase --phase migrate_schema`; next
   /db-drift:security (role sync and the parity diff). Not equal ->
   `state fail-phase` with the first difference as the reason.

## Provider: bigquery

Read migration.yaml (bigquery block) and artifacts/schema-plan.json
(from plan). No target connection flags exist. Live mode is NOT
LIVE-TESTED; label emulated counts as emulated.

1. Precondition: the views section of artifacts/translation-review.json
   is empty. Otherwise `bq-schema apply` refuses and names the views;
   the only way through is /db-drift:plan (the sql-translator step and
   Gate 1).
2. `python "$SCRIPTS" bq-schema apply --migration <name>`: datasets
   (already present), then every table (CREATE TABLE IF NOT EXISTS with
   NOT NULL, NOT ENFORCED keys, CLUSTER BY on key columns), then views
   and materialized views in dependency order. Writes
   artifacts/schema-applied.json (the ops list). Re-running is safe;
   existing objects are kept.
3. `python "$SCRIPTS" bq-schema verify --migration <name>`: lists every
   planned dataset through the backend and compares with the plan.
   Writes artifacts/schema-verify.json (expected {tables, views}, actual
   {tables, views}, missing, mismatched, pass, mode) and prints
   SCHEMA VERIFY PASSED or FAILED; exit 1 on any miss. Materialized
   views count as views; extra objects on the target are not a
   failure.
4. Write artifacts/04-schema-report.md with:
   - mode;
   - the expected and actual counts from schema-verify.json, and the
     missing and mismatched lists or "none";
   - the ops summary from schema-applied.json;
   - every finding from schema-plan.json verbatim, grouped by
     severity. WARNING codes: type_warning, matview_as_view,
     primary_key_dropped, foreign_key_dropped, view_review. INFO
     codes: index_dropped, constraints_dropped, no_primary_key. NOTE
     codes: sequence_dropped, identifier_renamed, default_dropped,
     and the rest;
   - the path of artifacts/bq-apply/20-tables.sql for hand review.
5. SCHEMA VERIFY PASSED -> `state complete-phase --phase migrate_schema`;
   next /db-drift:security. FAILED -> `state fail-phase --phase
   migrate_schema --reason <first missing or mismatched object>`.
