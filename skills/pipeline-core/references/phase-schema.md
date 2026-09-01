# Migrate-schema playbook

Preconditions: `state verify`;
`state start-phase --phase migrate_schema` succeeds.

Read migration.yaml (source conn) and artifacts/target.json (target
conn). Build source flags and target flags for the scripts from them.

1. `python "$SCRIPTS" dump schema --out <workspace>/artifacts/schema.dump
   <source flags>`
2. `python "$SCRIPTS" restore pre-data --dump .../schema.dump
   <target flags>`
3. `python "$SCRIPTS" objcount <source flags>` and again with target
   flags. Compare: tables, views, matviews, sequences MUST be equal.
   indexes and constraints are expected to differ here (they arrive
   with post-data during migrate-data); record both values.
4. Write artifacts/04-schema-report.md: timing records, both objcount
   JSON lines, the equal/deferred comparison verdict, and any restore
   warnings verbatim.
5. Equal -> `state complete-phase --phase migrate_schema`; next
   /db-drift:migrate-data. Not equal -> `state fail-phase` with the
   first difference as the reason.
