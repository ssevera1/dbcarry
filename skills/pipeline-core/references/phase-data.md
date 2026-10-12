# Migrate-data playbook

Preconditions: `state verify`;
`state start-phase --phase migrate_data` succeeds (migrate_security is
complete). Read the strategy from `state show`.

## Strategy: dump_restore (providers local, gcp, aws, azure)

1. `python "$SCRIPTS" dump data --out <workspace>/artifacts/data.dump
   <source flags>`
2. `python "$SCRIPTS" restore data --dump .../data.dump --jobs 2
   <target flags>`
3. `python "$SCRIPTS" restore post-data --dump .../schema.dump
   <target flags>` (schema.dump from migrate-schema).
4. Refresh every materialized view in inventory.json on the target:
   SQL `REFRESH MATERIALIZED VIEW <schema>.<name>` per matview.
5. `objcount` on both sides: all six counts MUST now be equal.
6. Security parity, now that post-data landed (RLS flags and
   policies; default privileges are in security.json but `security
   diff` does not compare them):
   `python "$SCRIPTS" security inventory <target flags> --out
   <workspace>/artifacts/security-target.json`, then
   `python "$SCRIPTS" security diff --left
   <workspace>/artifacts/security.json --right
   <workspace>/artifacts/security-target.json`. match must be true
   (exit 0): zero differences in every section. The only allowances
   are the ones phase-security.md step 4 records: `--ignore-roles` for
   the bypass_rls roles a --no-bypassrls provider cannot reproduce,
   and unsynced_target_roles as information. This is the full parity
   proof that migrate_security deferred.
7. Write artifacts/05-data-report.md: timing records with throughput
   (bytes/seconds), objcount lines, matviews refreshed, a "Security
   parity" section with the diff verdict and the per-section counts,
   and the verdict.
8. Counts equal and diff match -> `state complete-phase --phase
   migrate_data`; next /dbcarry:validate. Otherwise `state fail-phase`
   with the difference.

## Strategy: logical_replication (providers local, gcp, aws, azure)

Precondition: migrate_schema is complete (the subscriber needs the
schema; FK triggers are not fired by the apply workers, so constraints
being present is fine). Also restore post-data BEFORE subscribing so
indexes exist: run
`python "$SCRIPTS" restore post-data --dump .../schema.dump <target
flags>` first if migrate-schema left it deferred (it did; say so in
the report).

1. Verify source wal_level: `python "$SCRIPTS" inventory <source flags>
   --server-only`. If not `logical`:
   - The plan MUST list this change (check 02-plan.md; if it does not,
     stop: the plan needs re-approval).
   - Local/demo source: `python "$SCRIPTS" pg set-conf --name onprem
     --set wal_level=logical`, then `pg stop --name onprem`,
     `pg start --name onprem`, re-verify.
   - Real source: show the operator the required change, wait for their
     confirmation, re-verify.
2. `python "$SCRIPTS" replicate create-publication <source flags>`
   (an approved source write).
3. `python "$SCRIPTS" replicate create-subscription <target flags>
   --source-host <h> --source-port <p> --source-dbname <d>
   --source-user <u>`
4. `python "$SCRIPTS" replicate wait-synced <target flags>
   --source-host ... (all four) --timeout 900`. This runs long; use a
   long tool timeout or background execution and poll.
5. Refresh matviews on the target (same as the dump_restore branch;
   matview contents do not replicate).
6. `objcount` both sides: all six counts equal.
7. Security parity: the same two commands and the same zero-difference
   rule as dump_restore step 6.
8. Write artifacts/05-data-report.md: sync progress lines, final lag,
   objcounts, the "Security parity" section, a note that sequences
   intentionally lag until cutover, and that the subscription stays
   RUNNING until cutover finalizes it.
9. `state complete-phase --phase migrate_data`; next /dbcarry:validate.

## Strategy: bulk_load (provider bigquery)

Precondition: migrate_security completed with SECURITY VERIFY PASSED
(artifacts/security-verify.json has pass true). In live mode bq-load
refuses to load without it; `--force` overrides and is recorded in the
report, and this playbook never passes it. The source stays read-only:
the export is a psql \copy of SELECT row_to_json. Live mode is NOT
LIVE-TESTED; emulated numbers are labeled emulated.

1. `python "$SCRIPTS" bq-load run --migration <name>`. For every table
   in schema-plan.json: exports
   <workspace>/artifacts/export/<schema>.<table>.ndjson.gz (gzipped
   NDJSON, one line per row, bytea as base64, hstore as JSON, session
   TimeZone UTC), loads it through the backend with the table's schema
   as the target reports it (policy tags included), reads the row
   count back, and compares it with the export line count. Live mode
   with gcs_bucket set stages the file through `gcloud storage cp` to
   gs://<bucket>/dbcarry/<name>/<dataset>/ first. Writes
   artifacts/load-report.json and prints one line per table plus the
   verdict; exit 1 when any table fails. Large sources run long: use
   background execution and poll. Both backends append, so a table
   that already holds rows is reported as a failure and never loaded
   again; a partial failure is recovered per table with
   `python "$SCRIPTS" bq-load run --migration <name> --table
   <schema.table>` for each table that did not load (keep every
   printed line; each run overwrites load-report.json). A table left
   with a partial load cannot be emptied by the pipeline: emulated,
   the honest path is /dbcarry:rollback and a fresh migration; live,
   the operator empties the table by hand before the per-table run.
   Operators who want no plain-text staging copies left behind add
   `--cleanup` to the run: each table's local and GCS copies are
   removed once its counts match. The default keeps them for
   investigation until cutover removes them.
2. Read artifacts/load-report.json: tables[] with table, dataset,
   bq_name, exported, loaded, seconds, bytes, pass, reason,
   policy_tagged_columns, notes; security_verify {enforced, verified,
   forced}; staging {export_dir, gcs_bucket, gcs_prefix, cleanup,
   retention}. Every table in schema-plan.json must have exported ==
   loaded and pass true; forced must be false.
3. Write artifacts/05-data-report.md: mode; one row per table with
   exported, loaded, bytes, seconds, and throughput (bytes/second and
   rows/second); totals; policy_tagged_columns per table (the load
   kept the tags); the security_verify block; the staging paths and
   the retention note (plain-text rows, restricted columns and
   RLS-protected rows included; removed at cutover completion); a
   line that materialized views are not refreshed (BigQuery maintains
   them; the emulator never evaluates one) and that sequences do not
   exist on the target.
4. Every table passes -> `state complete-phase --phase migrate_data`;
   next /dbcarry:validate. Otherwise `state fail-phase --phase
   migrate_data --reason <first failing table and its reason>`.
