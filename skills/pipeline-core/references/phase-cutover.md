# Cutover playbook

Preconditions: `state verify`; validate is complete. Do NOT start the
phase yet; Gate 2 comes first (state enforces this: start-phase fails
until the gate is approved).

## Providers: local, gcp, aws, azure

1. Write artifacts/07-cutover-runbook.md before asking for approval:

   ```markdown
   # Cutover runbook: <name>
   Strategy: <strategy> | Validation: PASSED at <time from 06>

   ## Steps this pipeline will execute
   1. Quiesce source writes. Demo/local source: the pipeline runs
      ALTER DATABASE <db> SET default_transaction_read_only = on
      and terminates idle writer sessions. Real source: the OPERATOR
      stops application writes; the pipeline waits for confirmation.
   2. Final sync. logical_replication: wait for zero replication lag
      (replicate wait-synced), then DROP SUBSCRIPTION on the target,
      then DROP PUBLICATION dbdrift_pub on the source (this listed
      source-side change's cleanup is equally authorized as its
      creation was under Gate 1).
      dump_restore: fresh row counts both sides; on drift, reload data
      inside this downtime window (see Drift handling).
   3. Bump target sequences: for each source sequence, on the target
      SELECT setval('<seq>', <source last_value> + 1000). Margin 1000
      covers writes that raced the final source read.
   4. Smoke queries on the target (the three validation queries).
   5. Record completion. The source is left intact and read-only;
      decommissioning it is a human decision days later, outside this
      pipeline.

   ## Drift handling (dump_restore only)
   TRUNCATE all user tables on the target, re-dump data from the now
   read-only source, restore with --disable-triggers (local/superuser
   targets; on cloud targets re-run restore post-data instead after a
   truncate cascade), refresh matviews, re-verify counts.

   ## Rollback after cutover
   Apps reconnect to the source; revert its read-only setting
   (ALTER DATABASE <db> RESET default_transaction_read_only). The
   target keeps the migrated data for investigation.
   ```

2. GATE 2. Present in the main session: the runbook steps verbatim,
   the validation verdict line from 06-validation.md, and the exact
   write-quiesce consequence. AskUserQuestion: approve cutover or
   decline with reason.
   - Approved: `state approve-gate --gate cutover_approval
     --approved-by <who> --artifact artifacts/07-cutover-runbook.md`,
     then `state start-phase --phase cutover`. Resuming after a failed
     cutover attempt: when `state show` already has cutover_approval
     approved true (a previous attempt failed a step and the quiesce
     was reverted), approve-gate exits 1 because a gate is approved
     once; skip it and run only `state start-phase --phase cutover`,
     which the state machine allows on a failed phase.
   - Declined: `state decline-gate --gate cutover_approval --reason
     <r>` and stop.
3. Execute the runbook exactly, in order, echoing each step's real
   output into artifacts/07-cutover-runbook.md under an "Execution log"
   heading as you go. The quiesce SQL runs via pg.run_sql WITHOUT
   readonly (this is an approved source write, per SKILL.md
   hard rule 2). Terminate sessions:
   SELECT pg_terminate_backend(pid) FROM pg_stat_activity
   WHERE datname = '<db>' AND pid <> pg_backend_pid()
   AND backend_type = 'client backend'.
   The backend_type filter matters: logical replication walsenders also
   appear in pg_stat_activity with datname set to the decoded database,
   and terminating one here would kill the replication connection right
   before step 2 waits for zero lag.
   For logical_replication strategy only, after dropping the subscription
   on the target, drop the publication on the source with:
   `python "$SCRIPTS" replicate drop-publication <source flags> --name dbdrift_pub`
   (dump_restore strategy has no publication to drop).
4. All steps green -> `state complete-phase --phase cutover`. Report:
   the migration is complete, where the target lives (target.json),
   and that /db-drift:rollback remains available for the back-out path.
   Any step fails -> `state fail-phase --phase cutover --reason <r>`,
   immediately revert the quiesce (RESET default_transaction_read_only)
   so the source is writable again, and report loudly.

## Provider: bigquery

Strategy bulk_load. There is no replication to finalize and no
sequence to bump (BigQuery has none; ids were loaded explicitly). The
runbook is a final row-count delta check with reload of drifted tables,
then smoke fingerprints. Live mode is NOT LIVE-TESTED; in emulated mode
every number is labeled emulated.

1. Write artifacts/07-cutover-runbook.md before asking for approval:

   ```markdown
   # Cutover runbook: <name>
   Strategy: bulk_load | Target: <project> (<mode>) | Validation: PASSED at <time from 06>; security validation PASSED at <time from 06b>

   ## Steps this pipeline will execute
   1. Quiesce source writes. Demo/local source: the pipeline runs
      ALTER DATABASE <db> SET default_transaction_read_only = on
      and terminates idle writer sessions (same statement and
      backend_type filter as the PostgreSQL runbook). Real source: the
      OPERATOR stops application writes; the pipeline waits for
      confirmation.
   2. Delta check. Re-read every table's row count on the now read-only
      source:
      python "$SCRIPTS" bq-validate fingerprint --migration <name> --side source --out <workspace>/artifacts/cutover-source-fingerprint.json
      and compare each table's rows with loaded in
      artifacts/load-report.json. Equal everywhere: no drift. A table
      whose count differs drifted after its export: see Drift handling.
   3. Smoke fingerprints. Fingerprint the target:
      python "$SCRIPTS" bq-validate fingerprint --migration <name> --side target --out <workspace>/artifacts/cutover-target-fingerprint.json
      then
      python "$SCRIPTS" bq-validate compare --left <workspace>/artifacts/cutover-source-fingerprint.json --right <workspace>/artifacts/cutover-target-fingerprint.json --out <workspace>/artifacts/cutover-fingerprint-compare.json
      match must be true. Quote the rows and per-column metrics of the
      three largest tables (demo: public.order_items, public.orders,
      public.customers) as the smoke evidence; the compare covers
      every table (live mode: one full scan, see the cost line).
   4. Record completion. The source is left intact and read-only;
      decommissioning it is a human decision days later, outside this
      pipeline. Remove the staging copies, which hold every row in
      plain text: <workspace>/artifacts/export/ and, in live mode with
      gcs_bucket set, the objects under gs://<bucket>/db-drift/<name>/
      (gcloud storage rm -r gs://<bucket>/db-drift/<name>/; NOT
      LIVE-TESTED). No sequence bump.

   ## Drift handling
   Both backends append and bq-load refuses a table that already
   holds rows, so a drifted table must be emptied before its reload.
   Live (NOT LIVE-TESTED): run, through bq --project_id=<project>
   query --use_legacy_sql=false, the statement TRUNCATE TABLE on the
   backticked <project>.<dataset>.<table>; then
   python "$SCRIPTS" bq-load run --migration <name> --table <schema.table>
   (re-exports from the read-only source and loads; exported must equal
   loaded); then
   python "$SCRIPTS" bq-security verify --migration <name>
   must still print SECURITY VERIFY PASSED (the table's policy tags and
   row access policies are expected to survive a TRUNCATE; the verify
   proves it instead of assuming it). Emulated: the emulator runs only
   CREATE statements and cannot empty a table; the demo source was
   read-only throughout, so a differing count there is a pipeline
   defect: fail the phase and report it.

   ## Rollback after cutover
   Apps reconnect to the source; revert its read-only setting
   (ALTER DATABASE <db> RESET default_transaction_read_only). The
   target keeps the migrated data for investigation; /db-drift:rollback
   removes it after typed confirmation.
   ```

2. GATE 2. Present in the main session: the runbook steps verbatim,
   the verdict lines from 06-validation.md and
   06b-security-validation.md, and the exact write-quiesce
   consequence. AskUserQuestion: approve cutover or decline with reason.
   - Approved: `state approve-gate --gate cutover_approval
     --approved-by <who> --artifact artifacts/07-cutover-runbook.md`,
     then `state start-phase --phase cutover`. Resuming after a failed
     cutover attempt: when `state show` already has cutover_approval
     approved true (a previous attempt failed a step and the quiesce
     was reverted), approve-gate exits 1 because a gate is approved
     once; skip it and run only `state start-phase --phase cutover`,
     which the state machine allows on a failed phase.
   - Declined: `state decline-gate --gate cutover_approval --reason
     <r>` and stop.
3. Execute the runbook exactly, in order, echoing each step's real
   output into artifacts/07-cutover-runbook.md under an "Execution log"
   heading as you go. The quiesce SQL runs via pg.run_sql WITHOUT
   readonly (an approved source write, per SKILL.md hard rule 2), with
   the same pg_terminate_backend statement and backend_type filter as
   the PostgreSQL branch.
4. All steps green -> `state complete-phase --phase cutover`. Report:
   the migration is complete, where the target lives (target.json:
   project, location, datasets, taxonomy), and that
   /db-drift:rollback remains available for the back-out path. Any
   step fails -> `state fail-phase --phase cutover --reason <r>`,
   immediately revert the quiesce (RESET default_transaction_read_only)
   so the source is writable again, and report loudly.
