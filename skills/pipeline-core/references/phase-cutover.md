# Cutover playbook

Preconditions: `state verify`; validate is complete. Do NOT start the
phase yet; Gate 2 comes first (state enforces this: start-phase fails
until the gate is approved).

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
     then `state start-phase --phase cutover`.
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
