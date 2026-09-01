# Migrate-data playbook

Preconditions: `state verify`;
`state start-phase --phase migrate_data` succeeds. Read the strategy
from `state show`.

## Strategy: dump_restore

1. `python "$SCRIPTS" dump data --out <workspace>/artifacts/data.dump
   <source flags>`
2. `python "$SCRIPTS" restore data --dump .../data.dump --jobs 2
   <target flags>`
3. `python "$SCRIPTS" restore post-data --dump .../schema.dump
   <target flags>` (schema.dump from migrate-schema).
4. Refresh every materialized view in inventory.json on the target:
   SQL `REFRESH MATERIALIZED VIEW <schema>.<name>` per matview.
5. `objcount` on both sides: all six counts MUST now be equal.
6. Write artifacts/05-data-report.md: timing records with throughput
   (bytes/seconds), objcount lines, matviews refreshed, verdict.
7. Equal -> `state complete-phase --phase migrate_data`; next
   /db-drift:validate. Otherwise `state fail-phase` with the difference.

## Strategy: logical_replication

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
   (the one approved source write).
3. `python "$SCRIPTS" replicate create-subscription <target flags>
   --source-host <h> --source-port <p> --source-dbname <d>
   --source-user <u>`
4. `python "$SCRIPTS" replicate wait-synced <target flags>
   --source-host ... (all four) --timeout 900`. This runs long; use a
   long tool timeout or background execution and poll.
5. Refresh matviews on the target (same as the dump_restore branch;
   matview contents do not replicate).
6. `objcount` both sides: all six counts equal.
7. Write artifacts/05-data-report.md: sync progress lines, final lag,
   objcounts, a note that sequences intentionally lag until cutover,
   and that the subscription stays RUNNING until cutover finalizes it.
8. `state complete-phase --phase migrate_data`; next /db-drift:validate.
