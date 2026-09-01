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

Added in a later build step (Task 11). If state says
logical_replication and this section still ends here, stop and tell
the user the build is incomplete.
