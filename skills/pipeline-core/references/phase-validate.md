# Validate playbook

Preconditions: `state verify`; `state start-phase --phase validate`
succeeds.

1. Read migration.yaml, target.json, and state (strategy).
2. Dispatch migration-validator with a prompt containing: the exact
   snapshot commands for both sides (source flags read-only by
   construction; snapshots written to artifacts/checksum-source.json
   and artifacts/checksum-target.json), the diff command with
   --ignore-sequences if and only if strategy is logical_replication,
   the objcount commands for both sides, the workspace path, the
   strategy, and these three sample queries to run on each side with
   identical psql invocations:
   `SELECT count(*), sum(quantity) FROM order_items`
   `SELECT id, email FROM customers ORDER BY id DESC LIMIT 5`
   `SELECT status, count(*) FROM orders GROUP BY status ORDER BY status`
   (For non-demo databases, derive three equivalent queries from the
   three largest tables in inventory.json: an aggregate, an ORDER BY
   LIMIT sample, and a GROUP BY.)
3. Read artifacts/06-validation.md. Verdict VALIDATION PASSED ->
   `state complete-phase --phase validate`; next /db-drift:cutover.
   VALIDATION FAILED -> `state fail-phase --phase validate --reason
   <first failing check>`; tell the user which earlier phase to re-run
   (checksum mismatch: migrate-data; count mismatch: migrate-schema)
   and stop. Never proceed toward cutover on a failed validation.
