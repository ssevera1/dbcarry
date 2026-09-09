# Validate playbook

Preconditions: `state verify`; `state start-phase --phase validate`
succeeds.

1. Read migration.yaml, target.json, and state (strategy, provider).

## Providers: local, gcp, aws, azure

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
3. The security-validator is NOT dispatched for PostgreSQL targets.
   Role, grant, column-grant, RLS, and policy parity was proven by
   `security diff` with zero differences at the end of migrate_data
   (05-data-report.md, "Security parity"), after the pre-data sections
   passed in 04b-security-report.md. Quote that verdict in the validate
   summary; if 05-data-report.md lacks the section, stop and send the
   user back to /db-drift:migrate-data.
4. Read artifacts/06-validation.md. Verdict VALIDATION PASSED ->
   `state complete-phase --phase validate`; next /db-drift:cutover.
   VALIDATION FAILED -> `state fail-phase --phase validate --reason
   <first failing check>`; tell the user which earlier phase to re-run
   (checksum mismatch: migrate-data; count mismatch: migrate-schema)
   and stop. Never proceed toward cutover on a failed validation.

## Provider: bigquery

Checksums cannot cross engines, so the validator compares engine-neutral
fingerprints (row count plus per-column aggregates, normalized in
Python, floats within a relative tolerance of 1e-9). Two subagents run
and both verdict lines must pass. Emulated mode computes the target
fingerprints in pure Python over the loaded NDJSON, which proves export
fidelity and pipeline logic, not BigQuery's behavior; every report line
says "(emulated)". Live mode is NOT LIVE-TESTED.

2. Dispatch migration-validator with a prompt containing: the workspace
   path, the provider and mode, the strategy bulk_load, and these
   exact commands in place of the checksum, objcount, and sample-query
   commands:
   `python "$SCRIPTS" bq-validate fingerprint --migration <name> --side source --out <workspace>/artifacts/fingerprint-source.json`
   `python "$SCRIPTS" bq-validate fingerprint --migration <name> --side target --out <workspace>/artifacts/fingerprint-target.json`
   `python "$SCRIPTS" bq-validate compare --left <workspace>/artifacts/fingerprint-source.json --right <workspace>/artifacts/fingerprint-target.json --out <workspace>/artifacts/fingerprint-compare.json`
   (exit 1 on any mismatch; the report names table, column, metric,
   and both values; missing_in_left and missing_in_right list tables
   present on one side only), plus
   `python "$SCRIPTS" bq-schema verify --migration <name>` for the
   object counts (tables and views equal the plan), and
   artifacts/load-report.json for the per-table exported and loaded
   counts to restate. Tell it plainly what does not apply here. No
   checksum, objcount, or psql sample queries run. Sample queries
   through bq are not part of v0.2.0 validation (the emulator has no
   SQL engine, and live bq is NOT LIVE-TESTED). Materialized view row
   counts are not compared (BigQuery maintains them, the emulator
   never evaluates a view). Sequences do not exist on the target. Its
   verdict line stays
   VALIDATION PASSED or VALIDATION FAILED in
   artifacts/06-validation.md, with "(emulated)" in emulated mode.
3. Dispatch security-validator with a prompt containing: the workspace
   path, the migration name, the mode, and these exact commands:
   `python "$SCRIPTS" bq-security verify --migration <name>`
   `python "$SCRIPTS" bq-security probes --migration <name> --run`
   `python "$SCRIPTS" bq-backend status --migration <name>`
   (add `--root <r>` to each when the workspace is not under
   ./migrations). probes --run builds one probe per mapped role and
   table (row_count, column_allowed, column_denied, table_denied),
   computes the expected counts on the source read-only, runs each as
   the principal (emulated: the model; live: impersonating the role's
   probe_service_account, and a role without one gets no probes), and
   writes artifacts/security-probes.json. An empty probe set or an
   unevaluable probe never passes. The agent writes
   artifacts/06b-security-validation.md with the verdict line
   SECURITY VALIDATION PASSED or SECURITY VALIDATION FAILED.
4. Read both reports. VALIDATION PASSED and SECURITY VALIDATION PASSED
   -> `state complete-phase --phase validate`; next /db-drift:cutover.
   Either FAILED -> `state fail-phase --phase validate --reason <first
   failing check>`; tell the user which earlier phase the failure
   points at (a fingerprint mismatch or a load count: migrate-data;
   a missing object: migrate-schema; a failed security check or probe:
   security, after fixing the principal map or a resolution through
   plan) and stop. Never proceed toward cutover on a failed validation.
