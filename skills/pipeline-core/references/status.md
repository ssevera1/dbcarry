# Status playbook

Read-only; touches nothing but state.json, migration.yaml, artifacts/.

1. Run `python "$SCRIPTS" state --migration <name> verify`; if invalid,
   report the problems and stop (recovery advice: the state CLI is the
   only writer; restore state.json from git or the decision log).
2. Run `... state show` and read migration.yaml.
3. Report: engine, provider (for bigquery also the mode, emulated or
   live, and the project), strategy, each of the eight phases (assess,
   plan, provision, migrate_schema, migrate_security, migrate_data,
   validate, cutover) with status glyph, gate states with approver and
   time, rollback flag, and existing artifacts (list artifacts/ with
   sizes). For bigquery, `python "$SCRIPTS" bq-backend status
   --migration <name>` may be quoted for the target's datasets, tables,
   row policies, and taxonomies; it is read-only.
4. Name the exact next command:
   first phase not complete maps assess->/db-drift:assess,
   plan->/db-drift:plan, provision->/db-drift:provision,
   migrate_schema->/db-drift:migrate-schema,
   migrate_security->/db-drift:security,
   migrate_data->/db-drift:migrate-data, validate->/db-drift:validate,
   cutover->/db-drift:cutover. A gate blocking the next phase means the
   next step is re-running the phase command that owns the gate (plan or
   cutover). For cutover, gate 2 is checked before the phase starts, so
   re-running always re-presents it. For plan, the gate is checked after
   the phase completes: if plan already shows complete with
   plan_approval unapproved, re-running /db-drift:plan hits its resume
   branch (start-phase fails because plan is done, so it checks the gate
   and re-presents it) rather than re-running the phase's other steps.
   For bigquery, when the next command is /db-drift:plan and
   security/principal-map.yaml still has empty principals, say so: the
   plan phase will report those roles as unmapped.
   All phases complete: report done.
