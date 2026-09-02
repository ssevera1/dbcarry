# Status playbook

Read-only; touches nothing but state.json, migration.yaml, artifacts/.

1. Run `python "$SCRIPTS" state --migration <name> verify`; if invalid,
   report the problems and stop (recovery advice: the state CLI is the
   only writer; restore state.json from git or the decision log).
2. Run `... state show` and read migration.yaml.
3. Report: engine, provider, strategy, each phase with status glyph,
   gate states with approver and time, rollback flag, and existing
   artifacts (list artifacts/ with sizes).
4. Name the exact next command:
   first phase not complete maps assess->/db-drift:assess,
   plan->/db-drift:plan, provision->/db-drift:provision,
   migrate_schema->/db-drift:migrate-schema,
   migrate_data->/db-drift:migrate-data, validate->/db-drift:validate,
   cutover->/db-drift:cutover. A gate blocking the next phase means the
   next step is re-running the phase command that owns the gate (plan or
   cutover). For cutover, gate 2 is checked before the phase starts, so
   re-running always re-presents it. For plan, the gate is checked after
   the phase completes: if plan already shows complete with
   plan_approval unapproved, re-running /db-drift:plan hits its resume
   branch (start-phase fails because plan is done, so it checks the gate
   and re-presents it) rather than re-running the phase's other steps.
   All phases complete: report done.
