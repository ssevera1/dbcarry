# Plan playbook

Preconditions: `state verify` passes; `state start-phase --phase plan`
succeeds (assess must be complete).

Resuming after interruption: if `state start-phase --phase plan` fails
because plan is already complete, this is not necessarily an error. Run
`state show` and check `plan_approval`. If it is still unapproved, the
prior session completed step 4 (writing 02-plan.md and calling `state
complete-phase --phase plan`) but was interrupted before step 5's
`state approve-gate` ran, so the gate is stranded rather than the phase
being genuinely done. Skip straight to step 5 (GATE 1), re-presenting
the existing artifacts/02-plan.md verbatim, rather than treating the
start-phase failure as a hard stop. If plan_approval is already
approved, the phase is genuinely done; report that and move on to
provision.

1. Read artifacts/01-assessment.md, artifacts/inventory.json, and
   migration.yaml.

2. Choose the strategy with these rules, in order:
   a. downtime_tolerance is `flexible` -> dump_restore.
   b. downtime_tolerance is `low` -> candidate logical_replication.
      For each table with has_pk false and replica_identity not `f`:
      logical replication cannot apply UPDATE or DELETE for it, and an
      UPDATE or DELETE on the source will error once published. Ask the
      user (AskUserQuestion) whether each such table is insert-only.
      All confirmed insert-only -> logical_replication, with the risk
      recorded in the plan. Any not insert-only -> dump_restore, and the
      plan explains the downtime consequence.
   c. logical_replication additionally requires source wal_level
      `logical`. When inventory says otherwise, the plan MUST list the
      source-side change (set wal_level=logical, restart the source)
      under "Source-side changes requiring approval". Listing a change under "Source-side changes requiring approval" in the Gate 1 approved plan is the only mechanism that ever authorizes any source-side change; that covers this wal_level change and the publication and replication slot the template below always lists for logical_replication.

3. Size the target: data bytes from inventory times 1.3 headroom,
   rounded up. Pick the smallest instance class from the provider
   skill's provision section that fits.

4. Write artifacts/02-plan.md:

   ```markdown
   # Migration plan: <name>
   Date | Source | Target provider | Strategy: <strategy>

   ## Why this strategy
   <the rule that fired and the facts behind it>

   ## Source-side changes requiring approval
   <exact list, or "None". For logical_replication always include:
   publication <dbdrift_pub> FOR ALL TABLES, one replication slot.
   Add wal_level change when needed.>

   ## Target
   <instance class, storage, version, extensions to enable, roles to
   pre-create (from inventory), estimated cost line from provider skill>

   ## Execution outline
   <the remaining phases with what each does under this strategy, and
   the expected downtime window and when it starts>

   ## Rollback plan
   <before cutover: tear down target, drop replication objects, nothing
   on source changed except approved items, which get reverted. After
   cutover: reconnect apps to source, which was left read-only but
   intact; then tear down target after investigation.>

   ## Validation criteria
   <row counts equal; checksums equal (sequences deferred to cutover
   under logical_replication); constraint and index counts equal;
   three sample queries return identical results>
   ```

5. GATE 1. In the main session, present: strategy and why, source-side
   changes (verbatim), target sizing and cost line, rollback summary.
   Ask via AskUserQuestion: approve the plan, or decline with reason.
   - Approved: `state set-strategy --strategy <s>`, then
     `state complete-phase --phase plan`, then
     `state approve-gate --gate plan_approval --approved-by <user email
     if known, else "operator"> --artifact artifacts/02-plan.md`.
   - Declined: `state decline-gate --gate plan_approval --reason <r>`,
     leave the phase in_progress, report what to change and stop.

6. Verification: 02-plan.md exists with all six sections non-empty;
   state shows strategy set and gate approved (approved path only).
