# Plan playbook

Preconditions: `state verify` passes; `state start-phase --phase plan`
succeeds (assess must be complete).

Resuming after interruption: if `state start-phase --phase plan` fails
because plan is already complete, this is not necessarily an error. Run
`state show` and check `plan_approval`. If it is still unapproved, the
prior session already ran `state set-strategy` and `state
complete-phase --phase plan` (step 8's first two Approved sub-steps)
but was interrupted before `state approve-gate` ran, so the gate is
stranded rather than the phase being genuinely done. Skip straight to
step 8 (GATE 1), re-presenting the existing artifacts/02-plan.md
verbatim, rather than treating the start-phase failure as a hard stop.
On approval this time, call ONLY `state approve-gate`: do not repeat
`state set-strategy` or `state complete-phase`, since both now fail
cleanly (strategy is no longer settable once plan is complete, and a
complete phase cannot be completed again) precisely because the prior
session already did them. If plan_approval is already approved, the
phase is genuinely done; report that and move on to provision.

1. Read artifacts/01-assessment.md, artifacts/inventory.json,
   artifacts/security.json, and migration.yaml.

## Providers: local, gcp, aws, azure

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

4. Security mapping inputs, from security.json: the roles
   `security sync-roles` will create in migrate_security (every role
   except postgres, superusers, and pg_* roles) with LOGIN, INHERIT,
   and BYPASSRLS attributes and their memberships; the RLS tables with
   policy counts and the column-level grants, all of which pg_dump
   carries (grants with pre-data, RLS flags and policies with
   post-data). On every provider except local, BYPASSRLS is not
   reproduced (sync-roles runs with --no-bypassrls); name each
   affected role.

## Provider: bigquery

2. Strategy is `bulk_load` by rule: every table is exported as NDJSON
   from the read-only source and loaded through the backend. Record
   downtime_tolerance in the plan; when it is `low`, add a NOTE that
   bulk_load needs a write freeze from the final export to cutover and
   that continuous replication (Datastream) is a documented next step
   in docs/ROADMAP.md and is not shipped in v0.2.0.
3. Read <workspace>/security/principal-map.yaml (written by assess).
   For every role whose principal is empty, ask the operator
   (AskUserQuestion) for a principal now or confirm that it stays
   unmapped, and edit the file with the answers. Recommended
   principal types are `user:`, `group:`, and `serviceAccount:`;
   `domain:` and `specialGroup:` are accepted; allUsers and
   allAuthenticatedUsers are refused by the planner.
4. Translate and plan:
   `python "$SCRIPTS" bq-schema translate --migration <name>`
   `python "$SCRIPTS" bq-security plan --migration <name>`
   The first writes artifacts/schema-plan.json,
   artifacts/bq-apply/10-datasets.sh, artifacts/bq-apply/20-tables.sql,
   and the views section of artifacts/translation-review.json. The
   second writes artifacts/security-plan.json,
   artifacts/security-plan.md, artifacts/bq-apply/30-iam.sh,
   40-policy-tags.sh, 50-row-policies.sql, 60-masking-requests.json
   (masking mode only), 70-identity-notes.md, and the policies section
   of translation-review.json. Both print their WARNING findings;
   bq-security plan exits 1 on a malformed principal. Neither touches
   the target.
5. Read artifacts/translation-review.json. If views or policies is
   non-empty, dispatch the sql-translator subagent with: the workspace
   path, the review file path, the output path
   artifacts/translation-resolutions.json and its shape
   {"views": {"schema.name": {"sql", "rationale", "source_sql"}},
   "policies": {"schema.table/policy": {"sql", "rationale",
   "source_sql"}}} (source_sql copied from the review item, so a
   stale resolution is rejected), and the path
   ${CLAUDE_PLUGIN_ROOT}/skills/security-mapping/references/rls-translation.md.
   Write its JSON reply verbatim to that path (the agent has no write
   tool). Then run both step 4 commands again: they
   pick up the resolutions (a resolved item shows confidence
   `resolved`; a null resolution keeps it at `review`, and the apply
   verbs will refuse it, which is the intended outcome until a human
   decides). Read translation-review.json again and list what remains.
6. Cost line, from the Cost section of
   ${CLAUDE_PLUGIN_ROOT}/skills/provider-bigquery/SKILL.md: emulated is
   free; live states <data bytes from inventory> of active storage per
   GB-month plus roughly one full scan for validation at on-demand
   query pricing, each marked "verify current pricing". When mode is
   live, the line ends with: "live mode is NOT LIVE-TESTED in this
   repository; the first live run is expected to find differences
   (provider-bigquery SKILL.md banner)".

## All providers

7. Write artifacts/02-plan.md:

   ```markdown
   # Migration plan: <name>
   Date | Source | Target provider (bigquery: and mode) | Strategy: <strategy>

   ## Why this strategy
   <the rule that fired and the facts behind it; bigquery: the
   downtime_tolerance NOTE when it is low>

   ## Source-side changes requiring approval
   <exact list, or "None". For logical_replication always include:
   publication <dbcarry_pub> FOR ALL TABLES, one replication slot.
   Add wal_level change when needed. bulk_load: "None" (the export is
   read-only); the demo-mode quiesce at cutover is hard rule 2's
   standing exception.>

   ## Target
   <PostgreSQL targets: instance class, storage, version, extensions to
   enable, roles to pre-create (from inventory), estimated cost line
   from provider skill. bigquery: project, location, datasets with
   their source schemas (schema-plan.json datasets), the taxonomy
   dbcarry_<migration>, instance class "on-demand (serverless)", the
   cost line, and for mode live the NOT LIVE-TESTED statement from
   step 6>

   ## Security mapping summary
   <PostgreSQL targets: the roles sync-roles will create with their
   attributes and memberships, BYPASSRLS roles not reproduced
   (non-local), RLS tables and policy counts, column-level grants, and
   the two parity checks (pre-data sections in migrate_security, full
   zero-difference diff at the end of migrate_data).
   bigquery, from security-plan.json and schema-plan.json: the
   principals table (role -> principal or "(unmapped)"); counts of
   bindings, policy tags, row access policies, authorized views; every
   WARNING finding from both plans verbatim (code, subject, message,
   action); every identity note; every resolution from
   translation-resolutions.json with its rationale, and any item still
   at review; the line that controls are applied in migrate_security
   before any data loads.>

   ## Execution outline
   <the remaining phases with what each does under this strategy, and
   the expected downtime window and when it starts. bulk_load: provision
   creates datasets; migrate_schema creates tables and views;
   migrate_security applies and verifies the controls on empty tables;
   migrate_data exports and loads; validate compares fingerprints and
   runs the security probes; cutover quiesces the demo source, checks
   row-count deltas, runs smoke fingerprints; no sequence bump>

   ## Rollback plan
   <before cutover: tear down target, drop replication objects, nothing
   on source changed except approved items, which get reverted.
   bigquery: delete the datasets named in target.json and the taxonomy
   (emulated: bq-backend reset --yes); nothing on the source changed.
   After cutover: reconnect apps to source, which was left read-only but
   intact; then tear down target after investigation.>

   ## Validation criteria
   <PostgreSQL targets: row counts equal; checksums equal (sequences
   deferred to cutover under logical_replication); constraint and index
   counts equal; three sample queries return identical results;
   security diff zero differences. bigquery: fingerprint compare match
   on every table; bq-schema verify counts equal the plan; SECURITY
   VERIFY PASSED with enforcement active; probes ran and passed with no
   unevaluable probe; verdict lines VALIDATION PASSED and SECURITY
   VALIDATION PASSED>
   ```

8. GATE 1. In the main session, present: strategy and why, source-side
   changes (verbatim), target sizing and cost line (bigquery: project,
   location, datasets, the cost line, and for mode live the statement
   that live mode is NOT LIVE-TESTED in this repository and the first
   live run is expected to find differences), the security mapping
   summary (bigquery: every unmapped role, every WARNING, every
   resolution with its rationale, anything still at review), and the
   rollback summary. Ask via AskUserQuestion: approve the plan, or
   decline with reason.
   - Approved: `state set-strategy --strategy <s>` (bigquery:
     bulk_load), then `state complete-phase --phase plan`, then
     `state approve-gate --gate plan_approval --approved-by <user email
     if known, else "operator"> --artifact artifacts/02-plan.md`.
   - Declined: `state decline-gate --gate plan_approval --reason <r>`,
     leave the phase in_progress, report what to change (bigquery:
     often the principal map or a resolution; re-run this command
     afterwards) and stop.

9. Verification: 02-plan.md exists with all seven sections non-empty;
   state shows strategy set and gate approved (approved path only).
   bigquery: translation-review.json has empty views and policies, or
   the plan names each remaining item and the approver saw it.
