# Assess playbook

Preconditions: `state verify` passes, then
`state --migration <name> start-phase --phase assess` succeeds.

1. Read migration.yaml for source connection and provider.
2. Dispatch the discovery-analyst subagent. Its prompt must contain:
   the exact inventory command to run, built from migration.yaml:
   `python "$SCRIPTS" inventory --host <h> --port <p> --dbname <d>
   --user <u> [--password-env <e>] --exact
   --out <workspace>/artifacts/inventory.json`,
   the workspace path, and the reminder that source access is that one
   script invocation only.
3. On subagent failure (connection refused, auth), run
   `state fail-phase --phase assess --reason <short reason>`, report,
   and stop.
4. Dispatch the compatibility-checker subagent. Its prompt must contain:
   the inventory.json path, the provider skill path
   ${CLAUDE_PLUGIN_ROOT}/skills/provider-<provider>/SKILL.md, and the
   workspace path. If the provider skill does not exist yet (early
   build order), note that compatibility is unchecked; that is a
   WARNING in the assessment, not a silent skip.
5. Assemble artifacts/01-assessment.md yourself from both notes files:

   ```markdown
   # Migration assessment: <name>
   Date: <iso date> | Source: <engine> <version> at <host>:<port>/<db>
   | Target: <provider>

   ## Summary and recommendation
   <one paragraph; end with GO, GO WITH CONDITIONS (list them), or NO-GO>

   ## Source profile
   <sizes, row counts, largest tables: from inventory-notes>

   ## Risk register
   | # | Finding | Severity | Impact | Addressed in phase |
   <every planted-or-real finding gets a row: no-PK tables, wal_level,
   extensions, matviews, roles>

   ## Target compatibility
   <finding table from compatibility-notes, plus unchecked-dimensions note>
   ```

6. Verification: 01-assessment.md exists, contains a risk row for every
   no-PK table and non-default extension in inventory.json, and states
   a go/no-go. The demo dataset must yield at least: audit_log no-PK
   row, wal_level=replica row, hstore row, matview refresh row.
7. `state complete-phase --phase assess`, then summarize the assessment
   and name the next command (/db-drift:plan).
