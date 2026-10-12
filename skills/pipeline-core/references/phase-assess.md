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
5. Dispatch the security-analyst subagent. Its prompt must contain:
   the exact inventory command
   `python "$SCRIPTS" security inventory --host <h> --port <p>
   --dbname <d> --user <u> [--password-env <e>]
   --out <workspace>/artifacts/security.json`,
   the workspace path, and the reminder that source access is that one
   script invocation (catalog queries only, no data rows). It writes
   artifacts/security-notes.md. On failure, handle it as in step 3.
   This runs for every provider: PostgreSQL targets use security.json
   for the role sync and the parity diff in migrate_security, BigQuery
   uses it for the security plan.

## Providers: local, gcp, aws, azure

Nothing beyond steps 1-5. Continue at step 8.

## Provider: bigquery

6. Principal map template:
   `python "$SCRIPTS" bq-security plan --migration <name> --template`
   writes <workspace>/security/principal-map.yaml with one entry per
   non-system role and empty principals (superusers appear in a
   comment only). When the file already exists the command refuses
   with exit 1: that is the operator's file, leave it alone and never
   pass --force in this phase. Tell the user the file must be filled
   in before Gate 1; an empty principal means unmapped, which means no
   access on the target.
7. Type and DDL findings:
   `python "$SCRIPTS" bq-schema translate --migration <name>` reads
   inventory.json, migration.yaml, and translation-resolutions.json
   when it exists (no backend, no target) and
   writes artifacts/schema-plan.json, artifacts/bq-apply/10-datasets.sh,
   artifacts/bq-apply/20-tables.sql, and the views section of
   artifacts/translation-review.json. Read findings[] in
   schema-plan.json (severity, code, subject, message, action). The
   WARNING codes are type_warning, primary_key_dropped,
   foreign_key_dropped, matview_as_view, view_review, and the three
   resolution rejections view_resolution_ignored,
   view_resolution_unjustified, and view_resolution_stale. The plan
   phase runs translate again; this run only feeds the risk register.

## All providers

8. Assemble artifacts/01-assessment.md yourself from the notes files:

   ```markdown
   # Migration assessment: <name>
   Date: <iso date> | Source: <engine> <version> at <host>:<port>/<db>
   | Target: <provider> (<mode> for bigquery)

   ## Summary and recommendation
   <one paragraph; end with GO, GO WITH CONDITIONS (list them), or NO-GO>

   ## Source profile
   <sizes, row counts, largest tables: from inventory-notes>

   ## Security profile
   <from security-notes: roles and memberships, restricted columns,
   RLS tables with their policies in plain language, bypass roles,
   PUBLIC grants, default privileges, what needs a principal>

   ## Risk register
   | # | Finding | Severity | Impact | Addressed in phase |
   <every planted-or-real finding gets a row: no-PK tables, wal_level,
   extensions, matviews, roles, and the security rows below>

   ## Target compatibility
   <finding table from compatibility-notes, plus unchecked-dimensions note>
   ```

   Security rows in the risk register:
   - one row per RLS table (rls[] in security.json) naming its
     policies, addressed in migrate_security (BigQuery: row access
     policies; PostgreSQL targets: post-data restore, verified in
     migrate_security and migrate_data);
   - one row per (relation, grantee) column-level grant, listing the
     restricted columns (BigQuery: policy tags);
   - one row per PUBLIC grant, or one row saying none;
   - one row per bypass role: superusers, roles with bypass_rls, and
     the owner of each RLS table where forced is false;
   - bigquery: one row per role in security/principal-map.yaml with an
     empty principal (unmapped until the operator fills it in;
     addressed in plan);
   - bigquery: one row per WARNING finding from schema-plan.json
     (unsupported types and dropped keys).
9. Verification: 01-assessment.md exists, contains a risk row for every
   no-PK table, non-default extension, RLS table, column-level grant,
   and bypass role in the inventories, and states a go/no-go. The demo
   dataset must yield at least: audit_log no-PK row, wal_level=replica
   row, hstore row, matview refresh row, RLS rows for orders (two
   policies) and audit_log (two policies), the restricted column
   customers.email (app_ro), the bypass role postgres, and for
   bigquery the unmapped roles app_ro, app_rw, and reporting.
10. `state complete-phase --phase assess`, then summarize the
    assessment and name the next command (/dbcarry:plan). For
    bigquery, repeat that security/principal-map.yaml must be filled
    in first.
