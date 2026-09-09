# Migrate-security playbook

Preconditions: `state verify`;
`state start-phase --phase migrate_security` succeeds (migrate_schema
is complete). The tables are still empty: this phase runs before
migrate_data on purpose (hard rule 8), so no row exists before its
controls do.

Read migration.yaml (provider, source) and artifacts/security.json, the
source security inventory from assess. If security.json is missing,
run the assess command now (read-only catalog queries, no data rows):
`python "$SCRIPTS" security inventory --host <h> --port <p> --dbname <d>
--user <u> [--password-env <e>] --out <workspace>/artifacts/security.json`

## Providers: local, gcp, aws, azure

Read artifacts/target.json for the target flags. pg_dump carries
grants, column grants, RLS flags, and policies, but not role attributes
or memberships; this phase recreates those. Section boundary: grants
and column grants were restored with pre-data in migrate_schema; RLS
flags and policies travel in post-data, which migrate_data restores,
so their parity is proven there. Default privileges appear in
security.json for the reader, but `security diff` does not compare
them (its seven sections are named in step 4), so this pipeline
never claims parity for them.

1. Optional dry read: run the step 2 command with `--dry-run` appended
   to print the statements without executing anything.
2. `python "$SCRIPTS" security sync-roles --from
   <workspace>/artifacts/security.json --host <th> --port <tp>
   --dbname <d> --user <u> [--password-env <e>]`, adding
   `--no-bypassrls` for every provider except local (BYPASSRLS and
   NOBYPASSRLS need superuser, which managed services refuse). Creates
   every role except postgres, superusers, and pg_* roles (idempotent
   DO blocks), sets LOGIN or NOLOGIN, INHERIT or NOINHERIT, BYPASSRLS
   where allowed, then grants each membership with its PostgreSQL 16
   options (a pre-16 target gets plain GRANT and a WARNING on stderr).
   Never SUPERUSER, CREATEROLE, CREATEDB, or a password: login roles
   need passwords set by the operator out of band; say so in the
   report. This writes to the target, never to the source.
3. `python "$SCRIPTS" security inventory --host <th> --port <tp>
   --dbname <d> --user <u> [--password-env <e>] --out
   <workspace>/artifacts/security-target.json`
4. `python "$SCRIPTS" security diff --left
   <workspace>/artifacts/security.json --right
   <workspace>/artifacts/security-target.json`. The JSON report has
   sections roles, memberships, schema_privileges, relation_privileges,
   column_privileges, rls, and policies, each with missing and extra
   lists, plus unsynced_target_roles and match; exit 0 only when match
   is true. Owner-derived rows and grantor names are ignored by the
   tool. Read it with these rules:
   - roles, memberships, schema_privileges, relation_privileges,
     column_privileges: missing and extra must both be empty.
   - rls and policies: extra must be empty. Missing entries are
     expected here whenever the source has RLS: pg_dump emits ENABLE
     ROW LEVEL SECURITY and CREATE POLICY in its post-data section, so
     after a pre-data restore the diff should list every RLS flag and
     policy as missing. The v0.2.0 acceptance run recorded exactly that
     on the demo source (2 rls flags and 4 policies missing after
     pre-data, match true after post-data; see README); the proof for
     any run is migrate_data, which repeats this diff after post-data
     and requires match true. List each missing entry
     under "Deferred to post-data" in the report. A source without
     RLS gets match true and exit 0 right here.
   - unsynced_target_roles: informational. Roles the target has and the
     source never mentioned (platform roles on a managed service, the
     target's own superuser); list them, never delete them.
   - With --no-bypassrls, a non-superuser source role with bypass_rls
     true differs under roles. When every roles difference is a
     bypass_rls attribute, run the diff again with `--ignore-roles`,
     record each such role as a WARNING (it cannot bypass RLS on this
     target), and continue; any other roles difference fails.
5. Write artifacts/04b-security-report.md:

   ```markdown
   # Security report: <name>
   Date: <iso date> | Provider: <provider> | Target: <host>:<port>/<db>

   ## Roles synced
   | role | login | inherit | bypassrls | memberships |
   <one row per synced role; bypassrls says "applied" or "not
   reproduced (--no-bypassrls)"; then the roles skipped (postgres,
   superusers) and "passwords: set out of band by the operator">

   ## Parity diff (sections pre-data carries)
   <per section: missing count, extra count, PASS or FAIL; then the
   line "default privileges: not compared by security diff">

   ## Deferred to post-data
   <every rls and policies missing entry verbatim, or "none";
   "verified again in migrate_data">

   ## Unsynced target roles
   <list or "none">

   ## Verdict
   SECURITY PARITY (pre-data sections) PASSED or FAILED
   ```

6. Every rule of step 4 satisfied -> `state complete-phase --phase
   migrate_security`; next /db-drift:migrate-data. Otherwise
   `state fail-phase --phase migrate_security --reason <section and
   first difference>` and stop.

## Provider: bigquery

Read artifacts/security-plan.json (from plan). No target connection
flags exist: bq-security reads the bigquery block of migration.yaml.
The steps are the same in emulated and live mode; live is NOT
LIVE-TESTED, and in emulated mode every table header in the report
ends with "(emulated)".

1. Precondition: no row access policy in security-plan.json has
   confidence `review` (the policies section of
   artifacts/translation-review.json is empty). Otherwise apply refuses
   and names them; the only way through is /db-drift:plan, the
   sql-translator, and Gate 1.
2. `python "$SCRIPTS" bq-security apply --migration <name>`. In this
   order: the taxonomy dbdrift_<migration> activated for
   FINE_GRAINED_ACCESS_CONTROL and its policy tags (only when
   security-plan.json has policy tags; a source without column grants
   gets no taxonomy, security-applied.json records taxonomy null, and
   verify skips the enforcement check with enforcement_active true),
   the fine-grained reader binding per tag reader, the project-level
   jobUser bindings, dataset access entries (bindings and authorized
   views), table bindings, the tag attachment through each table's
   schema, and the row access policies. Writes
   artifacts/security-applied.json (taxonomy resource name, tag
   resource names, ops, mode). Re-running
   is safe: existing taxonomies and tags are reused by display name
   and existing bindings are kept. Every mutating call is one line in
   artifacts/bq-operations.log. With column_security
   policy_tags_with_masking, bq-apply/60-masking-requests.json is
   rendered and never executed (no CLI surface); say so in the report.
3. `python "$SCRIPTS" bq-security verify --migration <name>`. Reads
   every control back through the backend, never from the apply log:
   project bindings, dataset access entries, table bindings,
   authorized views, the taxonomy and its activation
   (taxonomy_enforcement), every tag with every reader, every tagged
   column, every row policy with the same members and a
   whitespace-normalized equal filter, and extras the plan does not
   name (tag_reader_extra, row_policy_extra fail with expected
   "absent"). Writes artifacts/security-verify.json (checks[] with
   name, expected, actual, pass; enforcement_active; pass; mode) and
   prints SECURITY VERIFY PASSED or FAILED; exit 1 on any miss. pass is
   true only when every check passed and, when tags were planned,
   enforcement_active is true.
4. `python "$SCRIPTS" bq-backend status --migration <name>` for the
   read-back listing (datasets, tables with their row_policies,
   taxonomies with their policyTags) quoted in the report.
5. Write artifacts/04b-security-report.md:

   ```markdown
   # Security report: <name>
   Date: <iso date> | Provider: bigquery (<mode>) | Project: <project>, location <location>

   ## Bindings applied
   | scope | resource | role | member | source role | read-back |
   <one row per binding in security-plan.json; read-back is PASS or
   FAIL from the matching check in security-verify.json>

   ## Policy tags
   Taxonomy: <resource name from security-applied.json, or "none (no policy tags planned)"> | enforcement active: <true or false>
   | tag | columns | readers | read-back |

   ## Row access policies
   | table | policy | members | filter | confidence | read-back |

   ## Authorized views
   | view | dataset | read-back |

   ## Verification
   <the SECURITY VERIFY line verbatim; checks passed and failed counts;
   every failed check with expected and actual; enforcement_active>

   ## Not applied
   <masking requests (rendered only); identity notes from
   bq-apply/70-identity-notes.md; unmapped roles (WARNING
   unmapped_role); group memberships the operator performs out of band>
   ```

6. SECURITY VERIFY PASSED with enforcement active -> `state
   complete-phase --phase migrate_security`; next
   /db-drift:migrate-data. Any failed check, or enforcement_active
   false with tags planned -> `state fail-phase --phase migrate_security
   --reason <first failed check name>` and stop. Never load data on a
   failed verification: in live mode bq-load refuses on its own, in
   emulated mode this playbook is the guard.
