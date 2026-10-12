# Mapping rules

Spec sections 7.1 to 7.5 as rule tables, restated from
`scripts/db_carry/bq_security.py`. Each rule names the finding code the
planner emits, exactly as the code spells it. The full code list with
severities is at the end; it is the complete set the module can emit.
The live command forms in 7.5 are NOT LIVE-TESTED.

Inputs: `security.json` (the security inventory), `inventory.json`
(must carry the v0.2.0 `columns` section; without it the planner raises
and asks for a fresh assess), the `bigquery` block of migration.yaml,
`security/principal-map.yaml`, and `translation-resolutions.json` when
present. Output: `security-plan.json` and `security-plan.md`.

## 7.1 Roles to principals

| Rule | Source | Target | Finding |
|---|---|---|---|
| One principal per role | role `r` with `principal:` set in the principal map | every binding, tag reader, and row policy for `r` names that principal | none |
| Principal type | `user:`, `group:`, `serviceAccount:`, `domain:` (and `specialGroup:` only for projectOwners, projectReaders, projectWriters) | accepted; anything untyped, containing whitespace or quotes, or spelling `allUsers` or `allAuthenticatedUsers` in any case or behind any prefix makes the plan fail | a plan error (no finding is emitted) |
| Unmapped role | role with any relation, column, or schema privilege and no principal | nothing on BigQuery | WARNING `unmapped_role`, message lists every binding, tag reader, and row policy it would have received |
| Principal map entry for a role that does not exist on the source | | ignored | INFO `principal_without_role` |
| Several roles on one principal | | the principal holds the union; the strongest data role per (scope, resource, member) wins and a dataset-level role absorbs the member's table bindings inside that dataset | NOTE `principal_shared`, listing the absorbed bindings |
| Membership flattening | `GRANT g TO r` where the membership inherits (PostgreSQL 16 and later: the membership's own `inherit_option`; earlier: `r`'s INHERIT attribute; unknown server version: both must allow) | `r` receives `g`'s grants and applicable policies, transitively | none |
| Membership without inheritance | NOINHERIT role, or `GRANT ... WITH INHERIT FALSE` | not flattened; `r` gets only its own grants | WARNING `noinherit_not_flattened` |
| PUBLIC grants | any grant to PUBLIC | folded into every role's effective set; when `public_principal` is set, also bound directly to it, and PUBLIC then counts as a column reader of its own, so a column-level PUBLIC grant leaves the other columns tagged and the public principal outside their readers | NOTE `public_mapped` when set; WARNING `public_unmapped` when empty and PUBLIC holds relation or column grants; NOTE `public_schema_usage` when PUBLIC holds only schema USAGE |
| Superuser, mapped | `rolsuper` role with a principal | `roles/bigquery.dataOwner` on every dataset, fine-grained reader on every policy tag, `rls_bypass_<role>` with TRUE on every RLS table | WARNING `superuser_mapped` |
| Superuser, unmapped | | nothing; the migration identity owns the datasets | INFO `superuser_unmapped` |
| Ownership | relation owners | not mapped | NOTE `ownership_not_mapped` (once, subject `owners`) |

Superusers never define which columns are restricted (they bypass
column privileges on the source), so a table read only by a superuser
has no restricted columns and no tags.

## 7.2 Relation privileges to IAM

Scopes: `table` (a table, view, or materialized view, resource
`<dataset>.<name>`), `dataset`, `project`. One data role per (scope,
resource, member).

| Rule | Source | Target | Finding |
|---|---|---|---|
| Read | SELECT on a table, view, or matview | `roles/bigquery.dataViewer` on it | none |
| Column read | column-level SELECT on a table without table SELECT | dataViewer on the table; the restricted columns carry a policy tag (7.3) | none |
| Column read on a view | column-level SELECT on a view or matview | dataViewer on the view; the inventory lists no columns for views, so nothing protects the other columns | WARNING `view_column_grant_widens` |
| Write | any of INSERT, UPDATE, DELETE, TRUNCATE on a table | `roles/bigquery.dataEditor` on it (never together with dataViewer) | WARNING `editor_widens` when the role lacks any of SELECT, INSERT, UPDATE, DELETE, naming what dataEditor adds |
| Write on a view with SELECT | | dataViewer only | INFO `view_write_unmapped` (once per role) |
| Write on a view without SELECT | | dataViewer, which the source never granted | WARNING `view_write_widens` |
| Schema USAGE without relation grants in it | | `roles/bigquery.metadataViewer` on the dataset | none |
| Schema CREATE | | dataEditor on the dataset (reads and writes every table) | WARNING `schema_create_widens` |
| Any binding at all | | `roles/bigquery.jobUser` on the project, once per member | none |
| Sequences | USAGE, SELECT, UPDATE on sequences | nothing | INFO `sequence_unmapped` (once per role) |
| REFERENCES, TRIGGER, MAINTAIN | | nothing | INFO `privilege_unmapped` (once per role) |
| Default privileges | `ALTER DEFAULT PRIVILEGES ... GRANT ... TO r` | no binding (a dataset-level binding would widen access to tables the source never granted); the note says whether `r` already holds a dataset-level binding that covers future tables | NOTE `default_privileges_note` per (schema, grantee) |
| Granularity `auto` | the member holds the same IAM role on every relation of a dataset | one dataset-level binding replaces the per-relation ones | none |
| Granularity `dataset` | the member holds a role on at least one relation of a dataset | the strongest role held anywhere in the dataset, at dataset level | WARNING `widened_by_granularity` when the source grants that level on only some relations, listing the read-only and the ungranted ones |
| Granularity `table` | | never promotes | none |
| Column write | column-level INSERT or UPDATE | nothing; BigQuery has no column-level write control | WARNING `column_write_unmapped` |
| Missing column rows | a readable table with no `columns` rows in the inventory | table privileges mapped, column privileges unanalyzed, probes select no columns | WARNING `inventory_without_columns` |

Authorized views: for each view or materialized view and each mapped,
non-superuser role with SELECT on it, when the role lacks table SELECT
on any base table (from `view_dependencies`), the plan adds `{"view":
"<dataset>.<view>", "dataset": "<base dataset>"}` once per pair (NOTE
`authorized_view`). Two semantic differences are reported per view:
INFO `view_rls_semantics` when a base table has RLS (PostgreSQL
evaluates the view as its owner unless security_invoker; BigQuery
applies the querying principal's row policies) and INFO
`view_column_semantics` when a base table has restricted columns
(BigQuery enforces the tags on the querying principal even through an
authorized view).

## 7.3 Column privileges to policy tags

| Rule | Detail |
|---|---|
| Readable set per (table, role) | every column when the role has table SELECT (directly, through PUBLIC, or through inheritance); otherwise the columns with column-level SELECT. A role that reads nothing is absent. Superusers are excluded |
| Restricted column | a column that some reader of the table cannot read |
| Allowed readers | the readers of the table that can read the column; a mapped superuser is added to every tag's readers |
| Grouping | restricted columns of one table with identical allowed-reader sets share one tag, in inventory column order |
| Tag name | `<bq table name>__<first column>` plus `_and_<k>_more` for `k` further columns, sanitized to `[A-Za-z0-9_]`; on a collision across tables the dataset name is prefixed |
| Taxonomy | one per migration, display name `dbcarry_<migration>`, `activatedPolicyTypes: ["FINE_GRAINED_ACCESS_CONTROL"]`. Without that activation a tag only labels the column; verify checks it (`taxonomy_enforcement`) |
| Reader role | `roles/datacatalog.categoryFineGrainedReader` on the tag for each allowed reader's principal |
| Attachment | the tag's resource name in the column's `policyTags.names` of the table schema, applied after the tables exist |
| Unmapped reader | recorded in the role's `unmapped_role` message as "fine-grained reader on tag <name>" |
| Masking (`column_security: policy_tags_with_masking`) | per tag one entry `{"tag", "data_policy_id": "mask_<tag>", "rule": "ALWAYS_NULL", "masked_readers": [principals with table read but not the column]}`, rendered to `60-masking-requests.json` as request bodies, never executed |

The demo: `app_ro` loses table SELECT on `customers` and keeps column
SELECT on `id`, `full_name`, `created_at`; `app_rw` reads every column;
`reporting` inherits `app_ro`. `email` is the only restricted column,
tag `customers__email`, readers `app_rw` only.

## 7.4 Row-level security to row access policies

| Rule | Detail |
|---|---|
| Scope | every table with `relrowsecurity` on (`rls[].enabled`); views are skipped |
| Applicable source policies for a role | command SELECT or ALL, a non-empty USING clause, and roles naming the role itself, PUBLIC, or a group the role inherits from |
| One policy per (table, mapped role that can read the table) | name `rls_<role>`, members `[principal]`, filter as combined below, `source_policies` carrying each source policy's name, command, permissive flag, roles, USING text, translated SQL, confidence, notes, and the role through which it applied (`via`) |
| Combination | `(perm_1) OR (perm_2) ...`, then `AND (restr_1) AND (restr_2) ...`; one permissive and no restrictive stands as written; `combine_predicates` does it, and the probe's PostgreSQL count query combines the source predicates the same way |
| Confidence | the lowest across the source policies: `review` < `resolved` < `auto` |
| No applicable permissive policy | no BigQuery policy for the role, so the table's other policies deny it every row, as PostgreSQL does | INFO `rls_denies_role` |
| Bypass | BYPASSRLS roles, the owner when RLS is not forced (ownership inherited through membership counts), and mapped superusers: `rls_bypass_<role>` with `TRUE`, confidence auto |
| Table with no policy for any mapped role | `rls_deny_all` with `FALSE` granted to `admin_principal`, because a BigQuery table without any policy is open | WARNING `rls_deny_all`; WARNING `rls_deny_all_unassigned` when `admin_principal` is empty and nothing can be written |
| INSERT, UPDATE, DELETE policies and WITH CHECK clauses | not mapped (a WITH CHECK on a SELECT or ALL policy still has its USING mapped for reads) | WARNING `policy_command_unmapped` |
| Identity predicates | `current_user`, `session_user`, `current_role` become `SESSION_USER()`; the policy carries the translator's note and the plan's `identity_notes` | INFO `identity_predicate` |
| Review-flagged predicate carried by an emitted policy | blocks apply until resolved | WARNING `translation_review` |
| Review-flagged predicate reaching only unmapped roles | no policy carries it; nothing blocks | INFO `translation_review_unmapped` |
| Resolution present in `translation-resolutions.json` under `policies["schema.table/policy"]` | replaces that source policy's translated text only when the automatic translation was `review`; confidence `resolved`; the rationale is appended to the policy's notes. A resolution is rejected, and the policy stays `review`, when it has no rationale, when its `source_sql` (copied from the review file) no longer equals the source predicate, or when its `sql` is not one balanced expression without a semicolon | NOTE `translation_resolved`; WARNING `translation_resolution_ignored` (the predicate translated automatically), `translation_resolution_unjustified`, `translation_resolution_stale`, `translation_resolution_malformed` |
| PUBLIC reads an RLS table and `public_principal` is set | no row policy is written for the public principal (policies are per source role), so it sees no rows | INFO `public_rls_denied` |
| Security-barrier views | not translated | WARNING `security_barrier_view` |

The demo yields, on `orders`: `rls_reporting` with `(region = 'eu')`
(auto) and `rls_app_rw` with `TRUE`; on `audit_log`: `rls_app_ro` with
`(actor = SESSION_USER())` (auto, identity note), `rls_reporting` with
the same predicate through the `app_ro` membership, and `rls_app_rw`
with `TRUE`. `postgres` is a superuser: unmapped by default, it gets no
`rls_bypass_postgres`; mapped, it gets one on both tables.

## 7.5 Plan output

`security-plan.json` top level: `migration`, `project`, `location`,
`mode`, `taxonomy` (`display_name`, `activated`), `datasets` (dataset
to source schema), `principals` (role to principal), `bindings`
(`scope`, `resource`, `role`, `member`, `source_role`, `reason`),
`policy_tags` (`name`, `columns` as dataset, table, column, `readers` as
member and source_role, `source_columns`, `description`),
`row_policies` (`dataset`, `table`, `source_table`, `name`, `members`,
`source_roles`, `filter`, `confidence`, `notes`, `source_policies`),
`authorized_views` (`view`, `dataset`), `identity_notes`,
`nesting_notes`, `masking`, `findings` (sorted WARNING, INFO, NOTE,
then subject), `effective` (role to relation to privilege list, for the
report), `context_tables` (bare and qualified source names to
backticked BigQuery names, the translator's context). Bindings are
deduplicated and sorted by scope, resource, role, member.

`security-plan.md` renders the same as tables: principals, bindings,
policy tags, row access policies (with `via` per source policy),
authorized views, masking requests when any, findings, identity notes.

`bq-apply/` after `bq-security plan`: `30-iam.sh` (project bindings with
`--condition=None`, dataset access entries as JSON to add by hand
through `bq show` then `bq update --source`, table bindings with `bq
add-iam-policy-binding`), `40-policy-tags.sh` (taxonomy and tags through
the Data Catalog REST API with a token from `gcloud auth
print-access-token`, readers through `gcloud data-catalog taxonomies
policy-tags add-iam-policy-binding`, attachment instructions per table),
`50-row-policies.sql` (`CREATE OR REPLACE ROW ACCESS POLICY <name> ON
<table> GRANT TO ("<member>") FILTER USING (<filter>)`; review policies
commented out), `60-masking-requests.json` (masking mode only),
`70-identity-notes.md` (never executed). `10-datasets.sh` and
`20-tables.sql` come from `bq-schema translate`.

## Finding codes

Every code `bq_security.py` can emit, with severity and subject shape.
`translation_review` and `rls_deny_all_unassigned` block apply; the rest
inform Gate 1 and the reports. The plan phase presents every WARNING.

| Code | Severity | Subject | Meaning |
|---|---|---|---|
| `editor_widens` | WARNING | `schema.table/role` | the role holds some but not all of SELECT, INSERT, UPDATE, DELETE; dataEditor also grants the missing ones |
| `view_write_widens` | WARNING | `schema.view/role` | write privilege on a view without SELECT; dataViewer is the only binding available and it reads |
| `column_write_unmapped` | WARNING | `schema.table.column/role` | column-level INSERT or UPDATE; no column-level write control on BigQuery |
| `view_column_grant_widens` | WARNING | `schema.view/role` | column-level SELECT on a view; no view columns in the inventory, so dataViewer exposes every column |
| `schema_create_widens` | WARNING | `schema/role` | CREATE on a schema becomes dataEditor on the dataset |
| `widened_by_granularity` | WARNING | `dataset/member` | `binding_granularity: dataset` promoted a role the source grants on only some relations |
| `superuser_mapped` | WARNING | `role` | a superuser has a principal: dataOwner everywhere, reader on every tag, TRUE row policies |
| `public_unmapped` | WARNING | `PUBLIC` | PUBLIC holds relation or column grants and `public_principal` is empty; only inventoried roles keep access |
| `policy_command_unmapped` | WARNING | `schema.table/policy` | an INSERT, UPDATE, or DELETE policy, or a WITH CHECK clause, has no BigQuery form |
| `rls_deny_all` | WARNING | `schema.table` | no mapped role gets a read policy on this RLS table; `rls_deny_all` (FALSE) for `admin_principal` keeps it closed |
| `rls_deny_all_unassigned` | WARNING | `schema.table` | same situation with `admin_principal` empty: nothing can be written and the table would be open to every reader; apply refuses the plan, and the probes expect zero rows for every mapped reader |
| `column_grant_unknown_column` | WARNING | `schema.table/role` | a column-level SELECT names a column the inventory does not list; no binding is derived from it |
| `translation_resolution_ignored` | WARNING | `schema.table/policy` | a resolution exists for a predicate that translated automatically; it is ignored |
| `translation_resolution_unjustified` | WARNING | `schema.table/policy` | the resolution has no rationale; the policy stays at review |
| `translation_resolution_stale` | WARNING | `schema.table/policy` | the resolution's `source_sql` differs from the current source predicate; the policy stays at review |
| `translation_resolution_malformed` | WARNING | `schema.table/policy` | the resolution is not one balanced expression, or carries a semicolon; the policy stays at review |
| `noinherit_not_flattened` | WARNING | `role` | a membership without inheritance was not flattened |
| `unmapped_role` | WARNING | `role` | a role with privileges has no principal; the message lists what it would have received |
| `security_barrier_view` | WARNING | `schema.view` | a security_barrier view's logic is not translated |
| `translation_review` | WARNING | `schema.table/policy` | the predicate needs the sql-translator; apply is blocked until a resolution exists |
| `inventory_without_columns` | WARNING | `schema.table` | a readable table has no column rows in the inventory |
| `principal_without_role` | INFO | `name` | the principal map names a role the source does not have |
| `view_write_unmapped` | INFO | `role` | write privileges on views that also have SELECT; dataViewer only |
| `sequence_unmapped` | INFO | `role` | sequence privileges; no sequences on BigQuery |
| `privilege_unmapped` | INFO | `role` | REFERENCES, TRIGGER, or MAINTAIN; no equivalent |
| `superuser_unmapped` | INFO | `role` | a superuser with no principal; the migration identity owns the datasets |
| `identity_predicate` | INFO | `schema.table/policy` | the predicate compares a column with the caller's identity; role name on PostgreSQL, email on BigQuery |
| `public_rls_denied` | INFO | `schema.table` | PUBLIC reads an RLS table and a public principal is set; it receives no row policy and sees no rows |
| `rls_denies_role` | INFO | `schema.table/role` | the role reads the table but no permissive policy names it; no rows on either side |
| `view_rls_semantics` | INFO | `schema.view` | the view reads an RLS table; owner evaluation on PostgreSQL, querying principal on BigQuery |
| `view_column_semantics` | INFO | `schema.view` | the view reads restricted columns; tags apply to the querying principal even through an authorized view |
| `translation_review_unmapped` | INFO | `schema.table/policy` | a review-flagged predicate reaches only roles without a principal; nothing blocks |
| `public_mapped` | NOTE | `PUBLIC` | PUBLIC's grants are bound to `public_principal` besides being folded into every role |
| `public_schema_usage` | NOTE | `PUBLIC` | PUBLIC holds only schema USAGE; folded, no separate principal |
| `principal_shared` | NOTE | `member` | several roles map to one principal; it holds the union, and absorbed bindings are listed |
| `translation_resolved` | NOTE | `schema.table/policy` | the recorded resolution replaced the translated predicate; confirm the rationale at Gate 1 |
| `authorized_view` | NOTE | `schema.view` | the view is authorized on base datasets for roles that cannot read every base table |
| `default_privileges_note` | NOTE | `schema or */grantee` | default privileges exist on the source; no binding is written, and the note says whether a dataset-level binding already covers future tables |
| `ownership_not_mapped` | NOTE | `owners` | relation ownership is not mapped |

Twenty-one WARNING, eleven INFO, seven NOTE: 39 codes. `SEVERITY_RANK`
orders them WARNING, INFO, NOTE in the plan and the report.
