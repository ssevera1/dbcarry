# The PostgreSQL to BigQuery security mapping, for a reviewer

This document explains what dbcarry does with a PostgreSQL database's
access controls when the target is BigQuery, in enough detail that a
security reviewer can decide whether to trust it. The mapping is
implemented once, as the pure function `plan_security` in
`scripts/db_carry/bq_security.py`, and every rule here has a test in
`tests/test_bq_security.py`. The running example is the demo database
that `/dbcarry:demo setup` seeds, with the principal map filled in as the
spec's example does (one Google Group per role). All numbers and names
below come from running the pipeline against the demo's inventory
fixtures in emulated mode; the artifacts a real run writes carry the same
values.

One caveat governs everything: the emulated backend proves that the
pipeline plans, applies, and verifies the right controls. It does not
prove BigQuery's behavior. The live backend is written from documentation
and is NOT LIVE-TESTED.

## The demo in one paragraph

Database `retail`, schema `public`, five tables (`customers`, `products`,
`orders`, `order_items`, `audit_log`), a view `recent_orders` over
`orders` and `customers`, and a materialized view `sales_by_product`.
Four roles: `postgres` (superuser, owns everything), `app_rw` (login;
SELECT, INSERT, UPDATE, DELETE on every table, USAGE and SELECT on every
sequence), `app_ro` (login; SELECT on every table, except that its SELECT
on `customers` was revoked and replaced by a column grant on `id`,
`full_name`, `created_at`), and `reporting` (no login; SELECT on the two
views, and a member of `app_ro`). Row-level security is enabled on
`orders` with two policies (`orders_region_eu`, FOR SELECT TO `reporting`
USING `region = 'eu'`; `orders_all_rw` TO `app_rw` USING `true`) and on
`audit_log` with two (`audit_self`, FOR SELECT TO `app_ro` USING `actor =
current_user`; `audit_all_rw` TO `app_rw` USING `true`). A default
privilege grants SELECT on future tables in `public` to `app_ro`.
`PUBLIC` holds USAGE on schema `public` and nothing else.

## Inputs

- `artifacts/security.json`, written by `python scripts/dbcarry.py
  security inventory --host <h> --port <p> --dbname <d> --user <u>
  [--password-env <e>] --out artifacts/security.json`. Catalog queries
  only (`pg_roles`, `pg_auth_members`, `aclexplode` over `pg_namespace`,
  `pg_class`, `pg_attribute`, and `pg_default_acl`, and `pg_get_expr`
  over `pg_policy` for the policy expressions), read-only, no data rows
  read, no superuser needed. Sections: `roles`,
  `memberships`, `schema_privileges`, `relation_privileges`,
  `column_privileges`, `rls`, `policies`, `default_privileges`,
  `security_barrier_views`.
- `artifacts/inventory.json` for the columns, keys, and view definitions.
- The `bigquery` block of `migration.yaml`: `project`, `location`,
  `dataset_map` (`public: retail` in the demo), `admin_principal`,
  `public_principal` (empty in the demo), `column_security`
  (`policy_tags`), `binding_granularity` (`auto`).
- `security/principal-map.yaml`, one principal per role. The assess phase
  writes the template with `bq-security plan --template`; the operator
  fills it. In this document: `app_ro` is
  `group:retail-app-ro@example.com`, `app_rw` is
  `group:retail-app-rw@example.com`, `reporting` is
  `group:retail-reporting@example.com`, and `postgres` is left out.

## Principals and memberships

Each role maps to exactly one principal, which must be a typed IAM
principal: `user:`, `group:`, or `serviceAccount:` as recommended in the
template, `domain:` if you must, and `specialGroup:` only for
`projectOwners`, `projectReaders`, or `projectWriters`. `allUsers` and
`allAuthenticatedUsers` in any spelling or behind any prefix, untyped
strings, and values containing whitespace or quotes are rejected by the
planner when it reads the map (the same check covers `admin_principal`
and `public_principal`) and again by the backend before any binding is
written, so no mistake in the map can open a dataset to the world.

Memberships are flattened. `reporting` is a member of `app_ro` and both
roles have INHERIT, so `reporting`'s effective privileges are the union of
its own (SELECT on the two views) and `app_ro`'s (SELECT on every table,
the three-column grant on `customers`), and the policies that name
`app_ro` apply to `reporting` too. The plan records this in
`effective.reporting`: `public.customers` shows `SELECT(created_at,
full_name, id)`. A NOINHERIT role is not flattened and gets the WARNING
`noinherit_not_flattened`, because it would need `SET ROLE` on PostgreSQL
and BigQuery has no equivalent.

`PUBLIC` is folded into every role's effective set. In the demo it holds
only USAGE on the schema, so the plan emits the NOTE `public_schema_usage`
and binds nothing for it. When `PUBLIC` holds a relation privilege and
`public_principal` is empty, the plan emits the WARNING `public_unmapped`
listing the relations; when `public_principal` is set, that principal is
bound directly with a NOTE.

`postgres` is a superuser and is not in the map. The plan emits the INFO
`superuser_unmapped` ("the migration identity owns the datasets instead")
and gives it nothing. Had it been mapped, it would have received
`roles/bigquery.dataOwner` on every dataset, the fine-grained reader role
on every tag, and a `FILTER USING (TRUE)` row policy on every RLS table,
with the WARNING `superuser_mapped`, because that is what a superuser can
do on the source.

## Relation privileges to IAM bindings

For each role and relation: any SELECT (table-level or on at least one
column) earns `roles/bigquery.dataViewer`; any of INSERT, UPDATE, DELETE,
TRUNCATE earns `roles/bigquery.dataEditor` instead (never both on one
resource for one member; dataEditor includes read, and when the source had
write without SELECT the plan says so with the WARNING `editor_widens`).
Every member with at least one binding gets `roles/bigquery.jobUser` on
the project once, because without it the principal cannot run a query at
all. With `binding_granularity: auto`, a member that holds the same role on
every table and view of a dataset gets one dataset-level binding instead
of a binding per relation; `dataset` forces promotion whenever the member
has that role on at least one relation (WARNING `widened_by_granularity`
names what it widened), and `table` never promotes.

Two schema-level privileges also produce bindings. USAGE on a schema in
which the role holds no relation grant earns
`roles/bigquery.metadataViewer` on the dataset (the role could list
objects on the source, so it may list them on the target). CREATE on a
schema earns `roles/bigquery.dataEditor` on the dataset with the WARNING
`schema_create_widens`, because the closest BigQuery role also reads and
writes every table there. The demo triggers neither: `PUBLIC`'s USAGE is
folded into roles that already hold relation grants, and no role holds
CREATE.

The demo yields twelve bindings:

| scope | resource | role | member | why |
|---|---|---|---|---|
| dataset | retail | dataViewer | app_ro | same role on every relation of the dataset |
| dataset | retail | dataViewer | reporting | same role on every relation (inherited from app_ro, plus its own view grants) |
| project | emulated-project | jobUser | app_ro | needed to run queries |
| project | emulated-project | jobUser | app_rw | needed to run queries |
| project | emulated-project | jobUser | reporting | needed to run queries |
| table | retail.audit_log, customers, order_items, orders, products (five rows) | dataEditor | app_rw | DELETE, INSERT, SELECT, UPDATE on each |
| table | retail.recent_orders | dataViewer | app_rw | SELECT on the view (its write grants are unmappable: INFO `view_write_unmapped`) |
| table | retail.sales_by_product | dataViewer | app_rw | SELECT on the matview |

`app_rw` is not promoted to dataset level because its role differs between
the tables (dataEditor) and the views (dataViewer). `app_ro`'s dataset
binding also answers the default-privileges rule: PostgreSQL grants
`app_ro` SELECT on future tables in `public`, BigQuery has no default
privileges, and the plan notes (`default_privileges_note`) that only a
dataset-level binding covers tables created later, which `app_ro` already
holds. The plan never adds a dataset binding for that reason alone, since
that would widen access for a role that lacked it on some table.

Sequence privileges (`app_rw` holds USAGE and SELECT on three sequences)
and REFERENCES, TRIGGER, and MAINTAIN have no BigQuery equivalent: INFO
`sequence_unmapped` and `privilege_unmapped`. Ownership is not mapped
(NOTE `ownership_not_mapped`).

## Views

On PostgreSQL a view runs as its owner, so a role can read a view without
reading its base tables. BigQuery mirrors that with an authorized view: an
access entry on the base dataset naming the view. The demo emits one,
`retail.recent_orders` authorized on `retail`, because `app_ro` and
`reporting` can read the view but hold no table-level SELECT on
`customers` (NOTE `authorized_view`).

Two semantics differ and the plan says so rather than hiding it:

- `view_column_semantics` (INFO): `recent_orders` selects
  `customers.email`, a restricted column. PostgreSQL lets view readers see
  it through the owner; BigQuery enforces the policy tag on the querying
  principal even through an authorized view, so `app_ro` and `reporting`
  will get an access error selecting that column of the view unless they
  are made tag readers on purpose.
- `view_rls_semantics` (INFO): `recent_orders` reads `orders`, which has
  row-level security. PostgreSQL evaluates the view as its owner (RLS
  bypassed unless `security_invoker`); BigQuery applies the querying
  principal's row access policies on the base table, so a `reporting`
  query on the view sees only `eu` rows.

## Column privileges to policy tags

PostgreSQL column privileges are additive allow lists, so the planner
first computes, per table and role, the readable column set: every column
when the role has table SELECT, otherwise the columns with a column-level
SELECT. Superusers are left out of this computation because they bypass
column privileges and would otherwise define nothing as restricted. A
column is **restricted** when some role that can read at least one column
of the table cannot read that column. Restricted columns are grouped by
identical reader sets, and each group becomes one policy tag named
`<table>__<first_column>` (plus `_and_<k>_more` for a group of several
columns).

In the demo the only restricted column is `customers.email`: `app_rw`
reads every column, `app_ro` reads three, and `reporting` inherits
`app_ro`'s three. The tag is `customers__email`, its reader is
`group:retail-app-rw@example.com` (source role `app_rw`), and its
description is "dbcarry: public.customers.email readable by app_rw".

Mechanics that matter to a reviewer:

- The tag lives in a taxonomy named `dbcarry_<migration>` created with
  `activatedPolicyTypes: ["FINE_GRAINED_ACCESS_CONTROL"]`. That activation
  is what makes the tag enforced; a taxonomy created without it only labels
  columns. `bq-security verify` has a dedicated check,
  `taxonomy_enforcement`, and the whole verification fails when it is off.
- Each reader gets `roles/datacatalog.categoryFineGrainedReader` on the
  tag. BigQuery requires that role even for dataset owners; there is no
  bypass, and the emulator enforces the same rule.
- The tag is attached to the column through the table schema
  (`policyTags.names` on the field). The emulator keeps it in its table
  model; the live backend rewrites the schema with `bq update`.
- A principal with dataViewer on the table but no reader role on the tag
  gets an access error selecting that column, including through `SELECT
  *`. That is the PostgreSQL behavior for a column it lacks SELECT on.
- Column-level INSERT or UPDATE grants cannot be expressed (BigQuery has no
  column-level write control) and produce a WARNING.
- With `column_security: policy_tags_with_masking` the plan additionally
  emits one data policy request per tag (`mask_customers__email`, rule
  `ALWAYS_NULL`, `roles/bigquerydatapolicy.maskedReader` for `app_ro` and
  `reporting`, the principals that read the table but not the column)
  into `60-masking-requests.json`. Nothing executes those; the roadmap
  covers it.

## Row-level security to row access policies

BigQuery evaluates row access policies with OR semantics: a principal sees
the union of the rows of every policy that names it, and once a table has
any policy, a principal named by none sees no rows. PostgreSQL permissive
policies also combine with OR, and restrictive policies combine with AND
on top. The planner therefore emits **one BigQuery policy per (table,
mapped role)**, named `rls_<role>`, whose predicate is `(perm_1 OR perm_2
...) AND (restr_1) AND (restr_2 ...)` built from the source policies that
apply to that role (named directly, through `PUBLIC`, or through flattened
membership) with command SELECT or ALL. Every predicate goes through the
translator.

The demo yields five policies, all with confidence `auto`:

| table | policy | members | filter | from |
|---|---|---|---|---|
| retail.orders | rls_reporting | reporting | `(region = 'eu')` | `orders_region_eu`, the `::text` cast on the literal dropped |
| retail.orders | rls_app_rw | app_rw | `TRUE` | `orders_all_rw` |
| retail.audit_log | rls_app_ro | app_ro | `(actor = SESSION_USER())` | `audit_self`, `current_user` rewritten |
| retail.audit_log | rls_reporting | reporting | `(actor = SESSION_USER())` | `audit_self`, inherited through app_ro (`via: app_ro` in the plan) |
| retail.audit_log | rls_app_rw | app_rw | `TRUE` | `audit_all_rw` |

What the table does not show:

- `app_ro` holds SELECT on `orders`, but no policy names it, so on
  PostgreSQL it sees no rows. The plan writes no policy for it, and because
  `orders` has other policies, BigQuery denies it every row too. The INFO
  `rls_denies_role` for `public.orders/app_ro` records the match.
- `rls_app_rw` with `FILTER USING (TRUE)` is the planted demonstration of
  the "any policy denies unnamed principals" rule: it is needed so
  `app_rw` keeps seeing every row once the table has a policy at all.
- `audit_self` compares `actor` with the caller's identity. PostgreSQL
  `current_user` is a role name; BigQuery `SESSION_USER()` is an email
  address. The translation is mechanical, but the compared column must
  hold Google identities on the target or the predicate needs a mapping
  table. The plan carries this on the policy's notes, as the INFO
  `identity_predicate`, in `identity_notes`, and in
  `70-identity-notes.md`, and the probes report the row count for that
  policy without comparing it (see below).
- A table with RLS enabled on which no mapped role gets a read policy
  (no policies at all, policies that name only unmapped roles, or
  policies for INSERT, UPDATE, or DELETE only) would allow everything on
  BigQuery once nothing is written, so the planner emits `rls_deny_all`
  with `FILTER USING (FALSE)` granted to `admin_principal` and a WARNING
  (`rls_deny_all`, or `rls_deny_all_unassigned` when no admin principal
  is configured). The demo has no such table.
- Mapped bypass roles (superuser, BYPASSRLS, or the owner when RLS is not
  forced; ownership is inherited through membership) get
  `rls_bypass_<role>` with `FILTER USING (TRUE)`. None are mapped in the
  demo.
- Policies for INSERT, UPDATE, or DELETE and any WITH CHECK clause cannot
  be carried (row access policies filter reads and DML targets but cannot
  check new rows): WARNING `policy_command_unmapped`.
- A `security_barrier` view is flagged (WARNING `security_barrier_view`),
  never translated.

## The translator and the review gate

`bq_predicate.translate` is rule-based text rewriting, conservative by
design. It handles casts (`'eu'::text` drops the cast; `'2024-01-01'::date`
becomes `DATE '2024-01-01'`; `'90 days'::interval` becomes `INTERVAL 90
DAY`), `current_user` and `session_user` to `SESSION_USER()` with a note,
`now()` to `CURRENT_TIMESTAMP()`, `ILIKE` to `LOWER(a) LIKE LOWER(b)`,
`= ANY (ARRAY[...])` to `IN (...)`, double-quoted identifiers to backticks,
and table names to the backticked `project.dataset.table` from the
inventory and the dataset map. Anything it does
not fully account for (`current_setting(...)`, a function outside a small
allowlist, a subquery, a regular-expression operator) leaves the result
marked `review` with a note naming the spot.

A `review` predicate blocks `bq-security apply`, and a `review` view body
blocks `bq-schema apply`. The plan phase writes every flagged item with its
source SQL, the auto attempt, the notes, and the table context to
`artifacts/translation-review.json`. The sql-translator subagent answers
with `artifacts/translation-resolutions.json` (`{"views": {...},
"policies": {"schema.table/policy": {"sql", "rationale", "source_sql"}}}`).
The plan is then re-run, and the resolved item carries confidence
`resolved` and the NOTE `translation_resolved`. A resolution counts only
for a review-flagged item, only with a rationale, only while its
`source_sql` still equals the source predicate, and only when its `sql`
is one balanced expression without a semicolon; otherwise the item stays
at `review` with a WARNING naming the reason, because the live backend
hands the filter text to `bq query`, which runs scripts. Gate 1 shows every resolution and its
rationale before anything is provisioned. The demo needs no resolutions:
its review file holds empty `views` and `policies` maps.

## The demo's findings

Thirteen findings, ordered by severity: 0 WARNING, 9 INFO, 4 NOTE. Every
finding carries a subject, a message, and a suggested action, and Gate 1
lists every WARNING verbatim.

| severity | code | subject |
|---|---|---|
| INFO | sequence_unmapped | app_rw |
| INFO | view_write_unmapped | app_rw |
| INFO | privilege_unmapped | postgres (MAINTAIN, REFERENCES, TRIGGER) |
| INFO | sequence_unmapped | postgres |
| INFO | superuser_unmapped | postgres |
| INFO | identity_predicate | public.audit_log/audit_self |
| INFO | rls_denies_role | public.orders/app_ro |
| INFO | view_column_semantics | public.recent_orders |
| INFO | view_rls_semantics | public.recent_orders |
| NOTE | public_schema_usage | PUBLIC |
| NOTE | ownership_not_mapped | owners |
| NOTE | authorized_view | public.recent_orders |
| NOTE | default_privileges_note | public/app_ro |

Codes that the demo does not trigger but a real database may, by
severity. WARNING: `unmapped_role` (a role with privileges and no
principal, listing what it would have received), `public_unmapped`,
`rls_deny_all`, `rls_deny_all_unassigned`, `editor_widens`,
`view_write_widens`, `column_write_unmapped`, `view_column_grant_widens`,
`widened_by_granularity`, `schema_create_widens`, `superuser_mapped`,
`noinherit_not_flattened`, `policy_command_unmapped`,
`security_barrier_view`, `translation_review` (the only code that blocks
apply), and `inventory_without_columns`. INFO: `principal_without_role` (a
map entry for a role the source lacks) and `translation_review_unmapped`.
NOTE: `public_mapped`, `principal_shared` (several roles mapped to one
principal, which holds the union), and `translation_resolved`. The full
table with subjects and meanings is
`skills/security-mapping/references/mapping-rules.md`. The plan also
refuses to run at all when the inventory predates v0.2.0 and has no
`columns` section, since restricted columns cannot be computed without
it.

## Apply order and verification

`bq-security apply` drives the backend in a fixed order: taxonomy, tags,
tag readers, project bindings, dataset access entries (including the
authorized view), table bindings, column tag attachments, row policies. In
the demo that is 22 operations, each recorded as a JSON line in
`artifacts/bq-operations.log`, and the run is idempotent (applying twice
changes nothing). It runs in `migrate_security`, after the tables exist
and before any row is loaded; in live mode `bq-load` refuses to load until
the verification below has passed.

`bq-security verify` reads everything back from the backend and never
consults the apply log. In the demo it produces 23 checks, sorted by name:
one `taxonomy` and one `taxonomy_enforcement` (expected
`FINE_GRAINED_ACCESS_CONTROL`), one `policy_tag`, one `tag_reader`, one
`column_tag` (the tag resource name on `retail.customers.email`), two
`dataset_access`, one `authorized_view`, three `project_binding`, seven
`table_binding`, and five `row_policy` (expected and actual rendered as
`GRANT TO (...) FILTER USING (...)` and compared after whitespace
normalization). The verdict passes only when every check passes and
enforcement is active. A row access policy on a planned table that the
plan does not name appears as a `row_policy_extra:<dataset>.<table>/<name>`
check, and a fine-grained reader on a planned tag that the plan does not
list as a `tag_reader_extra:<tag>:<member>` check; both carry expected
`absent`, and either one fails the whole verification, since a control the
pipeline did not plan can widen access.
The unit suite proves the verifier notices tampering: removing the tag
reader behind the backend's back fails exactly the `tag_reader` check, and
clearing the taxonomy's activation fails the run even when every other
check passes.

## Probes

`bq-security probes` builds, for every mapped role (in live mode, for
every mapped role with a `probe_service_account`, which the backend
impersonates), a set of queries that exercise the controls as that
principal. The expected status comes from the plan (what the target was
told to enforce) and the expected row count from the source (a read-only
`SELECT count(*) ... WHERE <original USING expressions>` run as the
pipeline's own user, which bypasses RLS as owner or superuser and so
counts what the policy allows). Kinds: `row_count` per readable table,
`column_denied` per restricted column the principal cannot read,
`column_allowed` per restricted column it can, and `table_denied` per
table the plan grants it no read role on.

The demo yields 18 probes: for each of the three principals a `row_count`
on each of the five tables, plus `column_denied` on `customers.email` for
`app_ro` and `reporting` and `column_allowed` on it for `app_rw`. No
`table_denied` probes, because every mapped role can read every table on
the source. Three expectations deserve attention:

- `app_ro` on `orders` expects 0 rows (no policy names it), and the
  emulator returns 0.
- `reporting` on `orders` expects the source's count of `region = 'eu'`
  rows, and `app_rw` expects the full count; both are compared exactly
  when the source is reachable (`--no-source` skips the comparison).
- `app_ro` and `reporting` on `audit_log` have an identity predicate. The
  count is reported but not compared, with a note, because the source
  compares a role name and the target an email address; a probe that
  claimed equivalence there would be lying.

An emulated probe is evaluated by the emulator's predicate engine, which
handles `TRUE`, `FALSE`, `col = 'lit'`, `col <> 'lit'`, `col IN (...)`,
`col NOT IN (...)`, `col = SESSION_USER()`, `AND`, `OR`, `NOT`, and
parentheses over STRING columns; anything else is reported as
`unevaluable`, and an unevaluable probe never passes. The
security-validator subagent then reads the plan, the verification, and
the probe results, tries to find a principal, column, or row the plan
claims is protected and is not, and writes `06b-security-validation.md`
with "(emulated)" in every table header when that is the mode.

## What is not carried, in one place

- Identity formats: `current_user` is a role name, `SESSION_USER()` is an
  email. Every affected policy is named.
- WITH CHECK and per-command policies.
- Column-level write privileges.
- Conditional column visibility (security-barrier views).
- Sequences, REFERENCES, TRIGGER, MAINTAIN, ownership, default privileges
  (noted, never widened).
- NOINHERIT roles and `SET ROLE`.
- Anything BigQuery itself does. The emulator proves the pipeline; the
  first live run is the partner team's first task.

## Invariants a reviewer can hold the pipeline to

1. The plan never widens access. Every binding, tag reader, and row policy
   traces to a source privilege, and every case where a BigQuery role is
   necessarily broader than the source privilege is a WARNING at Gate 1.
   `PUBLIC` never becomes `allUsers` or `allAuthenticatedUsers`, and the
   planner rejects both wherever a principal is named.
2. A review-flagged translation is never applied. Both apply verbs refuse
   until a recorded resolution exists, and Gate 1 shows the resolutions.
3. Controls are applied to empty tables, before data. The live loader
   refuses to run without a passing `security-verify.json`.
4. Verification reads back from the target and never trusts the apply
   log, and the probes read as each principal.
5. Rollback deletes only what the pipeline created: the datasets named in
   `target.json` and the migration's taxonomy, after the operator types
   the migration name. The project-level `roles/bigquery.jobUser`
   bindings are left in place and reported, and removed only when the
   operator asks. The export staging files under `artifacts/export/`
   (and their GCS copies) hold every row in plain text, restricted
   columns and RLS-protected rows included. They are removed only by
   `--cleanup` on the run that loads (`bq-load run --migration <name>
   --cleanup`, right after each table's counts match) or by the operator
   by hand; a later `bq-load load --cleanup` refuses the already loaded
   tables and deletes nothing. A reviewer should ask when they were
   removed, since the default keeps them until the cutover runbook's last
   step.
