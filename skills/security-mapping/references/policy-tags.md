# Policy tags (column-level security)

How PostgreSQL column privileges become enforced BigQuery column-level
security, and what that costs in behavior. Code: `build_tags`,
`build_masking`, `apply_plan`, and `verify_plan` in
`scripts/db_carry/bq_security.py`; `EmulatedBackend` and `LiveBackend`
in `bq_backend.py`. Live mechanics are NOT LIVE-TESTED.

## Activation is what enforces

A Data Catalog taxonomy created without `activatedPolicyTypes:
["FINE_GRAINED_ACCESS_CONTROL"]` only labels columns; every principal
with table read keeps reading them. The plan creates
`dbcarry_<migration>` with that activation, `apply_plan` reuses an
existing taxonomy of that display name, and `verify_plan` reads the
taxonomy back and reports `taxonomy_enforcement` (expected
`FINE_GRAINED_ACCESS_CONTROL`) plus the top-level `enforcement_active`
flag. The verify verdict fails whenever tags are planned and the
activation is missing, even if every other check passes. Live:
`gcloud data-catalog taxonomies describe <id> --location=<loc>
--project=<project> --format=json` shows `activatedPolicyTypes`.

## One tag per allowed-reader set

Per table, the readable column set of each reader is every column
(table SELECT) or the columns with column-level SELECT. A column some
reader cannot read is restricted; restricted columns of one table with
the same allowed-reader set share one tag, named
`<table>__<first_column>` plus `_and_<k>_more`, sanitized to
`[A-Za-z0-9_]`, dataset-prefixed on a cross-table collision. The tag's
description names the source columns and their readers. A table with
one restricted column and one reader set therefore gets one tag; a
table whose readers each see a different subset gets one tag per
distinct subset. Superusers do not shape the restricted set (they
bypass column privileges), and a mapped superuser is added as a reader
of every tag.

Demo: `customers__email`, source column `public.customers.email`,
readers `app_rw`. `app_ro` and `reporting` (through inheritance) keep
`dataViewer` on the table and no reader role on the tag.

## The fine-grained reader role

Each allowed reader's principal gets
`roles/datacatalog.categoryFineGrainedReader` on the tag resource
(never on the table). Live: `gcloud data-catalog taxonomies policy-tags
add-iam-policy-binding <tag id> --taxonomy=<taxonomy id>
--location=<loc> --project=<project> --member=<principal>
--role=roles/datacatalog.categoryFineGrainedReader`; read back with
`get-iam-policy`. Nobody bypasses a tag: a dataset owner, a project
admin, and the migration identity itself all need the reader role to
select a tagged column, and the emulator enforces the same rule, so an
emulated probe that reads a tagged column as a dataOwner without the
role is denied too.

Attachment goes through the table schema: `bq show --schema` (live) or
the emulator's stored fields, set `"policyTags": {"names":
["<tag resource name>"]}` on each column, then `bq update
<project>:<dataset>.<table> <schema file>`. `apply_plan` does this after
`bq-schema apply` created the tables and fails with a clear message if
a column is missing. The load schema `bq-load` uses is the one read back
from the table, so a live load never strips the tags. Data Catalog may
report the tag's resource name with the project number where the table
schema reports it with the project id; verify compares the two without
the project segment.

## The SELECT * consequence

A principal with `dataViewer` on the table but without the reader role
on a tag cannot run `SELECT *` against that table, and cannot name the
tagged column in any query: BigQuery returns an access error for the
whole query. It must list only the columns it may read. PostgreSQL
behaves the same for a table with column privileges (`SELECT *` fails
with permission denied), so the consequence is parity, and it still
deserves a sentence in the plan and the report: any application that
selected `*` from a column-restricted table as that role breaks on the
target exactly as it would have on the source.

The probes prove it: `column_denied` for each restricted column the
role cannot read expects `denied`; `column_allowed` expects `ok`; the
role's `row_count` probe selects only the columns it may read (demo:
`app_ro` on `customers` selects `id`, `full_name`, `created_at`).

## Masking, and why it is off by default

`column_security: policy_tags_with_masking` adds, per tag, a data
policy request body: `dataPolicyId` `mask_<tag>`, type
`DATA_MASKING_POLICY`, rule `ALWAYS_NULL`, and
`roles/bigquerydatapolicy.maskedReader` for the principals that can read
the table but not the column. `bq-security plan` writes them to
`artifacts/bq-apply/60-masking-requests.json` for
`bigquerydatapolicy.googleapis.com` `dataPolicies.create`, with the
policy tag resource name to be filled in after apply. dbcarry does not
execute them: there is no CLI surface for data policies, and verify
does not read them back.

The default is `policy_tags` (deny) because PostgreSQL column
privileges deny; they never mask. Masking would turn an access error
into a NULL value, so a query that fails on the source would succeed
with different data on the target, and the probes could no longer tell
a denial from a mask. Choose masking only when the target's consumers
need it, and say so in the plan.

## No column-level write control

BigQuery has no per-column INSERT or UPDATE. A column-level write grant
on the source produces WARNING `column_write_unmapped`, and the role's
table-level binding decides: a write on the table becomes `dataEditor`
on the whole table, and a role with column-level writes only keeps
read access. The action in the finding says it: give the write path a
service account of its own with table-level write, or keep the column
read-only on the target.

Related limits:

- The inventory lists columns for tables only. A column-level SELECT on
  a view maps to `dataViewer` on the view with WARNING
  `view_column_grant_widens`; no tag protects the other columns.
- Tags apply to the querying principal even through an authorized
  view, where PostgreSQL lets view readers see restricted base columns
  through the view's owner (INFO `view_column_semantics`). Grant the
  reader role to the view's readers when they need those columns.
- A tag attaches to a whole column and cannot carry a condition. A
  security-barrier view that hides a column conditionally is flagged
  (WARNING `security_barrier_view`) and left untranslated.
- Data Catalog quotas at the time of writing: 100 policy tags per
  taxonomy, 40 taxonomies per project, one tag per column. Verify
  current values.
- Rollback: a tag attached to a column cannot be deleted, and the
  taxonomy cannot be deleted while any of its tags is attached. The
  provider skill's teardown deletes the datasets first, which detaches
  every tag, then the taxonomy.
