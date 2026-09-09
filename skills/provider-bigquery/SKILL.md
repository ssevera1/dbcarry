---
name: provider-bigquery
description: Google BigQuery target provider for db-drift, emulated on a laptop or live through bq, gcloud, and the Data Catalog API, with security parity controls
---

# Provider: Google BigQuery

> DOCUMENTED, NOT LIVE-TESTED. The live mode (bq, gcloud, and the Data
> Catalog REST API) was written 2026-09-08 from CLI and API documentation
> and is mock-tested through fake runners in tests/test_bq_backend.py.
> No GCP credentials existed where this was built, so no command in this
> file has run against a real project. The emulated mode is what the
> v0.2.0 acceptance run proves. Before the first live run: verify each
> claim against cloud.google.com/bigquery/docs and
> cloud.google.com/data-catalog/docs, dry-read every command with
> `--help`, and expect the first live run to find differences (that run
> is the IT partners' first task, see docs/HANDOFF.md). Cloud resources
> cost money the moment they exist.

## Modes

`bigquery.mode` in migration.yaml (`emulated` or `live`) selects the
backend. The verbs that touch the target open it through
`bq_backend.make_backend`: `bq-backend status`, `bq-schema apply` and
`verify`, `bq-security apply`, `verify`, and `probes --run`, every
`bq-load` verb, and `bq-validate fingerprint --side target`.
`bq-schema translate`, `bq-security plan`, `bq-security probes` without
`--run`, `bq-validate fingerprint --side source`, and `bq-validate
compare` are pure and read artifacts only. A playbook never branches on
the mode itself; only the prerequisite check and the teardown differ.

### emulated

- A JSON model of one BigQuery project on local disk. State lives at
  `bq_backend.emulated_root(<migration>)`, which is
  `~/.db-drift/bq-emulated/<migration>/` (`DBDRIFT_HOME` replaces
  `~/.db-drift`). `state.json` there holds datasets, tables and their
  schemas, IAM bindings, dataset access lists, taxonomies, policy tags,
  and row access policies; `data/<dataset>/<table>.ndjson.gz` holds the
  loaded rows, line for line as exported (numbers are read as Decimal,
  so NUMERIC and BIGNUMERIC fingerprints are exact). The state file also
  records the workspace that created it: a second working directory
  with the same migration name is refused with both paths named (pick
  another name, or reset from the recorded workspace), and a state file
  from before this key is adopted on first open. Writes are atomic
  (temp file and rename); two loads of one table at the same time are
  not guarded against each other.
- What it proves: the pipeline's own logic, end to end. Plan output,
  apply order, idempotent re-apply, read-back verification, and the
  structural enforcement rules the pipeline relies on: a tagged column
  is readable only with the fine-grained reader role on its tag (nobody
  bypasses, dataset owners included), a table with any row access
  policy denies rows to every principal no policy names, and a
  principal with no data read role at table, dataset, or project scope
  reads nothing. It also proves export fidelity: fingerprints are
  computed over the loaded NDJSON by pure Python, an implementation
  independent of the PostgreSQL SQL.
- What it cannot prove: BigQuery's behavior. It has no SQL engine (views
  and materialized views are recorded and never evaluated;
  `query_json` raises), it evaluates only the predicate subset listed in
  `skills/security-mapping/references/verification.md` and reports
  anything else as `unevaluable`, and it knows nothing about quotas, IAM
  propagation delay, the exact bq and gcloud command forms, or whether
  `bq load` accepts the NDJSON. Label every emulated number as emulated.
- The emulator's state file is also named `state.json`. The PreToolUse
  hook blocks any shell redirect into a file by that name, and hand
  edits are never acceptable anyway. `bq-backend reset --yes`, run from
  the workspace the state file records, is the one sanctioned way to
  clear it.
- A `bytea[]` column exports as an array of base64 strings (each
  element encoded the way a scalar bytea is), so `bq load` reads it as
  `ARRAY<BYTES>`.

### live

- `bq` and `gcloud`. Every bq call carries `--project_id=<project>`;
  reads carry `--format=json`; every `bq ls` carries
  `--max_results=10000` (the default page is 50). DDL, row policy
  creation, counts, and fingerprints run as `bq --project_id=<project>
  --format=json query --use_legacy_sql=false --nouse_cache` with the
  SQL on stdin. An impersonated probe runs `bq --project_id=<project>
  --format=json --oauth_access_token=<token> query
  --use_legacy_sql=false`, also with the SQL on stdin and without
  `--nouse_cache`.
- Taxonomy creation, policy tag creation, and taxonomy deletion go to
  the Data Catalog REST API (`https://datacatalog.googleapis.com/v1`),
  because gcloud has no `taxonomies create`, `policy-tags create`, or
  `taxonomies delete` verb in any release track (checked 2026-09-08).
  The token comes from `gcloud auth print-access-token`, travels in the
  Authorization header only, and is scrubbed from every response, error,
  and log line. Data Catalog location ids are lower case (`us`, `eu`)
  where BigQuery writes `US`, `EU`; the backend lowercases them.
- Documents bq reads from files (table schemas for `bq update`, dataset
  access lists for `bq update --source`) are written under
  `<workspace>/artifacts/bq-work/`.
- Every mutating call on either backend appends one JSON line to
  `<workspace>/artifacts/bq-operations.log`, tokens redacted, so what
  happened is always readable without trusting anyone's summary.

## Prerequisites check

Emulated: `python "$SCRIPTS" bq-backend status --migration <name>` prints
the mode, project, location, emulator root, datasets, and taxonomies as
JSON (empty lists on a fresh migration). A `BQ-BACKEND ERROR` means
migration.yaml is missing, the existing emulator state belongs to
another project or location than migration.yaml names (run `bq-backend
reset --migration <name> --yes` or restore the config), or the migration
name is outside `[A-Za-z0-9_-]+`. Fail the phase on any error.

Live, every check, and fail the provision phase if any one fails:

1. `gcloud auth list` shows an active account.
2. `gcloud config get-value project` returns `bigquery.project` from
   migration.yaml.
3. `bq --project_id=<project> ls --datasets` succeeds (an empty result
   is fine).
4. `gcloud services list --enabled --project=<project>` lists
   `bigquery.googleapis.com` and `datacatalog.googleapis.com`.
   `bigquerydatapolicy.googleapis.com` matters only if the operator
   executes the masking request bodies by hand (see
   `skills/security-mapping/references/policy-tags.md`).
5. The operator's IAM on the project: `roles/bigquery.admin` (datasets,
   tables, table IAM, row access policies, load jobs), plus
   `roles/datacatalog.admin` or at least the taxonomy permissions
   `datacatalog.taxonomies.create`, `.get`, `.list`, `.delete`,
   `.getIamPolicy`, and `.setIamPolicy` (they cover policy tags too),
   plus `resourcemanager.projects.setIamPolicy` (for example
   `roles/resourcemanager.projectIamAdmin`), because the plan binds
   `roles/bigquery.jobUser` at project level through `gcloud projects
   add-iam-policy-binding`.
6. For probes: `roles/iam.serviceAccountTokenCreator` on every
   `probe_service_account` named in `security/principal-map.yaml`, and
   each such service account a member of that role's group so it holds
   exactly the role's access. A role without a probe service account
   gets no live probes at all (the probe set skips it).

`gcloud auth list`, `gcloud config get-value`, and `bq ls` are on the
allowlist in `.claude/settings.json`; the other checks prompt.

## Capability matrix (verify against current docs; dated 2026-09-08)

| Dimension | Support |
|---|---|
| Types | From `bq_types.map_type`: smallint, integer, bigint, serial variants, oid to INT64; numeric(p,s) to NUMERIC when p <= 38 and s <= 9, else BIGNUMERIC when p <= 76 and s <= 38, else STRING with a WARNING (unconstrained numeric is NUMERIC with a precision note); real, double precision to FLOAT64; boolean to BOOL; text, varchar, char, citext, uuid, name, inet, cidr, macaddr to STRING; bytea to BYTES (exported base64); date to DATE; timestamp with time zone to TIMESTAMP; timestamp without time zone to DATETIME; time to TIME; time with time zone to STRING with a WARNING; json, jsonb, hstore to JSON (hstore exported through hstore_to_json); arrays to ARRAY of the element type (nested arrays to ARRAY of JSON); interval, money, xml, geometry, geography, tsvector, tsquery, bit types, and the geometric types to STRING with a WARNING; enum columns and anything unknown to STRING with a WARNING (a domain arrives as its underlying type) |
| Sequences and identity columns | None. Dropped with findings; no sequence bump at cutover; loads carry explicit ids |
| Constraints | PRIMARY KEY and FOREIGN KEY as NOT ENFORCED only (key columns limited to key-capable types, at most 16); UNIQUE, CHECK, EXCLUDE dropped with an INFO; indexes dropped, CLUSTER BY on up to four primary key columns instead |
| Superuser | No such concept. A mapped superuser gets dataOwner on every dataset, reader on every policy tag, and a FILTER USING (TRUE) row policy on every RLS table (WARNING superuser_mapped) |
| Roles and grants | IAM roles dataViewer, dataEditor, metadataViewer, dataOwner at table, dataset, or project scope, plus jobUser on the project to run queries at all. No write-only role: dataEditor also reads |
| Row-level security | Row access policies with OR semantics: a principal sees the union of rows from every policy that names it, and a table with at least one policy shows no rows to anyone no policy names. They filter reads and the target rows of DML; there is no WITH CHECK and no per-command policy |
| Column-level security | Data Catalog policy tags, enforced only while the taxonomy is activated for FINE_GRAINED_ACCESS_CONTROL; one tag per column; read control only, no column-level write control |
| Masking | Data policies through the separate bigquerydatapolicy API. db-drift renders the request bodies (60-masking-requests.json) and does not execute them |
| Views | Views, and authorized views through a dataset access entry. Bodies go through the translator. A view runs with the querying principal's row policies and tags, where PostgreSQL evaluates it as the owner |
| Materialized views | Only when the translated body has none of ORDER BY, LIMIT, HAVING, a set operation, a window function or WINDOW clause, a non-deterministic function, or a view reference; otherwise a plain view with a WARNING. BigQuery caps materialized views per base table (20 at the time of writing) |
| Quotas that matter | Row access policies: 400 per table, 6,000 per query, and 5 CREATE or DROP ROW ACCESS POLICY statements per table per 10 seconds (apply creates them one at a time; a table with many mapped roles can hit it). Policy tags: 100 per taxonomy, 40 taxonomies per project, hierarchy depth 5. Authorized resources: 2,500 per dataset. Verify current values before a large run |
| Identity | Typed principals user:, group:, serviceAccount:, domain:. SESSION_USER() is an email address. No SET ROLE, no session variables |
| Load | bq load NEWLINE_DELIMITED_JSON, append-only: a table that already holds rows is never loaded again by the pipeline; reset (emulated) or tear down (live) before a second migrate_data |

## Provision

Datasets are the only resource provision creates. Tables and views come
in migrate_schema, controls in migrate_security.

1. Read migration.yaml (the `bigquery` block) and confirm
   `artifacts/inventory.json` carries a `columns` section (the v0.2.0
   inventory; an older one makes `bq-schema translate` fail).
2. `python "$SCRIPTS" bq-schema translate --migration <name>` writes
   `artifacts/schema-plan.json`, `artifacts/bq-apply/10-datasets.sh`,
   `artifacts/bq-apply/20-tables.sql`, and the `views` part of
   `artifacts/translation-review.json`. The plan phase already ran it;
   running it again is idempotent and picks up any new resolution.
3. `python "$SCRIPTS" bq-schema apply --migration <name> --datasets-only`
   creates every dataset in the plan and keeps existing ones. In live
   mode the backend runs `bq --project_id=<project> --format=json mk
   --dataset --location=<location> <project>:<dataset>` per dataset;
   `10-datasets.sh` is the same sequence rendered for hand review. With
   `--datasets-only`, views still flagged for review do not block.
4. Verify: `python "$SCRIPTS" bq-backend status --migration <name>` lists
   every dataset named in `schema-plan.json` under `datasets`.
5. Write `artifacts/target.json` in exactly this shape:

   ```json
   {
     "provider": "bigquery",
     "mode": "emulated",
     "project": "<bigquery.project>",
     "location": "<bigquery.location>",
     "datasets": ["retail"],
     "taxonomy": "dbdrift_<migration>"
   }
   ```

   No host, port, user, or password_env: there is nothing to connect
   to. No `bq-*` verb reads target.json (they read migration.yaml);
   it is the record the rollback playbook deletes from and the status
   playbook reports.
6. Instance class: not applicable, BigQuery is serverless. Record
   `on-demand` and the cost line below in 03-provision.md, together with
   the teardown commands that undo the provision.

## Connect

- bq: `bq --project_id=<project> --format=json <verb> ...`; gcloud:
  `--project=<project>`. Both use the gcloud credentials: `gcloud auth
  login` for a person, or application default credentials (`gcloud auth
  application-default login`, or a service account key named by the
  `GOOGLE_APPLICATION_CREDENTIALS` env var; only the env var NAME ever
  appears in files, prompts, or output).
- sslmode: not applicable; the APIs are HTTPS.
- The source connection is unchanged: the `source` block of
  migration.yaml, read-only, as in every other provider.
- Emulated: nothing to connect to; the backend opens the state file.

## Teardown

Irreversible either way; the caller must have collected the typed
migration name first (rollback playbook step 2).

Emulated: `python "$SCRIPTS" bq-backend reset --migration <name> --yes`
removes `~/.db-drift/bq-emulated/<name>/` and refuses any path that is
not a direct child of `bq-emulated`, and refuses when the state file
records a different workspace than the one running the command. Without
`--yes` it prints what it would delete and exits 2.

Live: no `bq-*` verb performs a live teardown; the rollback playbook
runs these, in this order, and records each output:

1. For each dataset in target.json:
   `bq --project_id=<project> rm -r -f -d <project>:<dataset>`. This
   removes the tables, views, and row access policies, and detaches
   every policy tag from the columns that carried one.
2. Find the taxonomy: `gcloud data-catalog taxonomies list
   --location=<location, lower case> --project=<project> --format=json`
   and take the entry whose `displayName` equals target.json's
   `taxonomy`. Delete it by full resource name:
   `curl -sS -X DELETE -H "Authorization: Bearer $(gcloud auth
   print-access-token)"
   https://datacatalog.googleapis.com/v1/projects/<project>/locations/<location>/taxonomies/<id>`.
   The shell expands the token inside the header; never echo it.
3. Order matters: a policy tag still attached to a column cannot be
   deleted, so the taxonomy delete fails while any attachment exists.
   Deleting the datasets first removes the attachments. If a table the
   pipeline never planned carries one of the migration's tags, detach
   it by hand (`bq update` with a schema that drops the `policyTags`
   entry) before step 2.
4. Left behind on purpose: the project-level `roles/bigquery.jobUser`
   bindings the plan added. List them from `gcloud projects
   get-iam-policy <project> --format=json` for the plan's members,
   report them, and remove them only when the operator asks
   (`gcloud projects remove-iam-policy-binding <project> --member=<m>
   --role=roles/bigquery.jobUser --condition=None`).
5. Staging: `artifacts/export/*.ndjson.gz` and any GCS copies under
   `gs://<gcs_bucket>/db-drift/<migration>/` hold every row in plain
   text. Delete them (`bq-load load --cleanup` did it per table when
   counts matched; otherwise by hand).

## Cost

Emulated: free, disk only (the loaded copies are about the size of the
gzipped export).

Live, verify current pricing before quoting: storage on the order of
$0.02 per GB-month for active logical storage; on-demand queries $6.25
per TB scanned, with a monthly free allowance for both. Policy tags,
taxonomies, and row access policies have no price of their own. The
validate phase scans every table once on the target for fingerprints,
and probes scan the RLS tables again per mapped role. State in the plan
and provision report: `<data bytes> x $0.02/GB-month` plus roughly one
full scan for validation, and "verify current pricing".

## Known limitations

- Live BigQuery execution is not live-tested in this repository (see
  the banner). Treat every live command as a correct map of the
  documented surface that has never been exercised.
- Identity formats differ: PostgreSQL `current_user` is a role name and
  BigQuery `SESSION_USER()` is an email address. A predicate comparing a
  column with identity is translated, flagged (INFO identity_predicate,
  a line in 70-identity-notes.md), and its probe count is reported
  without a source comparison. The demo's `audit_self` policy shows
  this: `actor` holds role-style names, so `app_ro` sees zero rows on
  the target until the data or the predicate is remapped. The pipeline
  cannot fix that.
- Row access policies cannot express WITH CHECK or per-command
  differences (WARNING policy_command_unmapped).
- A policy tag attaches to a whole column and cannot carry a condition.
  A security-barrier view that implements conditional visibility is
  flagged (WARNING security_barrier_view) and left untranslated.
- The emulator proves pipeline logic and export fidelity and nothing
  about BigQuery's behavior. It evaluates a small predicate subset and
  reports the rest as `unevaluable`, and it never evaluates a view body.
- No column-level write control (WARNING column_write_unmapped), no
  write-only role (WARNING editor_widens), no SET ROLE (WARNING
  noinherit_not_flattened), and the inventory lists columns for tables
  only, so a column grant on a view exposes the whole view (WARNING
  view_column_grant_widens).
- Datastream (continuous replication into BigQuery) is not in v0.2.0.
  The only strategy is `bulk_load`; a `low` downtime tolerance produces
  a NOTE pointing at Datastream, nothing more.
- No partitioning advisor. Tables are clustered on up to four primary
  key columns and never partitioned; partition design is the operator's
  job after the first run.
- Masking is rendered, never executed (no CLI surface for data
  policies).
- Live rollback leaves the project-level jobUser bindings in place (see
  Teardown) and never touches anything outside target.json's datasets
  and the migration's taxonomy.
- Data Catalog may report a tag's resource name with the project number
  where a BigQuery table schema reports it with the project id; verify
  compares the two without the project segment.
- On Windows, psql receives `-c` arguments in the ANSI code page, so a
  table or column name with characters outside ASCII cannot be exported
  or fingerprinted; the affected verbs say so.
- Export staging files are plain text and include RLS-protected rows
  and restricted columns; treat `artifacts/export/` as sensitive and
  remove it once validation passes.
