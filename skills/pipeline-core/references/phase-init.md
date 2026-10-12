# Init playbook

Creates the migration workspace. `$ARGUMENTS` is the migration name;
if empty, ask for one (lowercase letters, digits, and hyphens, no
spaces). `state init` accepts any name. For provider bigquery the
name also becomes the emulator directory, so bq-security and
bq-backend refuse a name outside [A-Za-z0-9_-] on every call, and so
does every verb that opens the emulated backend; the first refusal
would come from `bq-security plan --template` in assess, after the
workspace exists.

1. If ./migrations/<name>/ already exists, stop and point the user at
   /dbcarry:status.
2. Gather, via AskUserQuestion (one batch): engine (postgres; mysql is
   accepted but explain execution ships later), target provider (local,
   gcp, aws, azure, bigquery), downtime tolerance (low or flexible),
   source host, port, dbname, user, and the NAME of the env var holding
   the password (empty means trust or .pgpass). Sensible demo defaults:
   127.0.0.1, 55432, retail, postgres, empty, provider local, tolerance
   low. For the BigQuery demo: provider bigquery, tolerance flexible.
3. Provider bigquery only: a second AskUserQuestion batch for the
   bigquery block, with these defaults:
   - mode: `emulated` (default; a JSON model on local disk, no GCP
     account) or `live` (bq and gcloud with their own credentials; NOT
     LIVE-TESTED in this repository).
   - project: the GCP project id (any id in emulated mode).
   - location: default `US`.
   - dataset map: PostgreSQL schema to BigQuery dataset; default
     `public` -> the source dbname.
   - admin principal: receives the deny-all and bypass row policies;
     a typed principal such as `user:operator@example.com`.
   - public principal: the BigQuery principal for PostgreSQL PUBLIC
     grants; default empty, which leaves PUBLIC unmapped and denied.
   - column security: `policy_tags` (default) or
     `policy_tags_with_masking` (masking request bodies are rendered,
     never executed).
   - binding granularity: `auto` (default), `dataset`, or `table`.
   - gcs bucket: default empty, so bq load reads the local export
     files; live mode only.
   Recommended principal types are `user:`, `group:`, and
   `serviceAccount:`; `domain:` and `specialGroup:` are accepted;
   allUsers and allAuthenticatedUsers are refused by the planner.
4. Run `python "$SCRIPTS" state --migration <name> init
   --engine <engine> --provider <provider>`.

## Providers: local, gcp, aws, azure

5. Write ./migrations/<name>/migration.yaml exactly in this shape:

   ```yaml
   # dbcarry migration config. Secrets live in env vars; only names here.
   migration: demo-run
   engine: postgres
   provider: local
   downtime_tolerance: low   # low | flexible
   source:
     host: 127.0.0.1
     port: 55432
     dbname: retail
     user: postgres
     password_env: ""
   notes: ""
   ```

## Provider: bigquery

5. Write ./migrations/<name>/migration.yaml exactly in this shape:

   ```yaml
   # dbcarry migration config. Secrets live in env vars; only names here.
   migration: demo-run
   engine: postgres
   provider: bigquery
   downtime_tolerance: flexible
   source:
     host: 127.0.0.1
     port: 55432
     dbname: retail
     user: postgres
     password_env: ""
   bigquery:
     mode: emulated            # emulated | live
     project: my-sandbox-project
     location: US
     dataset_map:              # PostgreSQL schema -> BigQuery dataset
       public: retail
     principal_map: security/principal-map.yaml
     admin_principal: "user:operator@example.com"   # receives deny-all and bypass policies
     public_principal: ""      # BigQuery principal for PostgreSQL PUBLIC grants; empty = unmapped
     column_security: policy_tags   # policy_tags | policy_tags_with_masking
     binding_granularity: auto      # auto | dataset | table
     gcs_bucket: ""            # empty = bq load from local files
   notes: ""
   ```

   `principal_map` is a path relative to the workspace. The assess
   phase writes that file (`bq-security plan --template`) with one
   entry per non-system role and an empty principal; the operator
   fills it in before Gate 1. A role left empty is unmapped: it
   receives nothing on BigQuery and the plan says so with a WARNING.

## All providers

6. Connectivity check (read-only): run
   `python "$SCRIPTS" inventory --host <h> --port <p> --dbname <d>
   --user <u> [--password-env <e>] --server-only`.
   On failure: report the error, suggest fixes (is the instance running,
   is the env var exported), and leave state as initialized; init is
   still successful, assess will retest.
7. Tell the user the workspace path and that /dbcarry:assess is next.
   For bigquery, add that assess writes security/principal-map.yaml and
   that it must be filled in before /dbcarry:plan reaches Gate 1.
