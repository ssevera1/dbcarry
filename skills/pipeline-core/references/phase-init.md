# Init playbook

Creates the migration workspace. `$ARGUMENTS` is the migration name;
if empty, ask for one (lowercase, hyphens, no spaces).

1. If ./migrations/<name>/ already exists, stop and point the user at
   /db-drift:status.
2. Gather, via AskUserQuestion (one batch): engine (postgres; mysql is
   accepted but explain execution ships later), target provider (local,
   gcp, aws, azure), downtime tolerance (low or flexible), source host,
   port, dbname, user, and the NAME of the env var holding the password
   (empty means trust or .pgpass). Sensible demo defaults: 127.0.0.1,
   55432, retail, postgres, empty, provider local, tolerance low.
3. Run `python "$SCRIPTS" state --migration <name> init
   --engine <engine> --provider <provider>`.
4. Write ./migrations/<name>/migration.yaml exactly in this shape:

   ```yaml
   # db-drift migration config. Secrets live in env vars; only names here.
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

5. Connectivity check (read-only): run
   `python "$SCRIPTS" inventory --host <h> --port <p> --dbname <d>
   --user <u> [--password-env <e>] --server-only`.
   On failure: report the error, suggest fixes (is the instance running,
   is the env var exported), and leave state as initialized; init is
   still successful, assess will retest.
6. Tell the user the workspace path and that /db-drift:assess is next.
