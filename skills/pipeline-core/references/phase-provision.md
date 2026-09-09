# Provision playbook

Preconditions: `state verify`; `state start-phase --phase provision`
succeeds (this enforces Gate 1 approval; if it fails with a gate error,
send the user to /db-drift:plan).

1. Read migration.yaml (provider, dbname) and artifacts/inventory.json
   (roles). Read ${CLAUDE_PLUGIN_ROOT}/skills/provider-<provider>/SKILL.md.

## Providers: local, gcp, aws, azure

2. Execute the provider's Provision section. For local, the SQL steps
   run as:
   `python -c "import sys; sys.path.insert(0, r'<plugin>/scripts');
   from db_drift import pg;
   pg.run_sql({'host':'127.0.0.1','port':55433,'dbname':'postgres',
   'user':'postgres','password_env':None}, 'CREATE DATABASE \"<dbname>\"')"`
   and likewise for each role DO-block from the provider skill.
3. Write artifacts/target.json:
   {"provider": ..., "host": ..., "port": ..., "dbname": ...,
    "user": ..., "password_env": ..., "instance": "target-<migration>",
    "version": "<from step 4>"}
   For cloud providers `instance` is the cloud resource id.
4. Verify connectivity:
   `python "$SCRIPTS" inventory --host <target host> --port <target
   port> --dbname <dbname> --user <user> [--password-env <e>]
   --server-only`. Record the version it returns into target.json.
5. Write artifacts/03-provision.md: what was created, where, instance
   class, roles created, cost line from the provider skill, and the
   teardown command that undoes it.
6. `state complete-phase --phase provision`. Next: /db-drift:migrate-schema.

## Provider: bigquery

Datasets are the only resource this phase creates; tables and views
come in migrate_schema, controls in migrate_security. No connection
flags exist: every bq-* verb reads the bigquery block of migration.yaml.
Live mode is NOT LIVE-TESTED.

2. Run the Prerequisites check of
   ${CLAUDE_PLUGIN_ROOT}/skills/provider-bigquery/SKILL.md. Emulated:
   `python "$SCRIPTS" bq-backend status --migration <name>` must print
   JSON (mode, project, location, root, datasets, taxonomies); a
   BQ-BACKEND ERROR fails the phase. Live: every check the skill lists
   (gcloud auth list, gcloud config get-value project equal to
   bigquery.project, `bq --project_id=<project> ls --datasets`, the
   enabled services, the operator's IAM); any failure fails the phase.
3. `python "$SCRIPTS" bq-schema apply --migration <name> --datasets-only`
   creates every dataset in artifacts/schema-plan.json (the plan phase
   wrote it; if it is missing, run `python "$SCRIPTS" bq-schema
   translate --migration <name>` first) and keeps existing ones. Writes
   artifacts/schema-applied.json with datasets_only true. Views still
   at review do not block this step.
4. Verify: `python "$SCRIPTS" bq-backend status --migration <name>`
   lists every dataset named under datasets in schema-plan.json.
5. Write artifacts/target.json exactly in this shape:
   {"provider": "bigquery", "mode": "<mode>", "project": "<project>",
    "location": "<location>", "datasets": ["<each dataset>"],
    "taxonomy": "dbdrift_<migration>"}
   No host, port, user, or password_env. No bq-* verb reads
   target.json; it is the record rollback deletes from and status
   reports.
6. Write artifacts/03-provision.md: mode (emulated numbers labeled),
   project, location, datasets created with their source schemas, the
   taxonomy migrate_security will create, instance class "on-demand
   (serverless)", the cost line from the provider skill, the
   create_dataset lines from artifacts/bq-operations.log, and the
   teardown commands that undo this phase (emulated:
   `python "$SCRIPTS" bq-backend reset --migration <name> --yes`; live:
   the skill's Teardown list).
7. `state complete-phase --phase provision`. Next: /db-drift:migrate-schema.

On any provider command failure: `state fail-phase --phase provision
--reason <r>`, report the raw error, and stop. Never retry resource
creation blindly; a half-created cloud resource costs money.
