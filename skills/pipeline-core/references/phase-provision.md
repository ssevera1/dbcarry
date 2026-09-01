# Provision playbook

Preconditions: `state verify`; `state start-phase --phase provision`
succeeds (this enforces Gate 1 approval; if it fails with a gate error,
send the user to /db-drift:plan).

1. Read migration.yaml (provider, dbname) and artifacts/inventory.json
   (roles). Read ${CLAUDE_PLUGIN_ROOT}/skills/provider-<provider>/SKILL.md.
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

On any provider command failure: `state fail-phase --phase provision
--reason <r>`, report the raw error, and stop. Never retry resource
creation blindly; a half-created cloud resource costs money.
