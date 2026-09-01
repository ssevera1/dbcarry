# Demo playbook

Subcommands: `setup` and `teardown`. `$ARGUMENTS` selects one; default is
`setup`.

Set `$SCRIPTS` to `${CLAUDE_PLUGIN_ROOT}/scripts/dbdrift.py`. All commands
run via the shell tool from the user's project directory.

## setup

1. `python "$SCRIPTS" pg ensure-tools` (first run downloads ~300 MB; warn
   the user and run with a long timeout or in background).
2. `python "$SCRIPTS" pg create --name onprem --port 55432` (if it already
   exists, tell the user and skip to start). Do NOT pass --wal-level: the
   demo source deliberately starts at `replica` so the assessment has a
   real finding.
3. `python "$SCRIPTS" pg start --name onprem`
4. `python "$SCRIPTS" seed --port 55432 --dbname retail`
5. Report the seeded counts table, then print next steps for the user:
   the suggested init invocation is
   `/db-drift:init demo-run` with source host 127.0.0.1, port 55432,
   dbname retail, user postgres, no password env var (trust auth,
   localhost demo only), provider local, downtime tolerance low.

## teardown

Destroys demo instances and their data. This is irreversible; require the
user to type the word `teardown` to confirm (AskUserQuestion with an
Other/free-text response is acceptable; a click alone is not).

1. For each instance named `onprem` or starting with `target-` in
   `python "$SCRIPTS" pg list`:
   `pg stop --name <n>` (ignore "not running" errors), then
   `pg destroy --name <n> --yes`.
2. Confirm what was removed. Never touch instances with other names.
