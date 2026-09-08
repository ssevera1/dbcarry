# Contributing to db-drift

## Dev setup

- Python 3.10 or newer (developed on 3.13, Windows first; Linux and macOS
  also work). The runtime has no third-party dependencies: every script
  under `scripts/` is standard library only, and that stays true.
- pytest is the only dev dependency: `python -m pip install pytest`.
- For live PostgreSQL checks, `python scripts/dbdrift.py pg ensure-tools`
  downloads a portable PostgreSQL 17 toolchain under `~/.db-drift/pg/`
  (override the location with `DBDRIFT_HOME`). The unit suite does not
  need it.
- For development inside Claude Code, open the repository with
  `claude --plugin-dir .` so the commands, agents, and skills load from
  the working tree. `.claude/settings.json` carries the permission
  allowlist and the state-guard hook.

## Tests

```
python -m pytest -q -p no:cacheprovider
```

Every task follows TDD: write the test, watch it fail, implement, watch it
pass. The suite must be green before a task is done or a commit is made.
Tests use fixtures, never a live database. Live checks are run by hand and
their artifacts go under the gitignored `sandbox/`. Every subprocess call
passes `encoding="utf-8"`, and no script prints a password, a token, or a
full connection URL.

## Adding a provider

A provider is one skill directory, `skills/provider-<name>/SKILL.md`,
fulfilling the contract the playbooks rely on. Follow the headings of an
existing provider (`provider-local` for a runnable one, `provider-bigquery`
for one with emulated and live modes): Prerequisites check, Capability
matrix, Provision, Connect, Teardown, Cost, Known limitations. Provision
writes `artifacts/target.json` in the shape the later phases read.
Teardown is irreversible and requires typed confirmation. A provider that
has not been run against a real account says so in a "Not live-tested"
banner at the top. Playbooks never branch on a provider's name: if you find
yourself editing `skills/pipeline-core/` to special-case your provider,
extend the contract instead.

## Adding a security mapping rule

A mapping rule (how a PostgreSQL privilege, policy, or role attribute
becomes a BigQuery control) lives in three places and has a test:

1. Code: `scripts/db_drift/bq_security.py` (`plan_security` and its
   helpers). The rule emits plan entries and findings, and it never widens
   access beyond the source privilege it maps.
2. Rulebook: `skills/security-mapping/references/mapping-rules.md`, which
   the playbooks and the three security agents read.
3. Reviewer prose: `docs/security-mapping.md`, the same rule explained for
   a security reviewer with the demo as the running example.
4. Test: `tests/test_bq_security.py`, using the demo security fixture.
   Assert the plan entry, the finding code, and the verification
   read-back.

If the rule needs a new planted finding, add it to
`scripts/db_drift/seed_demo.py` and to the table in `demo/scenario.md` so
the emulated demo exercises it.

## Commit messages

Conventional prefixes: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
`chore:`. Subject in the imperative, lower case after the prefix, no
trailing period, under 72 characters. The body explains why when the
subject cannot. No em dashes or en dashes anywhere in the message.

Workers (subagents executing a plan task) do not commit. The orchestrating
session commits after each round, and workers report which files they
touched.

## Prose style

No em dashes or en dashes in anything authored here: docs, docstrings,
comments, commit messages, generated reports. Use a period, a colon,
commas, or parentheses. Number ranges use a plain hyphen (`2020-2024`).
Avoid the related tells too: the "it isn't X, it's Y" construction,
middle-dot separators, long semicolon chains, rule-of-three parallelism.
Do not rewrite existing files only to strip dashes; fix them when editing
that text for another reason. Never alter dashes inside code, string
literals, fixtures, data files, or quoted material.

## State is never hand-edited

`migrations/<name>/state.json` is written only by
`python scripts/dbdrift.py state --migration <name> <verb>`, which
validates each transition against the phase and gate table and appends to
`artifacts/decision-log.md`. Editing it by hand desynchronizes the log from
what ran and lets a gate be skipped.

`scripts/hooks/guard_state.py`, wired as a PreToolUse hook in
`.claude/settings.json` for the Edit, Write, MultiEdit, NotebookEdit,
Bash, and PowerShell tools, enforces this. It exits 2 (blocking the call
and explaining why on stderr) when an Edit, Write, MultiEdit, or
NotebookEdit targets a `state.json` under a `migrations` directory (the
last path component is read the way Windows opens it, so trailing spaces
or dots and a `::$DATA` stream suffix do not evade it), or when a Bash or
PowerShell command mentions `state.json` and either redirects output into
a state.json (`>`, `>>`, `>|`, `1>`, `2>`, `&>`, or dd's `of=`; the target
may mix quoted and bare segments such as `"$WS"/state.json`) or contains
an in-place editor, copier, mover, writer, or deleter anywhere: `sed` with
any in-place flag (`-i`, `-Ei`, `-i.bak`, `--in-place`, `-e ... -i`),
`perl -i` in any cluster (`-pi`, `-i.bak`), `cp`, `mv`, `copy`, `move`,
`rm`, `del`, `tee`, `truncate`, `Set-Content`, `Add-Content`,
`Clear-Content`, `Out-File`, `Copy-Item`, `Move-Item`, or `Remove-Item`.
The markers are over-inclusive on purpose: a command that removes a build
directory and then reads a state.json is refused too, and the fix is to
split it. Reads, `git`, the state CLI itself, redirects that land
elsewhere (`cat migrations/x/state.json 2>>errors.log`), and sibling
files such as `state.json.bak` pass through. Bad or unexpected input allows the call
(exit 0) so the hook can never wedge a session. `decide(payload)` is
pure and tested in `tests/test_hooks.py`; extend the tests before
changing the rules. The hook is a guard against accidents, not a
sandbox: a determined `python -c "open(...).write(...)"` gets past it,
and the state CLI's `verify` verb is what catches the damage.
