# Contributing to dbcarry

## Dev setup

- Python 3.10 or newer (developed on 3.13, Windows first; Linux and macOS
  also work). The runtime has no third-party dependencies: every script
  under `scripts/` is standard library only, and that stays true.
- pytest is the only dev dependency: `python -m pip install pytest`.
- For live PostgreSQL checks, `python scripts/dbcarry.py pg ensure-tools`
  downloads a portable PostgreSQL 17 toolchain under `~/.dbcarry/pg/`
  (override the location with `DBCARRY_HOME`). The unit suite does not
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

1. Code: `scripts/db_carry/bq_security.py` (`plan_security` and its
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
`scripts/db_carry/seed_demo.py` and to the table in `demo/scenario.md` so
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
`python scripts/dbcarry.py state --migration <name> <verb>`, which
validates each transition against the phase and gate table and appends to
`artifacts/decision-log.md`. Editing it by hand desynchronizes the log from
what ran and lets a gate be skipped.

`scripts/hooks/guard_state.py`, wired as a PreToolUse hook in
`.claude/settings.json` (this checkout as the project directory) and in
`hooks/hooks.json` (shipped with the plugin, through
`${CLAUDE_PLUGIN_ROOT}`) for the Edit, Write, MultiEdit, NotebookEdit,
Bash, and PowerShell tools, enforces this. It exits 2 (blocking the call
and explaining why on stderr) in three cases. First, an Edit, Write,
MultiEdit, or NotebookEdit targets a `state.json` under a `migrations`
directory; the path is judged as written, with 8.3 short names expanded
and after `normpath` and `realpath`, so trailing spaces or dots, a
`::$DATA` stream suffix, `MIGRAT~1`, symlinks, and junctions do not
evade it. Second, a Bash or PowerShell command mentions `state.json`
(after backslash, quote, brace-expansion, and 8.3 normalization) and is
not a pure read: every segment must start with an allowlisted reader
(`cat`, `head`, `tail`, `grep`, `rg`, `jq`, `wc`, `ls`, `diff`,
`Get-Content`, `Select-String`, `Test-Path`, `git status|diff|log|show`,
or the state CLI), every pipe stage must be an allowlisted filter, the
only redirects allowed are stream duplication and null devices, and
command substitution, process substitution, `::` static calls,
`Invoke-Expression`, and `Start-Process` are refused. `sed -n`,
`python -c`, and `perl -ne` reads are refused too: the allowlist is
narrow on purpose. Third, without any mention of `state.json`, a
command whose words include a deleter, mover, copier, or writer (`rm`,
`rmdir`, `del`, `mv`, `cp`, `xcopy`, `robocopy`, `rsync`, `install`,
`unlink`, `shred`, `ln`, `dd`, `tee`, `sponge`, `curl`, `wget`, `find
-delete`, `awk -i inplace`, the `*-Item` and `*-Content` cmdlets and
their aliases, `Out-File`, `Export-*`, `[IO.File]::`) together with a
`migrations` path segment or a bare glob that could match `state.json`.
`rm -rf sandbox/release` and a glob under a literal non-migrations
directory pass, and a single unpiped `python .../dbcarry.py <verb>` call
is exempt so a `--reason` text may name a path. A shell heredoc whose
prose mentions `state.json` is refused; write such a report with the
Write tool. Bad or unexpected input allows the call (exit 0) so the hook
can never wedge a session. `decide(payload)` is pure and tested in
`tests/test_hooks.py`; extend the tests before changing the rules. The
hook is a guard against accidents, not a sandbox: it does not see a
symlink written through a name that never mentions `migrations` or
`state.json`, a directory removed above the workspace (`rm -rf
sandbox/x`), a file name built at runtime, or a shell variable set in an
earlier call, and the state CLI's `verify` verb is what catches the
damage.
