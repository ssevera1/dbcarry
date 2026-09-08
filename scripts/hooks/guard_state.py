"""PreToolUse hook: refuse hand edits to a migration's state.json.

Claude Code runs this before an Edit, Write, MultiEdit, NotebookEdit, or
Bash tool call and passes the call as JSON on stdin:

    {"tool_name": "Edit", "tool_input": {"file_path": "...", ...}}

Exit code 2 blocks the call and shows stderr to the model. Exit code 0
allows it and prints nothing. Hard rule 1 of skills/pipeline-core/SKILL.md
says the state file is never hand-edited: every transition goes through
`python scripts/dbdrift.py state ...`, which validates the transition and
appends to the decision log. This hook makes that rule mechanical.

Two shapes are refused:

- An editing tool whose target path ends in state.json under a
  migrations directory (any depth, either path separator, any case).
  The last path component is compared the way Windows opens it:
  trailing spaces and dots are ignored, and an NTFS stream suffix
  (`state.json::$DATA`, `state.json:name`) names the same file.
- A Bash (or PowerShell) command that mentions state.json together with
  a write or delete marker. Either a redirect whose target names a
  state.json (any of `>`, `>>`, `>|`, `1>`, `2>`, `&>`, and dd's `of=`;
  the target may mix quoted and bare segments, as in `"$WS"/state.json`
  or `'migrations/x'/state.json`), or an in-place editor, copier, mover,
  writer, or deleter anywhere in the command: `sed` with an in-place
  flag (`-i`, `-Ei`, `-i.bak`, `--in-place`, or `-i` after `-e`), `perl`
  with `-i` (`-pi`, `-i.bak`), `cp`, `mv`, `copy`, `move`, `rm`, `del`,
  `tee`, `truncate`, `Set-Content`, `Add-Content`, `Clear-Content`,
  `Out-File`, `Copy-Item`, `Move-Item`, or `Remove-Item`.

Everything else is allowed, including Read, git, the state CLI itself,
plain reads such as `cat migrations/x/state.json`, a redirect that
lands somewhere else (`cat migrations/x/state.json 2>>errors.log`), and
a sibling file such as `state.json.bak` under either rule.

The hook never crashes on unexpected input. Anything it cannot interpret
(bad JSON, a non-object payload, missing keys) is allowed with exit 0 so a
malformed payload cannot wedge a session. decide() is pure so tests can
drive it without a subprocess. Standard library only.
"""
import json
import re
import sys

EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
SHELL_TOOLS = {"Bash", "PowerShell"}
PATH_KEYS = ("file_path", "notebook_path")
STATE_FILE = "state.json"
MIGRATIONS_DIR = "migrations"

# A redirect operator and its target. The operator is `>`, `>>`, or `>|`,
# optionally prefixed by a descriptor digit or `&` (so `1>`, `2>`, `&>`
# all count) and never the comparison `>=`; dd's `of=` counts as one too.
# The target is the whole run of segments that follows with nothing
# between them: double-quoted, single-quoted, or bare characters up to
# whitespace or another shell operator. That makes `"$WS"/state.json`,
# `'migrations/x'/state.json`, and `migrations/x/"state.json"` each one
# target. Quoted segments need their closing quote: a `>` inside a quoted
# argument (`git log --format='%h -> %s' -- migrations/x/state.json`)
# must not swallow the rest of the command as its target. The joined
# target is then checked for a state.json final component (see
# _names_state_file), so `cat state.json > /dev/null`, `cat state.json
# 2>>errors.log`, and `echo x > state.json.bak` pass.
REDIRECT_TARGET = re.compile(
    r"(?:(?:\d|&)?>>?\|?(?!=)\s*|\bof=)"
    r"((?:\"[^\"]*\"|'[^']*'|[^\s\"'<>|;&]+)+)",
    re.IGNORECASE,
)

# In-place editors, copiers, movers, writers, and deleters. Any of these
# anywhere in a command that also mentions state.json blocks the call.
# Over-inclusive on purpose (`rm -rf build; cat migrations/x/state.json`
# is refused): the model can split the command, and a missed write cannot
# be undone. sed's in-place flag may be combined (`-Ei`, `-ni`), carry a
# backup suffix (`-i.bak`), be spelled long (`--in-place`), or come after
# other options (`-e ... -i`), so anything from `sed` to the next pipe or
# separator is scanned for it. perl's `-i` is matched case-sensitively in
# a cluster of the argument-free switches (`-pi`, `-ni`, `-i.bak`) so
# `-Ilib` and `-MJSON` do not count.
DESTRUCTIVE_MARKERS = re.compile(
    r"\bsed\b[^|;&]*(?:\s-\w*i\w*|--in-place)"
    r"|\bperl\b[^|;&]*(?-i:\s-[pnlwa]*i)"
    r"|\b(?:cp|mv|copy|move|rm|del|tee|truncate)\s"
    r"|\b(?:Set-Content|Add-Content|Clear-Content|Out-File"
    r"|Copy-Item|Move-Item|Remove-Item)\b",
    re.IGNORECASE,
)

STATE_CLI = "python scripts/dbdrift.py state --migration <name> <verb> ..."


def _reason(what):
    return (
        f"db-drift guard: refusing {what}. A migration's state.json is never "
        "hand-edited (pipeline-core hard rule 1). Change state through the "
        f"state CLI instead: {STATE_CLI} (verbs: init, start-phase, "
        "complete-phase, fail-phase, approve-gate, decline-gate, set-strategy, "
        "mark-rollback, verify, show)."
    )


def _names_state_file(name):
    """True when a final path component opens the state file on Windows.

    NTFS ignores trailing spaces and dots in a name, and `name::$DATA` or
    `name:stream` addresses a stream of the same file, so those spellings
    are normalized away before the comparison. The rule is applied on
    every platform: none of those spellings is a legitimate sibling file.
    """
    return name.split(":", 1)[0].rstrip(" .").lower() == STATE_FILE


def _is_migration_state_file(path):
    parts = [p for p in re.split(r"[\\/]+", path) if p]
    if len(parts) < 2 or not _names_state_file(parts[-1]):
        return False
    return any(p.lower() == MIGRATIONS_DIR for p in parts[:-1])


def _redirects_into_state_file(command):
    for match in REDIRECT_TARGET.finditer(command):
        target = re.sub(r"[\"']", "", match.group(1))
        parts = [p for p in re.split(r"[\\/]+", target) if p]
        if parts and _names_state_file(parts[-1]):
            return True
    return False


def decide(payload):
    """Return (exit_code, reason). exit_code 2 blocks, 0 allows.

    The reason is empty when the call is allowed.
    """
    if not isinstance(payload, dict):
        return 0, ""
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool, str) or not isinstance(tool_input, dict):
        return 0, ""

    if tool in EDIT_TOOLS:
        for key in PATH_KEYS:
            path = tool_input.get(key)
            if isinstance(path, str) and _is_migration_state_file(path):
                return 2, _reason(f"{tool} on {path}")
        return 0, ""

    if tool in SHELL_TOOLS:
        command = tool_input.get("command")
        if not isinstance(command, str) or STATE_FILE not in command.lower():
            return 0, ""
        if _redirects_into_state_file(command):
            return 2, _reason(f"a {tool} command that redirects output "
                              "into a state.json")
        if DESTRUCTIVE_MARKERS.search(command):
            return 2, _reason(f"a {tool} command that edits, overwrites, "
                              "or removes a state.json")
        return 0, ""

    return 0, ""


def _read_stdin():
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is not None:
        return buffer.read().decode("utf-8", "replace")
    return sys.stdin.read()


def main():
    try:
        payload = json.loads(_read_stdin())
    except Exception:
        return 0
    try:
        code, reason = decide(payload)
    except Exception:
        return 0
    if code:
        sys.stderr.write(reason + "\n")
        sys.stderr.flush()
    return code


if __name__ == "__main__":
    sys.exit(main())
