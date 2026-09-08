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
- A Bash (or PowerShell) command that mentions state.json together with
  a write or delete marker: a redirect whose target is a state.json (any
  of `>`, `>>`, `>|`, `1>`, `2>`, `&>`, quoted or not), or `sed -i`,
  `Set-Content`, `Out-File`, `tee`, `rm`, `del`, or `Remove-Item`
  anywhere in the command.

Everything else is allowed, including Read, git, the state CLI itself,
plain reads such as `cat migrations/x/state.json`, and a redirect that
lands somewhere else (`cat migrations/x/state.json 2>>errors.log`).

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

# A redirect whose target is a state.json. The operator is `>`, `>>`, or
# `>|`, optionally prefixed by a descriptor digit or `&` (so `1>`, `2>`,
# `&>` all count), and must not be the comparison `>=`. The target is the
# next token: a double-quoted string, a single-quoted string, or a bare
# word that stops at whitespace, quotes, or another shell operator. Only
# a target ending in state.json matters, so `cat state.json > /dev/null`
# and `cat state.json 2>>errors.log` pass.
REDIRECT_INTO_STATE = re.compile(
    r"(?:\d|&)?>>?\|?(?!=)\s*"
    r"(?:\"[^\"]*state\.json\b"
    r"|'[^']*state\.json\b"
    r"|[^\s\"'<>|;&]*state\.json\b)",
    re.IGNORECASE,
)

# In-place editors, writers, and deleters. Any of these anywhere in a
# command that also mentions state.json blocks the call. Over-inclusive
# on purpose (`rm -rf build; cat migrations/x/state.json` is refused):
# the model can split the command, and a missed write cannot be undone.
DESTRUCTIVE_MARKERS = re.compile(
    r"\bsed\s+-i\b"
    r"|\bSet-Content\b"
    r"|\bOut-File\b"
    r"|\btee\s"
    r"|\brm\s"
    r"|\bdel\s"
    r"|\bRemove-Item\b",
    re.IGNORECASE,
)

STATE_CLI = "python scripts/dbdrift.py state --migration <name> <verb> ..."


def _reason(what):
    return (
        f"db-drift guard: refusing {what}. A migration's state.json is never "
        "hand-edited (pipeline-core hard rule 1). Change state through the "
        f"state CLI instead: {STATE_CLI} (verbs: start-phase, complete-phase, "
        "fail-phase, approve-gate, decline-gate, set-strategy, mark-rollback, "
        "verify, show)."
    )


def _is_migration_state_file(path):
    parts = [p for p in re.split(r"[\\/]+", path) if p]
    if len(parts) < 2 or parts[-1].lower() != STATE_FILE:
        return False
    return any(p.lower() == MIGRATIONS_DIR for p in parts[:-1])


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
        if REDIRECT_INTO_STATE.search(command):
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
