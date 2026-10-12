"""PreToolUse hook: refuse hand edits to a migration's state.json.

Claude Code runs this before an Edit, Write, MultiEdit, NotebookEdit,
Bash, or PowerShell tool call and passes the call as JSON on stdin:

    {"tool_name": "Edit", "tool_input": {"file_path": "...", ...}}

Exit code 2 blocks the call and shows stderr to the model. Exit code 0
allows it and prints nothing. Hard rule 1 of skills/pipeline-core/SKILL.md
says the state file is never hand-edited: every transition goes through
`python scripts/dbcarry.py state ...`, which validates the transition and
appends to the decision log. This hook makes that rule mechanical.

The guard is an allowlist, not a list of known write markers. Three
rules decide a call:

1. An editing tool (Edit, Write, MultiEdit, NotebookEdit) whose target
   path ends in state.json under a migrations directory is refused. The
   path is judged as written, after os.path.normpath, after expanding
   the 8.3 short names MIGRAT~1 and STATE~1.JSO, and (when the path
   exists) after os.path.realpath, so a symlink, a directory junction,
   or a `..` segment that lands on the state file is refused too. The
   last component is compared the way Windows opens it: trailing spaces
   and dots are ignored and an NTFS stream suffix (`state.json::$DATA`)
   names the same file.

2. A Bash or PowerShell command that mentions state.json is refused
   unless the whole command is a read-only form. The command text is
   normalized first (backslashes before letters removed so `state.js\\on`
   reads as `state.json`, quote characters and `$'...'` wrappers removed,
   `{,}` and `{a,b}` brace forms expanded, 8.3 short names expanded, and
   lowercased). A read-only form means: every `;`, `&&`, `||`, `&`, or
   newline separated segment starts with cat, head, tail, less, more,
   grep, rg, egrep, wc, stat, ls, dir, diff, jq, type, Get-Content, gc,
   Select-String, sls, Test-Path, `git status|diff|log|show`, or
   `python <path to dbcarry.py> state` (the script path may be relative,
   absolute, quoted, or `$SCRIPTS`); every pipe stage after the first is
   a known filter (the same readers plus sort, uniq, cut, tr, column,
   nl, sed, awk, Select-Object, ConvertFrom-Json, Format-List, and their
   kin) that itself names neither state.json nor a migrations path; the
   only redirects are descriptor dups (`2>&1`) or null sinks
   (`/dev/null`, `nul`, `$null`); and there is no command substitution,
   process substitution, .NET static call, or Invoke-Expression. A pipe
   into `python -c`, `python -`, tee, sponge, xargs, Out-File,
   Set-Content, or anything else not on the filter list is refused,
   because the guard cannot tell a reading interpreter from a writing
   one. When in doubt the call is refused and the reason names the
   state CLI.

   The practical consequence, seen in the acceptance run: a heredoc
   that writes a report mentioning state.json (`cat > report.md
   <<EOF ... state.json ... EOF`) is refused because it has a redirect
   and is not a read-only form. That is intended; produce such a file
   with the Write tool, which is judged by its path alone.

3. A Bash or PowerShell command that deletes, moves, renames, copies
   over, or writes into a migrations directory is refused whether or
   not it spells out state.json. That is any of rm, rmdir, rd, del,
   erase, ren, mv, move, cp, copy, xcopy, robocopy, rsync, install,
   unlink, shred, sponge, tee, truncate, dd, ln, curl, wget, `find`
   with -delete or -exec, sed or perl or awk in place, Remove-Item, ri,
   Move-Item, mi, Rename-Item, rni, Copy-Item, cpi, New-Item or ni with
   -Force or -Value, Clear-Content, clc, Set-Content, sc, Add-Content,
   ac, Out-File, Export-Csv, Export-Clixml, Tee-Object,
   Invoke-WebRequest, iwr, or a `[IO.*]::` or `[System.IO.*]::` static
   call, together with either a migrations path (the segment
   `migrations`, or MIGRAT~1) or a bare glob whose last component could
   match state.json (`*.json`, `state.js*`, `*`, `*/*/*.json`). A glob
   under a literal directory that is not migrations (`rm -rf sandbox/*`)
   and a removal that never mentions migrations (`rm -rf sandbox/release`)
   pass, since sandbox cleanup is legitimate. A single, unpiped, unredirected
   `python .../dbcarry.py <verb>` call is exempt from this rule so a
   `--reason` string may mention rm and a path.

What remains uncovered, by design of a text-only guard: a symlink or
junction created earlier and then written through a name that never
mentions migrations or state.json; a directory removed above the
migrations directory (`rm -rf sandbox/x` when the workspace root is
sandbox/x); interpreter code that builds the file name at runtime from
pieces that never spell state.json; and a name assembled from a shell
variable set in an earlier Bash call. The state CLI's `verify` verb is
what catches damage from those.

Everything else is allowed, including Read, git, the state CLI itself,
plain reads such as `cat migrations/x/state.json`, an Edit on
`migrations/x/migration.yaml`, and a sibling file such as
`state.json.bak` under either rule.

The hook never crashes on unexpected input. Anything it cannot interpret
(bad JSON, a non-object payload, missing keys) is allowed with exit 0 so a
malformed payload cannot wedge a session. decide() is pure so tests can
drive it without a subprocess. Standard library only.
"""
import json
import os
import re
import sys

EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
SHELL_TOOLS = {"Bash", "PowerShell"}
PATH_KEYS = ("file_path", "notebook_path")
STATE_FILE = "state.json"
MIGRATIONS_DIR = "migrations"

STATE_CLI = "python scripts/dbcarry.py state --migration <name> <verb> ..."

# 8.3 short names Windows may hand back for the two directory and file
# names the guard cares about. Expanded before every comparison.
SHORT_NAMES = (
    (re.compile(r"migrat~1", re.IGNORECASE), MIGRATIONS_DIR),
    (re.compile(r"state~1\.jso", re.IGNORECASE), STATE_FILE),
)

# A mention of the state file: the name as a whole word, so state.json.bak
# and my-state.json are siblings, while `state.json.` (trailing dot),
# `state.json::$DATA`, and `state.json{,}` are the file itself.
STATE_MENTION = re.compile(r"(?<![\w-])state\.json(?![\w-]|\.\w)")

# A mention of a migrations directory: the segment as a whole word.
MIGRATIONS_MENTION = re.compile(r"(?<![\w.-])migrations(?![\w.-])")

# Separators between commands, found on the quote-masked text. `&` alone
# is a separator unless it belongs to `2>&1`, `&>`, `>&`, or `|&`.
SEPARATORS = re.compile(r";|&&|\|\||\n|(?<![<>|\d])&(?![>&<\d])")
PIPES = re.compile(r"\|&?")

# A redirect and its target, on the quote-masked text. `->`, `>=`, `=>`
# are not redirects. The target is allowed only when it is a descriptor
# dup or a null sink; anything else (a file, a variable, a quoted name
# that masking blanked, a process substitution) refuses the call.
REDIRECT = re.compile(r"(?<![-=<>])(?:\d|&|\*)?>>?\|?(?!=)\s*(\S*)")
NULL_TARGETS = {"&1", "&2", "/dev/null", "nul", "$null"}

# Escapes into arbitrary code that a read-only start cannot vouch for.
CODE_ESCAPE = re.compile(
    r"\$\(|`|<\(|>\(|::"
    r"|(?<![\w-])(?:invoke-expression|iex|start-process|saps|start"
    r"|invoke-command|icm|invoke-item|ii)(?![\w-])"
)

READERS = (
    r"cat|head|tail|less|more|grep|rg|egrep|fgrep|wc|stat|ls|dir|diff|jq"
    r"|type|get-content|gc|select-string|sls|test-path"
)
DBCARRY_SCRIPT = (
    r"(?:\"[^\"]*dbcarry\.py\"|'[^']*dbcarry\.py'|[^\s\"']*dbcarry\.py"
    r"|\"?\$\{?scripts\}?\"?)"
)
PYTHON = r"(?:python3?|py)(?:\.exe)?"
READ_ONLY_START = re.compile(
    r"^(?:" + READERS + r")(?=\s|$)"
    r"|^git\s+(?:status|diff|log|show)(?=\s|$)"
    r"|^" + PYTHON + r"\s+" + DBCARRY_SCRIPT + r"\s+state(?=\s|$)"
)
DBCARRY_CALL = re.compile(
    r"^" + PYTHON + r"\s+" + DBCARRY_SCRIPT + r"\s+[a-z][\w-]*(?=\s|$)"
)

FILTERS = (
    READERS
    + r"|sort|uniq|cut|tr|column|nl|tac|rev|fold|paste|sed|awk"
    r"|select-object|select|where-object|where|\?|convertfrom-json"
    r"|convertto-json|format-list|fl|format-table|ft|format-custom"
    r"|format-wide|out-string|out-host|oh|out-null|measure-object|measure"
    r"|sort-object|group-object|group"
)
FILTER_START = re.compile(r"^(?:" + FILTERS + r")(?=\s|$)")
# Filters whose argument legitimately contains braces (a jq object, an
# awk program, a regex quantifier). Any other filter stage with a brace
# is carrying a scriptblock and is refused.
BRACE_FILTERS = re.compile(
    r"^(?:jq|awk|sed|grep|rg|egrep|fgrep|select-string|sls)(?=\s|$)")

# Deleters, movers, copiers, and writers. Matched on the original-case
# text with IGNORECASE except perl's switch cluster, which is
# case-sensitive so `-Ilib` does not count.
WRITERS = re.compile(
    r"(?<![\w.-])(?:rm|rmdir|rd|del|erase|ren|rename|mv|move|cp|copy|xcopy"
    r"|robocopy|rsync|install|unlink|shred|sponge|tee|truncate|dd|ln|curl"
    r"|wget|remove-item|ri|move-item|mi|rename-item|rni|copy-item|cpi"
    r"|clear-content|clc|set-content|sc|add-content|ac|out-file"
    r"|export-csv|export-clixml|tee-object|invoke-webrequest|iwr"
    r"|invoke-restmethod|irm)(?![\w.-])"
    r"|(?<![\w.-])(?:new-item|ni)(?![\w.-])[^|;&\n]*\s-(?:f|v)\w*"
    r"|(?<![\w.-])find(?![\w.-])[^|;&\n]*\s-(?:delete|exec|execdir|ok|okdir"
    r"|fprint\w*)\b"
    r"|(?<![\w.-])sed(?![\w.-])[^|;&\n]*(?:\s-\w*i\w*|--in-place)"
    r"|(?<![\w.-])perl(?![\w.-])[^|;&\n]*(?-i:\s-[pnlwa0-9]*i)"
    r"|(?<![\w.-])awk(?![\w.-])[^|;&\n]*(?<![\w.-])inplace(?![\w.-])"
    r"|\[(?:system\.)?io\.\w+\]::",
    re.IGNORECASE,
)


def _reason(what):
    return (
        f"dbcarry guard: refusing {what}. A migration's state.json is never "
        "hand-edited (pipeline-core hard rule 1). Change state through the "
        f"state CLI instead: {STATE_CLI} (verbs: init, start-phase, "
        "complete-phase, fail-phase, approve-gate, decline-gate, set-strategy, "
        "mark-rollback, verify, show). Read it with cat, Get-Content, or "
        "`state show`, one read-only command at a time with no redirect; "
        "write reports and other files with the Write tool."
    )


# ----------------------------------------------------------- editing tools

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


def _expand_short_names(text):
    for pattern, replacement in SHORT_NAMES:
        text = pattern.sub(replacement, text)
    return text


def _edit_path_forms(path):
    """Every spelling of an edit target that is judged: as written, with
    short names expanded and dot segments folded, and the real path when
    the file exists (so a symlink or junction is followed)."""
    forms = [path]
    expanded = _expand_short_names(path)
    forms.append(expanded)
    try:
        forms.append(os.path.normpath(expanded))
    except (ValueError, TypeError):
        pass
    try:
        if os.path.lexists(path):
            forms.append(os.path.realpath(path))
    except (OSError, ValueError, TypeError):
        pass
    return forms


def _decide_edit(tool, tool_input):
    for key in PATH_KEYS:
        path = tool_input.get(key)
        if not isinstance(path, str):
            continue
        for form in _edit_path_forms(path):
            if _is_migration_state_file(form):
                return 2, _reason(f"{tool} on {path}")
    return 0, ""


# ------------------------------------------------------------ shell tools

def _expand_braces(text, limit=32):
    """Expand `{a,b}` groups into every alternative (bounded)."""
    variants = [text]
    for _ in range(4):
        grown = []
        changed = False
        for item in variants:
            group = next((m for m in re.finditer(r"\{([^{}]*)\}", item)
                          if "," in m.group(1)), None)
            if group is None:
                grown.append(item)
                continue
            changed = True
            for alt in group.group(1).split(","):
                grown.append(item[:group.start()] + alt + item[group.end():])
        if not changed or len(grown) > limit:
            break
        variants = grown
    return variants


def _mention_texts(command):
    """Lowercase spellings of the command for name matching.

    One variant treats a backslash before a character as bash quote
    removal (`state.js\\on`), the other keeps backslashes as Windows path
    separators (`migrations\\x\\state.json`). Both have quote characters
    stripped, short names expanded, and braces expanded.
    """
    low = _expand_short_names(command.lower())
    unescaped = re.sub(r"\\([^\\/\s])", r"\1", low)
    texts = []
    for variant in (unescaped, low):
        variant = variant.replace("$'", "'")
        variant = re.sub(r"[\"']", "", variant)
        variant = variant.replace("{,}", "").replace("{}", "")
        texts.extend(_expand_braces(variant))
    return texts


def _mask_quotes(command):
    """Blank quoted text (keeping length) so separators, pipes, and
    redirects inside quotes are not mistaken for shell syntax.

    Returns the masked text and whether every quote was closed. An
    unbalanced quote means the command cannot be parsed reliably.
    """
    out = []
    quote = None
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if quote:
            if ch == quote:
                quote = None
                out.append(ch)
            elif ch == "\\" and quote == '"' and i + 1 < n:
                out.append("  ")
                i += 1
            else:
                out.append(" ")
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "\\" and i + 1 < n:
            out.append("  ")
            i += 1
        else:
            out.append(ch)
        i += 1
    return "".join(out), quote is None


def _split(text, masked, pattern):
    """Slice `text` at every match of `pattern` in the equally long
    `masked` text; drop empty pieces."""
    pieces, start = [], 0
    for match in pattern.finditer(masked):
        pieces.append((text[start:match.start()], masked[start:match.start()]))
        start = match.end()
    pieces.append((text[start:], masked[start:]))
    return [(t, m) for t, m in pieces if t.strip()]


def _bad_redirect(masked):
    for match in REDIRECT.finditer(masked):
        if match.group(1).lower() not in NULL_TARGETS:
            return True
    return False


def _read_only_problem(command):
    """Why the command is not a read-only form, or None when it is."""
    masked, balanced = _mask_quotes(command)
    if not balanced:
        return "it has an unclosed quote"
    low = command.lower()
    if CODE_ESCAPE.search(low):
        return ("it escapes into other code: a $(...) or `...` substitution, "
                "a process substitution, a .NET static call, or "
                "Invoke-Expression")
    if _bad_redirect(masked):
        return "it has a redirect (only 2>&1 and /dev/null or $null pass)"
    for segment, seg_masked in _split(command, masked, SEPARATORS):
        stages = _split(segment, seg_masked, PIPES)
        if not stages:
            continue
        first = stages[0][0].strip().lower()
        if not READ_ONLY_START.search(first):
            return (f"'{first.split()[0]}' is not a known read-only command "
                    "(cat, head, tail, grep, jq, Get-Content, git diff, "
                    "python scripts/dbcarry.py state, and the like)")
        for stage, _ in stages[1:]:
            stage = stage.strip().lower()
            if not FILTER_START.search(stage):
                return (f"the pipe into '{stage.split()[0]}' is not a known "
                        "read-only filter")
            texts = _mention_texts(stage)
            if any(STATE_MENTION.search(t) or MIGRATIONS_MENTION.search(t)
                   for t in texts):
                return "a pipe stage names state.json or a migrations path"
            if "{" in stage and not BRACE_FILTERS.search(stage):
                return "a pipe stage carries a scriptblock"
    return None


def _glob_translate(basename):
    out = ""
    for ch in basename:
        if ch == "*":
            out += ".*"
        elif ch == "?":
            out += "."
        else:
            out += re.escape(ch)
    return out


def _glob_could_hit_state(texts):
    """A bare glob whose last component could match state.json: no
    directory part, a directory part with its own glob, or a directory
    part under migrations."""
    for text in texts:
        for token in text.split():
            if "*" not in token and "?" not in token:
                continue
            parts = re.split(r"[\\/]+", token)
            base = parts[-1]
            if "*" not in base and "?" not in base:
                continue
            try:
                if not re.fullmatch(_glob_translate(base), STATE_FILE):
                    continue
            except re.error:
                continue
            directory = "/".join(parts[:-1])
            if (not directory or "*" in directory or "?" in directory
                    or MIGRATIONS_MENTION.search(directory)):
                return True
    return False


def _is_bare_dbcarry_call(command):
    masked, balanced = _mask_quotes(command)
    if not balanced or not DBCARRY_CALL.search(command.strip().lower()):
        return False
    if SEPARATORS.search(masked) or PIPES.search(masked):
        return False
    return not _bad_redirect(masked)


def _decide_shell(tool, command):
    texts = _mention_texts(command)
    mentions_state = any(STATE_MENTION.search(t) for t in texts)
    if mentions_state:
        problem = _read_only_problem(command)
        if problem:
            return 2, _reason(f"a {tool} command that names state.json and "
                              f"is not a read-only form: {problem}")
    writer = WRITERS.search(command)
    if writer and not _is_bare_dbcarry_call(command):
        mentions_migrations = any(MIGRATIONS_MENTION.search(t) for t in texts)
        if mentions_migrations or _glob_could_hit_state(texts):
            marker = writer.group(0).strip().split()[0]
            return 2, _reason(f"a {tool} command that removes, moves, copies, "
                              f"or writes into a migrations directory "
                              f"('{marker}' next to a migrations path or a "
                              "glob that could match state.json)")
    return 0, ""


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
        return _decide_edit(tool, tool_input)

    if tool in SHELL_TOOLS:
        command = tool_input.get("command")
        if not isinstance(command, str):
            return 0, ""
        return _decide_shell(tool, command)

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
