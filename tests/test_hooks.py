"""Tests for the state-file guard hook and the project settings file."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "scripts" / "hooks" / "guard_state.py"
SETTINGS = ROOT / ".claude" / "settings.json"


@pytest.fixture(scope="module")
def guard():
    spec = importlib.util.spec_from_file_location("guard_state", HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def edit(path, tool="Edit"):
    return {"tool_name": tool, "tool_input": {"file_path": path}}


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


# ------------------------------------------------------------ plan test cases

def test_blocks_edit_on_state_json(guard):
    code, reason = guard.decide(edit("migrations/x/state.json"))
    assert code == 2
    assert "state.json" in reason and "state" in reason.lower()


def test_reason_lists_every_state_cli_verb(guard):
    _, reason = guard.decide(edit("migrations/x/state.json"))
    for verb in ("init", "start-phase", "complete-phase", "fail-phase",
                 "approve-gate", "decline-gate", "set-strategy",
                 "mark-rollback", "verify", "show"):
        assert verb in reason, verb


def test_allows_edit_on_migration_yaml(guard):
    assert guard.decide(edit("migrations/x/migration.yaml")) == (0, "")


def test_blocks_bash_redirect_into_state_json(guard):
    code, reason = guard.decide(bash("echo '{}' > migrations/x/state.json"))
    assert code == 2 and reason


def test_allows_state_cli(guard):
    cmd = "python scripts/dbcarry.py state --migration x show"
    assert guard.decide(bash(cmd)) == (0, "")


def test_allows_read_of_state_json(guard):
    assert guard.decide(edit("migrations/x/state.json", tool="Read")) == (0, "")


def test_settings_json_parses_and_names_hook():
    settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
    pre = settings["hooks"]["PreToolUse"]
    commands = [h["command"] for entry in pre for h in entry["hooks"]]
    assert any("scripts/hooks/guard_state.py" in c for c in commands)
    matchers = [entry["matcher"] for entry in pre]
    assert any("Bash" in m and "Edit" in m and "Write" in m for m in matchers)
    allow = settings["permissions"]["allow"]
    assert "Bash(python scripts/dbcarry.py:*)" in allow
    assert "Bash(python -m pytest:*)" in allow
    assert {"permissions", "hooks"} <= set(settings)


def test_settings_hook_matcher_covers_every_guarded_tool():
    # PowerShell is the primary shell on Windows. A matcher that omits it
    # leaves the guard silent for every PowerShell command.
    settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
    guarded = {"Edit", "Write", "MultiEdit", "NotebookEdit", "Bash",
               "PowerShell"}
    for entry in settings["hooks"]["PreToolUse"]:
        commands = [h["command"] for h in entry["hooks"]]
        if any("guard_state.py" in c for c in commands):
            assert guarded <= set(entry["matcher"].split("|"))


# ------------------------------------------------------- additional coverage

@pytest.mark.parametrize("tool", ["Write", "MultiEdit", "NotebookEdit"])
def test_every_editing_tool_is_blocked(guard, tool):
    code, _ = guard.decide(edit("migrations/demo-run/state.json", tool=tool))
    assert code == 2


def test_notebook_path_key_is_checked(guard):
    payload = {"tool_name": "NotebookEdit",
               "tool_input": {"notebook_path": "migrations/x/state.json"}}
    assert guard.decide(payload)[0] == 2


@pytest.mark.parametrize("path", [
    r"D:\proj\migrations\demo-run\state.json",
    "/home/op/proj/migrations/demo-run/state.json",
    "sandbox/migrations/demo-run/state.json",
    "MIGRATIONS/x/State.json",
    # Windows resolves each of these to the real file.
    "migrations/x/state.json ",
    "migrations/x/state.json.",
    "migrations/x/state.json::$DATA",
    "migrations/x/state.json:stream",
    r"D:\proj\migrations\x\state.json. ",
])
def test_absolute_and_windows_paths_are_blocked(guard, path):
    assert guard.decide(edit(path))[0] == 2


@pytest.mark.parametrize("path", [
    "state.json",
    "config/state.json",
    "migrations/x/artifacts/target.json",
    "migrations/x/state.json.bak",
    "migrations/x/my-state.json",
])
def test_state_json_outside_migrations_is_allowed(guard, path):
    assert guard.decide(edit(path)) == (0, "")


@pytest.mark.parametrize("command", [
    "echo x >> migrations/x/state.json",
    "sed -i 's/pending/complete/' migrations/x/state.json",
    'Set-Content -Path migrations/x/state.json -Value "{}"',
    "'{}' | Out-File migrations/x/state.json",
    "echo '{}' | tee migrations/x/state.json",
    "rm migrations/x/state.json",
    r"del migrations\x\state.json",
    "Remove-Item migrations/x/state.json",
    "remove-item -Force migrations/x/state.json",
    # copies, moves, appends, truncations
    "cp backup.json migrations/x/state.json",
    "mv backup.json migrations/x/state.json",
    r"copy backup.json migrations\x\state.json",
    r"move backup.json migrations\x\state.json",
    "Copy-Item backup.json migrations/x/state.json",
    "Move-Item -Path backup.json -Destination migrations/x/state.json",
    "Add-Content migrations/x/state.json '{}'",
    "Clear-Content migrations/x/state.json",
    "truncate -s 0 migrations/x/state.json",
    "dd if=backup.json of=migrations/x/state.json",
    'dd if=backup.json of="migrations/x/state.json"',
    # in-place editors with combined or long flags
    "sed -Ei 's/pending/complete/' migrations/x/state.json",
    "sed -i.bak 's/pending/complete/' migrations/x/state.json",
    "sed --in-place 's/pending/complete/' migrations/x/state.json",
    "sed -e 's/pending/complete/' -i migrations/x/state.json",
    "perl -pi -e 's/pending/complete/' migrations/x/state.json",
    "perl -i.bak -pe 's/pending/complete/' migrations/x/state.json",
    "perl -p -i -e 's/pending/complete/' migrations/x/state.json",
])
def test_bash_write_forms_are_blocked(guard, command):
    code, reason = guard.decide(bash(command))
    assert code == 2 and "state.json" in reason


@pytest.mark.parametrize("command", [
    "cat migrations/x/state.json",
    r"type migrations\x\state.json",
    "python scripts/dbcarry.py state --migration x verify 2>&1",
    "git diff -- migrations/x/state.json",
    "grep -n status migrations/x/state.json | head",
    "python -m pytest -q -p no:cacheprovider > out.txt",
    "rm -rf build/",
    "echo hello > notes.txt",
    "cat migrations/x/state.json > /dev/null",
    # a sibling file, consistent with the Edit rule
    "echo x > migrations/x/state.json.bak",
])
def test_bash_reads_and_unrelated_writes_are_allowed(guard, command):
    assert guard.decide(bash(command)) == (0, "")


@pytest.mark.parametrize("command", [
    # The guard is an allowlist: a command that names state.json is
    # allowed only when every part of it is a known read-only form. These
    # happen to be reads, but the guard cannot tell a reading python -c,
    # sed, perl, or dd from a writing one, so they are refused and the
    # reason points at the state CLI or a plain cat.
    "python -c \"import json; print(json.load(open('migrations/x/state.json')))\"",
    "python -c \"assert len(open('migrations/x/state.json').read()) >= 2\"",
    "sed -n 1,5p migrations/x/state.json",
    "sed -E 's/\"//g' migrations/x/state.json",
    "perl -ne 'print if /phase/' migrations/x/state.json",
    "perl -MJSON -e 'print 1' migrations/x/state.json",
    "dd if=migrations/x/state.json of=/dev/null",
    "cat migrations/x/state.json 2>>errors.log",
    "echo x > out.txt; cat migrations/x/state.json",
    "cat migrations/x/state.json > /dev/null; echo done",
])
def test_reads_outside_the_allowlist_are_refused(guard, command):
    code, reason = guard.decide(bash(command))
    assert code == 2 and "state.json" in reason
    assert "dbcarry.py state" in reason


@pytest.mark.parametrize("payload", [
    {},
    {"tool_name": "Edit"},
    {"tool_name": "Edit", "tool_input": None},
    {"tool_name": "Edit", "tool_input": "migrations/x/state.json"},
    {"tool_name": "Bash", "tool_input": {}},
    {"tool_name": "Bash", "tool_input": {"command": None}},
    {"tool_name": None, "tool_input": {"file_path": "migrations/x/state.json"}},
    None,
    "not a mapping",
    [1, 2, 3],
])
def test_unexpected_shapes_allow(guard, payload):
    assert guard.decide(payload) == (0, "")


def _run_hook(stdin_text):
    return subprocess.run(
        [sys.executable, str(HOOK)], input=stdin_text, capture_output=True,
        text=True, encoding="utf-8")


def test_main_blocks_and_explains_on_stderr():
    proc = _run_hook(json.dumps(edit("migrations/x/state.json")))
    assert proc.returncode == 2
    assert "state.json" in proc.stderr
    assert proc.stdout == ""


def test_main_allows_silently():
    proc = _run_hook(json.dumps(edit("migrations/x/migration.yaml")))
    assert proc.returncode == 0
    assert proc.stdout == "" and proc.stderr == ""


@pytest.mark.parametrize("stdin_text", ["", "{not json", "42", "[]", "null"])
def test_main_never_crashes_on_bad_input(stdin_text):
    proc = _run_hook(stdin_text)
    assert proc.returncode == 0
    assert proc.stdout == "" and proc.stderr == ""


def test_hook_uses_only_stdlib():
    text = HOOK.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")):
            module = stripped.split()[1].split(".")[0]
            assert module in {"json", "os", "re", "sys", "posixpath"}, line


# ------------------------------------ redirect targets and the shell tools

@pytest.mark.parametrize("command", [
    "python x.py 2> migrations/x/state.json",
    "python x.py 2>> migrations/x/state.json",
    "python x.py &> migrations/x/state.json",
    "python x.py 1> migrations/x/state.json",
    "cat a >| migrations/x/state.json",
    'echo "{}" >"migrations/x/state.json"',
    "echo '{}' > '$WS/state.json'",
    "echo '{}' >> ${WS}/state.json",
    "echo '{}' > out.txt; echo '{}' > migrations/x/state.json",
    # mixed quoting: the target is a run of quoted and bare segments
    'echo \'{}\' > "$WS"/state.json',
    'echo x > migrations/x/"state.json"',
    "echo x > 'migrations/x'/state.json",
    "echo x > \"$WS\"'/state.json'",
    "echo x > migrations/x/state.json;echo done",
    "echo x > migrations/x/state.json|cat",
    # Windows name forms that resolve to the same file
    "echo x > migrations/x/state.json.",
    "echo x > migrations/x/state.json::$DATA",
])
def test_redirect_into_state_json_is_blocked_in_every_form(guard, command):
    code, reason = guard.decide(bash(command))
    assert code == 2 and "state.json" in reason


@pytest.mark.parametrize("command", [
    # The arrow lives inside a quoted argument, so it is not a redirect.
    "git log --format='%h -> %s' -- migrations/x/state.json",
    # No state.json is named, so the redirect elsewhere is fine.
    "python scripts/dbcarry.py state --migration x show > state-copy.txt",
    "cat migrations/x/state.json 2>&1",
    "cat migrations/x/state.json >/dev/null",
    "Get-Content migrations/x/state.json > $null",
])
def test_quoted_arrow_and_null_sinks_are_allowed(guard, command):
    assert guard.decide(bash(command)) == (0, "")


@pytest.mark.parametrize("command", [
    "Set-Content -Path migrations/x/state.json -Value '{}'",
    "'{}' > migrations\\x\\state.json",
    "Remove-Item migrations/x/state.json",
    "Copy-Item backup.json migrations/x/state.json",
    "Move-Item backup.json migrations/x/state.json",
    "Add-Content -Path migrations/x/state.json -Value '{}'",
    "Clear-Content migrations/x/state.json",
    "'{}' > \"$ws\"/state.json",
])
def test_powershell_tool_is_guarded_like_bash(guard, command):
    payload = {"tool_name": "PowerShell", "tool_input": {"command": command}}
    code, reason = guard.decide(payload)
    assert code == 2 and "state.json" in reason


def test_powershell_read_is_allowed(guard):
    payload = {"tool_name": "PowerShell",
               "tool_input": {"command": "Get-Content migrations/x/state.json"}}
    assert guard.decide(payload) == (0, "")


# ---------------------------------------- allowlist: every reproduced bypass

def powershell(command):
    return {"tool_name": "PowerShell", "tool_input": {"command": command}}


@pytest.mark.parametrize("command", [
    # interpreter writes
    "python -c \"open('migrations/x/state.json','w').write('{}')\"",
    "python - <<'EOF'\nimport json\njson.dump({}, open('migrations/x/state.json', 'w'))\nEOF",
    "python <<EOF\nopen('migrations/x/state.json', 'w').write('{}')\nEOF",
    "node -e \"require('fs').writeFileSync('migrations/x/state.json', '{}')\"",
    # quoting tricks
    r"echo x > migrations/x/state.js\on",
    "echo x > migrations/x/$'state.json'",
    "echo x > migrations/x/state.json{,}",
    "F=state.json; echo x > migrations/x/$F",
    "F=migrations/x/state.json; echo x > $F",
    "echo x > migrations/x/sta''te.json",
    'echo x > migrations/x/"state".json',
    # tools the old marker list did not know
    "perl -0pi -e 's/pending/complete/' migrations/x/state.json",
    "awk -i inplace '{print}' migrations/x/state.json",
    "ex -s +'%s/pending/complete/g' -cwq migrations/x/state.json",
    "install -m 644 backup.json migrations/x/state.json",
    "rsync backup.json migrations/x/state.json",
    "cat backup.json | sponge migrations/x/state.json",
    "unlink migrations/x/state.json",
    "shred -u migrations/x/state.json",
    "curl -o migrations/x/state.json https://example.invalid/state",
    "wget -O migrations/x/state.json https://example.invalid/state",
    "find migrations -name state.json -delete",
    "find migrations -name state.json -exec rm {} \\;",
    r"ren migrations\x\state.json old.json",
    r"erase migrations\x\state.json",
    r"xcopy backup.json migrations\x\state.json /Y",
    r"robocopy backup migrations\x state.json",
    "ln -sf migrations/x/state.json s.json",
    "ed -s migrations/x/state.json <<< $'1d\\nw\\nq'",
    "touch migrations/x/state.json",
    "chmod 000 migrations/x/state.json",
    # a read followed by, or piped into, something that is not a read
    "cat migrations/x/state.json && python -c \"open('migrations/x/state.json','w')\"",
    "cat migrations/x/state.json | python -c \"import sys; open('migrations/x/state.json','w')\"",
    "cat migrations/x/state.json | python - ",
    "cat migrations/x/state.json | xargs rm",
    "cat migrations/x/state.json | tee migrations/x/state.json",
    "cat migrations/x/state.json | sponge migrations/x/state.json",
    "cat migrations/x/state.json | sed 'w migrations/x/state.json'",
    "cat migrations/x/state.json | awk '{print > \"migrations/x/state.json\"}'",
    "cat migrations/x/state.json > >(tee migrations/x/state.json)",
    "grep phase migrations/x/state.json | head; rm -rf migrations/x",
    "cat migrations/x/state.json\nrm migrations/x/state.json",
    "export F=migrations/x/state.json",
    # 8.3 short names in a shell command
    r"echo x > D:\proj\MIGRAT~1\x\STATE~1.JSO",
    r"del D:\proj\migrat~1\x\state~1.jso",
    # a heredoc report that quotes the file name and writes elsewhere;
    # the Write tool is the way to produce such a file
    "cat > migrations/x/artifacts/report.md <<'EOF'\nSee state.json for the phase.\nEOF",
])
def test_every_bash_bypass_is_blocked(guard, command):
    code, reason = guard.decide(bash(command))
    assert code == 2 and "state.json" in reason, command
    assert "dbcarry.py state" in reason


@pytest.mark.parametrize("command", [
    # globs and directory removal never spell out state.json
    "rm migrations/x/*.json",
    "rm migrations/x/state.js*",
    "rm -rf migrations/x",
    "rm -rf migrations",
    "rm -rf ./migrations/",
    "rm -r sandbox/r/migrations/x",
    "rm -rf *",
    "rm */*/*.json",
    "rm -f state.jso?",
    "find migrations -name '*.json' -delete",
    "find . -path '*/migrations/*' -delete",
    "mv migrations/x migrations/x.old",
    "cp -r backup/ migrations/x/",
    "rsync -a backup/ migrations/x/",
    "install -D backup.json migrations/x/other.json",
    "shred -u migrations/x/*",
    r"rd /s /q migrations\x",
    r"rmdir /s migrations\x",
    r"del migrations\x\*.json",
    r"erase migrations\x\*",
    r"ren migrations\x\state.js* old.json",
    r"xcopy backup migrations\x /E /Y",
    r"robocopy backup migrations\x /MIR",
    r"move migrations\x migrations\x.old",
    "Remove-Item -Recurse -Force migrations/x",
    "ri -r migrations/x",
    "Remove-Item migrations/x/*.json",
    "Move-Item migrations/x migrations/x.old",
    "mi migrations/x migrations/x.old",
    "Rename-Item migrations/x/state.js* old.json",
    "rni migrations/x x.old",
    "Copy-Item -Recurse backup/ migrations/x/",
    "cpi backup.json migrations/x/",
    "New-Item -Force -Path migrations/x/state.js -Value '{}'",
    "ni -Force migrations/x/other.json",
    "Clear-Content migrations/x/*.json",
    "clc migrations/x/*",
    "Set-Content migrations/x/*.json '{}'",
    "sc migrations/x/other.json '{}'",
    "Add-Content migrations/x/*.json '{}'",
    "ac migrations/x/other.json '{}'",
    "'{}' | Out-File migrations/x/other.json",
    "Get-ChildItem migrations/x | Export-Csv migrations/x/list.csv",
    "Export-Clixml -Path migrations/x/state.xml -InputObject 1",
    "[IO.File]::Delete('migrations/x/other.json')",
    "[System.IO.File]::WriteAllText('migrations/x/other.json', '{}')",
    "[IO.Directory]::Delete('migrations/x', $true)",
    "Invoke-WebRequest https://example.invalid -OutFile migrations/x/s.json",
])
def test_deleting_or_globbing_into_migrations_is_blocked(guard, command):
    code, reason = guard.decide(bash(command))
    assert code == 2 and "state.json" in reason, command
    code, reason = guard.decide(powershell(command))
    assert code == 2 and "state.json" in reason, command


@pytest.mark.parametrize("command", [
    # PowerShell aliases and .NET
    "sc migrations/x/state.json '{}'",
    "sc -Path migrations/x/state.json -Value '{}'",
    "ac migrations/x/state.json '{}'",
    "clc migrations/x/state.json",
    "ri migrations/x/state.json",
    "rd migrations/x",
    "mi backup.json migrations/x/state.json",
    "rni migrations/x/state.json old.json",
    "Rename-Item migrations/x/state.json old.json",
    "ni -Force migrations/x/state.json",
    "New-Item -Force -Path migrations/x/state.json",
    "New-Item migrations/x/state.json -Value '{}'",
    "'{}' | Tee-Object -FilePath migrations/x/state.json",
    "'{}' | tee migrations/x/state.json",
    "'{}' | Tee-Object migrations/x/state.json",
    "Get-Content backup.json | Export-Csv migrations/x/state.json",
    "[IO.File]::WriteAllText('migrations/x/state.json', '{}')",
    "[IO.File]::Delete('migrations/x/state.json')",
    "[System.IO.File]::WriteAllText('migrations/x/state.json', '{}')",
    "$f='migrations/x/state.json'; '{}' > $f",
    "$f = 'migrations/x/state.json'\n'{}' | Set-Content $f",
    "Get-Content migrations/x/state.json | % { [IO.File]::WriteAllText('migrations/x/state.json', $_) }",
    "Get-Content migrations/x/state.json | ForEach-Object { sc migrations/x/state.json $_ }",
    "Get-Content migrations/x/state.json | Out-File migrations/x/state.json",
    "Get-Content migrations/x/state.json | Set-Content migrations/x/state.json",
    "gc migrations/x/state.json | ac migrations/x/state.json",
    "Get-Content migrations/x/state.json > migrations/x/state.json",
    "Get-Content migrations/x/state.json 2> migrations/x/state.json",
    "Get-Content migrations/x/state.json; ri migrations/x/state.json",
    "Get-Content migrations/x/state.json | Where-Object { ri migrations/x/state.json }",
    "Get-Content migrations/x/state.json | select @{n='x';e={[IO.File]::Delete('migrations/x/state.json')}}",
    "Invoke-WebRequest https://example.invalid -OutFile migrations/x/state.json",
    "iwr https://example.invalid -OutFile migrations/x/state.json",
    "Start-Process notepad migrations/x/state.json",
    "Invoke-Expression \"sc migrations/x/state.json '{}'\"",
    r"Get-Content D:\proj\MIGRAT~1\x\STATE~1.JSO | Set-Content D:\proj\MIGRAT~1\x\STATE~1.JSO",
])
def test_every_powershell_bypass_is_blocked(guard, command):
    code, reason = guard.decide(powershell(command))
    assert code == 2 and "state.json" in reason, command
    assert "dbcarry.py state" in reason


@pytest.mark.parametrize("command", [
    "cat migrations/x/state.json",
    "python scripts/dbcarry.py state --migration x show",
    'python "D:/plugin/scripts/dbcarry.py" state --root sandbox/r --migration x verify',
    "python '/opt/plugin/scripts/dbcarry.py' state --migration x show",
    r'python "D:\plugin\scripts\dbcarry.py" state --migration x show',
    'python "$SCRIPTS" state --migration x show',
    'python "${CLAUDE_PLUGIN_ROOT}/scripts/dbcarry.py" state --migration x show',
    "python3 scripts/dbcarry.py state --migration x show",
    "py scripts/dbcarry.py state --migration x show 2>&1",
    "grep -n phase migrations/x/state.json | head",
    "Get-Content migrations/x/state.json",
    "gc migrations/x/state.json | ConvertFrom-Json | Select-Object phase",
    "Get-Content migrations/x/state.json | Select-String phase",
    "Test-Path migrations/x/state.json",
    "git diff migrations/x/migration.yaml",
    "git status --short migrations/x/state.json",
    "git show HEAD:migrations/x/state.json",
    "rm -rf sandbox/release",
    "rm -rf sandbox/release/*",
    "Remove-Item -Recurse -Force sandbox/release",
    "rm -rf build/ dist/ *.egg-info",
    "head -c 200 migrations/x/state.json",
    "tail -n 5 migrations/x/state.json",
    "less migrations/x/state.json",
    "more migrations/x/state.json",
    "rg phase migrations/x/state.json",
    "egrep phase migrations/x/state.json",
    "wc -l migrations/x/state.json",
    "stat migrations/x/state.json",
    "ls -la migrations/x/state.json",
    r"dir migrations\x\state.json",
    "diff migrations/x/state.json migrations/y/state.json",
    "jq .phase migrations/x/state.json",
    "jq -r '.phases[] | .name' migrations/x/state.json | sort | uniq -c",
    "cat migrations/x/state.json | jq .phase | head -1",
    "cat migrations/x/state.json | grep -i phase | sort | uniq | wc -l",
    "sls phase migrations/x/state.json",
    "Select-String -Path migrations/x/state.json -Pattern phase",
    "Get-Content migrations/x/state.json | ConvertFrom-Json | Format-List",
    # a migrations path with no writer and no state.json is fine
    "ls migrations/x/artifacts",
    "python scripts/dbcarry.py checksum --root . --migration x",
    'python "$SCRIPTS" inventory --root sandbox/r --migration x',
    "python scripts/dbcarry.py state --migration x fail-phase --reason 'rm of migrations/x/tmp failed'",
    "git commit -m 'docs: describe migrations/x layout'",
    "mkdir -p migrations/x/artifacts",
    "cat migrations/x/migration.yaml",
    "echo x > migrations/x/artifacts/notes.txt",
])
def test_read_only_forms_and_unrelated_work_stay_allowed(guard, command):
    assert guard.decide(bash(command)) == (0, ""), command
    assert guard.decide(powershell(command)) == (0, ""), command


def test_edit_on_migration_yaml_and_read_of_state_json_stay_allowed(guard):
    assert guard.decide(edit("migrations/x/migration.yaml")) == (0, "")
    assert guard.decide(edit("migrations/x/state.json", tool="Read")) == (0, "")


# ------------------------------------------- editing tools: path normalization

@pytest.mark.parametrize("path", [
    r"D:\proj\MIGRAT~1\x\STATE~1.JSO",
    r"d:\proj\migrat~1\x\state~1.jso",
    "MIGRAT~1/x/STATE~1.JSO",
    r"D:\proj\migrations\x\STATE~1.JSO",
    r"D:\proj\MIGRAT~1\x\state.json",
    r"D:\proj\migrations\x\..\x\state.json",
    "migrations/x/./state.json",
])
@pytest.mark.parametrize("tool", ["Edit", "Write", "MultiEdit"])
def test_short_names_and_dot_segments_are_blocked(guard, path, tool):
    code, reason = guard.decide(edit(path, tool=tool))
    assert code == 2 and "state.json" in reason


def test_notebook_edit_short_name_is_blocked(guard):
    payload = {"tool_name": "NotebookEdit",
               "tool_input": {"notebook_path": r"D:\p\MIGRAT~1\x\STATE~1.JSO"}}
    assert guard.decide(payload)[0] == 2


def test_symlink_to_state_json_is_blocked(guard, tmp_path):
    real = tmp_path / "migrations" / "x" / "state.json"
    real.parent.mkdir(parents=True)
    real.write_text("{}", encoding="utf-8")
    alias_dir = tmp_path / "scratch"
    alias_dir.mkdir()
    alias = alias_dir / "s.json"
    try:
        alias.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not permitted for this user")
    code, reason = guard.decide(edit(str(alias)))
    assert code == 2 and "state.json" in reason


def test_directory_junction_or_link_is_blocked(guard, tmp_path):
    real_dir = tmp_path / "migrations" / "x"
    real_dir.mkdir(parents=True)
    (real_dir / "state.json").write_text("{}", encoding="utf-8")
    link = tmp_path / "ws"
    try:
        if sys.platform == "win32":
            subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(real_dir)],
                           check=True, capture_output=True)
        else:
            link.symlink_to(real_dir, target_is_directory=True)
    except (OSError, NotImplementedError, subprocess.CalledProcessError):
        pytest.skip("directory links are not permitted for this user")
    code, reason = guard.decide(edit(str(link / "state.json")))
    assert code == 2 and "state.json" in reason


def test_missing_paths_still_decide_without_touching_the_filesystem(guard):
    # realpath is only consulted for a path that exists; a missing one is
    # judged on its text alone and must not raise.
    assert guard.decide(edit("does/not/exist/migrations/x/state.json"))[0] == 2
    assert guard.decide(edit("does/not/exist/x/other.json")) == (0, "")


# ------------------------------------------ plugin hooks.json (finding B)

PLUGIN_HOOKS = ROOT / "hooks" / "hooks.json"
GUARDED_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit", "Bash",
                 "PowerShell"}


def test_plugin_hooks_json_registers_the_guard_for_plugin_installs():
    hooks = json.loads(PLUGIN_HOOKS.read_text(encoding="utf-8"))
    pre = hooks["hooks"]["PreToolUse"]
    matched = [entry for entry in pre
               if any("scripts/hooks/guard_state.py" in h["command"]
                      for h in entry["hooks"])]
    assert matched, "no PreToolUse entry names scripts/hooks/guard_state.py"
    for entry in matched:
        assert GUARDED_TOOLS <= set(entry["matcher"].split("|"))
        for h in entry["hooks"]:
            assert h["type"] == "command"
            assert "${CLAUDE_PLUGIN_ROOT}" in h["command"]
            assert "$CLAUDE_PROJECT_DIR" not in h["command"]


def test_project_settings_still_name_the_guard():
    settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
    pre = settings["hooks"]["PreToolUse"]
    matched = [entry for entry in pre
               if any("scripts/hooks/guard_state.py" in h["command"]
                      for h in entry["hooks"])]
    assert matched
    for entry in matched:
        assert GUARDED_TOOLS <= set(entry["matcher"].split("|"))


def test_module_docstring_names_the_uncovered_cases():
    text = HOOK.read_text(encoding="utf-8")
    doc = text.split('"""')[1]
    for phrase in ("symlink", "sandbox", "runtime", "Write tool", "heredoc"):
        assert phrase in doc, phrase
