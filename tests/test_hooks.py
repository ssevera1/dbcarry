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


def test_allows_edit_on_migration_yaml(guard):
    assert guard.decide(edit("migrations/x/migration.yaml")) == (0, "")


def test_blocks_bash_redirect_into_state_json(guard):
    code, reason = guard.decide(bash("echo '{}' > migrations/x/state.json"))
    assert code == 2 and reason


def test_allows_state_cli(guard):
    cmd = "python scripts/dbdrift.py state --migration x show"
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
    assert "Bash(python scripts/dbdrift.py:*)" in allow
    assert "Bash(python -m pytest:*)" in allow
    assert set(settings) == {"permissions", "hooks"}


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
])
def test_bash_write_forms_are_blocked(guard, command):
    code, reason = guard.decide(bash(command))
    assert code == 2 and "state.json" in reason


@pytest.mark.parametrize("command", [
    "cat migrations/x/state.json",
    r"type migrations\x\state.json",
    "python -c \"import json; print(json.load(open('migrations/x/state.json')))\"",
    "python scripts/dbdrift.py state --migration x verify 2>&1",
    "git diff -- migrations/x/state.json",
    "grep -n status migrations/x/state.json | head",
    "python -m pytest -q -p no:cacheprovider > out.txt",
    "rm -rf build/",
    "echo hello > notes.txt",
    "python -c \"assert len(open('migrations/x/state.json').read()) >= 2\"",
    "cat migrations/x/state.json 2>>errors.log",
])
def test_bash_reads_and_unrelated_writes_are_allowed(guard, command):
    assert guard.decide(bash(command)) == (0, "")


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
])
def test_redirect_into_state_json_is_blocked_in_every_form(guard, command):
    code, reason = guard.decide(bash(command))
    assert code == 2 and "state.json" in reason


@pytest.mark.parametrize("command", [
    "echo x > out.txt; cat migrations/x/state.json",
    "cat migrations/x/state.json > /dev/null; echo done",
    "git log --format='%h -> %s' -- migrations/x/state.json",
    "python scripts/dbdrift.py state --migration x show > state-copy.txt",
])
def test_redirect_elsewhere_beside_a_state_json_read_is_allowed(guard, command):
    assert guard.decide(bash(command)) == (0, "")


@pytest.mark.parametrize("command", [
    "Set-Content -Path migrations/x/state.json -Value '{}'",
    "'{}' > migrations\\x\\state.json",
    "Remove-Item migrations/x/state.json",
])
def test_powershell_tool_is_guarded_like_bash(guard, command):
    payload = {"tool_name": "PowerShell", "tool_input": {"command": command}}
    code, reason = guard.decide(payload)
    assert code == 2 and "state.json" in reason


def test_powershell_read_is_allowed(guard):
    payload = {"tool_name": "PowerShell",
               "tool_input": {"command": "Get-Content migrations/x/state.json"}}
    assert guard.decide(payload) == (0, "")
