"""State machine for dbcarry migrations.

State lives in migrations/<name>/state.json. Every mutation goes through
this module (as a CLI), validates the transition table, and appends a line
to artifacts/decision-log.md. Agents never edit state.json directly.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PHASES = [
    "assess", "plan", "provision", "migrate_schema", "migrate_security",
    "migrate_data", "validate", "cutover",
]
GATE_UNLOCKS = {"plan_approval": "provision", "cutover_approval": "cutover"}
GATE_REQUIRES = {"plan_approval": "plan", "cutover_approval": "validate"}
STRATEGIES = ("dump_restore", "logical_replication", "bulk_load")
PROVIDERS = ("local", "gcp", "aws", "azure", "bigquery")
STATUSES = ("pending", "in_progress", "complete", "failed")


class StateError(Exception):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_state(migration, engine, provider):
    return {
        "migration": migration,
        "engine": engine,
        "provider": provider,
        "strategy": None,
        "phases": {
            p: {"status": "pending", "started_at": None, "completed_at": None}
            for p in PHASES
        },
        "gates": {
            g: {"approved": False, "approved_by": None,
                "approved_at": None, "artifact": None}
            for g in GATE_UNLOCKS
        },
        "rollback": {"performed": False, "at": None, "reason": None},
    }


def _phase(state, phase):
    if phase not in state["phases"]:
        raise StateError(f"unknown phase: {phase}")
    return state["phases"][phase]


def check_can_start(state, phase):
    ph = _phase(state, phase)
    for prior in PHASES[: PHASES.index(phase)]:
        if state["phases"][prior]["status"] != "complete":
            raise StateError(
                f"cannot start {phase}: {prior} is "
                f"{state['phases'][prior]['status']}")
    for gate, unlocked in GATE_UNLOCKS.items():
        if unlocked == phase and not state["gates"][gate]["approved"]:
            raise StateError(f"cannot start {phase}: gate {gate} not approved")
    if ph["status"] == "complete":
        raise StateError(f"{phase} is already complete")


def apply_start(state, phase):
    check_can_start(state, phase)
    ph = state["phases"][phase]
    ph["status"] = "in_progress"
    ph["started_at"] = now()


def apply_complete(state, phase):
    ph = _phase(state, phase)
    if ph["status"] != "in_progress":
        raise StateError(
            f"cannot complete {phase}: status is {ph['status']}, "
            "must be in_progress")
    if phase == "plan" and state["strategy"] is None:
        raise StateError("cannot complete plan: no strategy set")
    ph["status"] = "complete"
    ph["completed_at"] = now()


def apply_fail(state, phase, reason=""):
    ph = _phase(state, phase)
    if ph["status"] != "in_progress":
        raise StateError(
            f"cannot fail {phase}: status is {ph['status']}, "
            "must be in_progress")
    ph["status"] = "failed"


def apply_approve_gate(state, gate, approver, artifact):
    if gate not in state["gates"]:
        raise StateError(f"unknown gate: {gate}")
    required = GATE_REQUIRES[gate]
    if state["phases"][required]["status"] != "complete":
        raise StateError(f"gate {gate} requires phase {required} complete")
    g = state["gates"][gate]
    if g["approved"]:
        raise StateError(f"gate {gate} is already approved")
    g.update(approved=True, approved_by=approver,
             approved_at=now(), artifact=artifact)


def apply_set_strategy(state, strategy):
    if strategy not in STRATEGIES:
        raise StateError(f"unknown strategy: {strategy}")
    if state["phases"]["plan"]["status"] != "in_progress":
        raise StateError("strategy may only be set while plan is in_progress")
    state["strategy"] = strategy


def apply_mark_rollback(state, reason):
    if state["rollback"]["performed"]:
        raise StateError("rollback already recorded")
    state["rollback"] = {"performed": True, "at": now(), "reason": reason}


def verify_state(state):
    problems = []
    for key in ("migration", "engine", "provider", "phases", "gates"):
        if key not in state:
            problems.append(f"missing key: {key}")
    if problems:
        return problems
    if list(state["phases"]) != PHASES:
        problems.append("phase list does not match expected pipeline")
        return problems
    reached_incomplete = False
    for phase in PHASES:
        ph = state["phases"][phase]
        status = ph["status"]
        if status not in STATUSES:
            problems.append(f"{phase}: invalid status {status!r}")
        if status in ("in_progress", "complete", "failed") and reached_incomplete:
            problems.append(f"{phase} is {status} but an earlier phase is not complete")
        if status == "complete" and not ph.get("started_at"):
            problems.append(f"{phase} is complete but was never started")
        if status != "complete":
            reached_incomplete = True
    for gate, required in GATE_REQUIRES.items():
        g = state["gates"].get(gate)
        if g is None:
            problems.append(f"missing gate: {gate}")
            continue
        if g["approved"] and state["phases"][required]["status"] != "complete":
            problems.append(f"gate {gate} approved but {required} not complete")
    for gate, unlocked in GATE_UNLOCKS.items():
        if state["phases"][unlocked]["status"] != "pending" and \
                not state["gates"][gate]["approved"]:
            problems.append(f"{unlocked} progressed without gate {gate}")
    if state["phases"]["plan"]["status"] == "complete" and not state["strategy"]:
        problems.append("plan complete but no strategy recorded")
    return problems


# ---------------------------------------------------------------- workspace IO

def workspace(root, migration):
    return Path(root) / "migrations" / migration


def load(root, migration):
    path = workspace(root, migration) / "state.json"
    if not path.exists():
        raise StateError(f"no state file at {path}; run init first")
    return json.loads(path.read_text(encoding="utf-8"))


def save(root, migration, state):
    path = workspace(root, migration) / "state.json"
    path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def log_decision(root, migration, message):
    log = workspace(root, migration) / "artifacts" / "decision-log.md"
    log.parent.mkdir(parents=True, exist_ok=True)
    if not log.exists():
        log.write_text("# Decision log\n\n", encoding="utf-8")
    with log.open("a", encoding="utf-8") as fh:
        fh.write(f"- {now()} | {message}\n")


# ------------------------------------------------------------------------- CLI

def main(argv):
    parser = argparse.ArgumentParser(prog="dbcarry.py state")
    parser.add_argument("--root", default=".", help="project root holding migrations/")
    parser.add_argument("--migration", required=True)
    sub = parser.add_subparsers(dest="verb", required=True)

    p = sub.add_parser("init")
    p.add_argument("--engine", default="postgres")
    p.add_argument("--provider", required=True, choices=list(PROVIDERS))
    for verb in ("start-phase", "complete-phase", "fail-phase"):
        p = sub.add_parser(verb)
        p.add_argument("--phase", required=True, choices=PHASES)
        if verb == "fail-phase":
            p.add_argument("--reason", default="")
    p = sub.add_parser("approve-gate")
    p.add_argument("--gate", required=True, choices=list(GATE_UNLOCKS))
    p.add_argument("--approved-by", required=True)
    p.add_argument("--artifact", required=True)
    p = sub.add_parser("decline-gate")
    p.add_argument("--gate", required=True, choices=list(GATE_UNLOCKS))
    p.add_argument("--reason", required=True)
    p = sub.add_parser("set-strategy")
    p.add_argument("--strategy", required=True, choices=list(STRATEGIES))
    p = sub.add_parser("mark-rollback")
    p.add_argument("--reason", required=True)
    sub.add_parser("verify")
    sub.add_parser("show")

    # argv[0] is the top-level verb "state"
    args = parser.parse_args(argv[1:])
    root, name = args.root, args.migration

    try:
        if args.verb == "init":
            ws = workspace(root, name)
            if (ws / "state.json").exists():
                raise StateError(f"{ws} already initialized")
            (ws / "artifacts").mkdir(parents=True, exist_ok=True)
            save(root, name, new_state(name, args.engine, args.provider))
            log_decision(root, name,
                         f"init | engine={args.engine} provider={args.provider}")
            print(f"initialized {ws}")
            return 0

        state = load(root, name)
        if args.verb == "start-phase":
            apply_start(state, args.phase)
            log_decision(root, name, f"phase:{args.phase} | started")
        elif args.verb == "complete-phase":
            apply_complete(state, args.phase)
            log_decision(root, name, f"phase:{args.phase} | complete")
        elif args.verb == "fail-phase":
            apply_fail(state, args.phase, args.reason)
            log_decision(root, name,
                         f"phase:{args.phase} | FAILED | {args.reason}")
        elif args.verb == "approve-gate":
            apply_approve_gate(state, args.gate, args.approved_by, args.artifact)
            log_decision(root, name,
                         f"gate:{args.gate} | APPROVED | by={args.approved_by} "
                         f"| artifact={args.artifact}")
        elif args.verb == "decline-gate":
            log_decision(root, name,
                         f"gate:{args.gate} | DECLINED | {args.reason}")
            print(f"gate {args.gate} declined; state unchanged")
            return 0
        elif args.verb == "set-strategy":
            apply_set_strategy(state, args.strategy)
            log_decision(root, name, f"strategy={args.strategy}")
        elif args.verb == "mark-rollback":
            apply_mark_rollback(state, args.reason)
            log_decision(root, name, f"ROLLBACK | {args.reason}")
        elif args.verb == "verify":
            problems = verify_state(state)
            if problems:
                print("STATE INVALID:")
                for p_ in problems:
                    print(f"  - {p_}")
                return 1
            print("state ok")
            return 0
        elif args.verb == "show":
            print(json.dumps(state, indent=2))
            return 0
        save(root, name, state)
        print(f"ok: {args.verb}")
        return 0
    except StateError as exc:
        print(f"STATE ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(f"STATE ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main(["state"] + sys.argv[1:])
