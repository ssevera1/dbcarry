import pytest

from db_drift import state as sm


def fresh():
    return sm.new_state("demo-run", "postgres", "local")


def complete_through(st, last_phase):
    """Drive phases in order through last_phase, approving gates as needed."""
    for phase in sm.PHASES:
        for gate, unlocked in sm.GATE_UNLOCKS.items():
            if unlocked == phase and not st["gates"][gate]["approved"]:
                sm.apply_approve_gate(st, gate, "tester", "artifacts/x.md")
        sm.apply_start(st, phase)
        if phase == "plan":
            sm.apply_set_strategy(st, "dump_restore")
        sm.apply_complete(st, phase)
        for gate, required in sm.GATE_REQUIRES.items():
            if required == phase and not st["gates"][gate]["approved"]:
                sm.apply_approve_gate(st, gate, "tester", "artifacts/x.md")
        if phase == last_phase:
            return st
    return st


def test_new_state_shape():
    st = fresh()
    assert st["migration"] == "demo-run"
    assert st["strategy"] is None
    assert list(st["phases"]) == sm.PHASES
    assert all(p["status"] == "pending" for p in st["phases"].values())
    assert not st["gates"]["plan_approval"]["approved"]


def test_happy_path_reaches_cutover():
    st = complete_through(fresh(), "cutover")
    assert st["phases"]["cutover"]["status"] == "complete"
    assert st["gates"]["cutover_approval"]["approved_by"] == "tester"


def test_cannot_skip_ahead():
    st = fresh()
    with pytest.raises(sm.StateError, match="assess"):
        sm.apply_start(st, "plan")


def test_provision_blocked_without_gate():
    st = complete_through(fresh(), "plan")
    # complete_through approves gates automatically, so rebuild without approval
    st = fresh()
    sm.apply_start(st, "assess")
    sm.apply_complete(st, "assess")
    sm.apply_start(st, "plan")
    sm.apply_set_strategy(st, "dump_restore")
    sm.apply_complete(st, "plan")
    with pytest.raises(sm.StateError, match="plan_approval"):
        sm.apply_start(st, "provision")


def test_gate_requires_its_phase_complete():
    st = fresh()
    with pytest.raises(sm.StateError, match="requires phase plan"):
        sm.apply_approve_gate(st, "plan_approval", "tester", "a.md")


def test_gate_cannot_be_approved_twice():
    st = complete_through(fresh(), "plan")
    with pytest.raises(sm.StateError, match="already approved"):
        sm.apply_approve_gate(st, "plan_approval", "tester", "a.md")


def test_failed_phase_can_rerun_but_not_advance():
    st = fresh()
    sm.apply_start(st, "assess")
    sm.apply_fail(st, "assess", "connection refused")
    assert st["phases"]["assess"]["status"] == "failed"
    with pytest.raises(sm.StateError):
        sm.apply_start(st, "plan")
    sm.apply_start(st, "assess")  # re-run allowed
    sm.apply_complete(st, "assess")


def test_complete_requires_in_progress():
    st = fresh()
    with pytest.raises(sm.StateError, match="in_progress"):
        sm.apply_complete(st, "assess")


def test_set_strategy_only_during_plan():
    st = fresh()
    with pytest.raises(sm.StateError):
        sm.apply_set_strategy(st, "dump_restore")
    with pytest.raises(sm.StateError, match="unknown strategy"):
        sm.apply_set_strategy(complete_through(fresh(), "assess"), "carrier_pigeon")


def test_verify_catches_corruption():
    st = complete_through(fresh(), "plan")
    st["phases"]["provision"]["status"] = "complete"  # illegal hand edit
    st["phases"]["provision"]["completed_at"] = "2026-09-01T00:00:00+00:00"
    problems = sm.verify_state(st)
    assert problems  # out of order: provision complete without gate approval
    st2 = fresh()
    st2["phases"]["plan"]["status"] = "bogus"
    assert sm.verify_state(st2)


def test_verify_clean_state_is_empty():
    assert sm.verify_state(fresh()) == []
    assert sm.verify_state(complete_through(fresh(), "cutover")) == []
