"""End-to-end: every scenario gets the outcome we demo."""
from datetime import datetime

from nightwatch import Action, NightWatch
from nightwatch.models import Event
from nightwatch.simulator import SCENARIOS, demo_identities


def run(name):
    nw = NightWatch(demo_identities())
    return nw, [nw.process(e) for _, e in SCENARIOS[name][1]()]


def test_normal_day_has_no_false_positives():
    _, ds = run("normal")
    assert all(d.action is Action.ALLOW for d in ds)


def test_rail_drain_blocked_on_first_payment_and_nothing_lost():
    nw, ds = run("drain")
    assert ds[0].action is Action.BLOCK
    assert all(d.action is Action.BLOCK for d in ds)
    assert nw.ledger.lost_aed == 0
    nw.respond(ds[0].event.id, confirmed_attack=True)
    assert nw.ledger.protected_aed == 512_000
    assert nw.ledger.held_aed == 0


def test_backdoor_commit_blocked_deploy_refused_and_devin_task_written():
    nw, ds = run("commit")
    commit, deploy = ds
    assert commit.action is Action.BLOCK
    codes = {s.code for s in commit.signals}
    assert {"HARDCODED_BYPASS", "SAFETY_CHECK_REMOVED", "SECRET_IN_CODE", "NEW_EGRESS"} <= codes
    assert commit.fix_task and "regression tests" in commit.fix_task
    assert "demo_bank/payments/transfer.py" in commit.fix_task
    assert deploy.action is Action.BLOCK
    assert any(s.code == "QUARANTINED_COMMIT" for s in deploy.signals)


def test_exfiltration_killed_and_rows_protected():
    nw, ds = run("exfil")
    assert ds[0].action is Action.BLOCK
    assert nw.ledger.protected_rows == 3_300_000
    assert nw.ledger.leaked_rows == 0


def test_false_positive_release_restores_access():
    nw, ds = run("drain")
    steps = nw.respond(ds[0].event.id, confirmed_attack=False)
    assert "false positive" in steps[0].lower()
    assert not nw.state["key-paylink"].revoked


def test_decisions_are_fast():
    _, ds = run("drain")
    assert max(d.latency_ms for d in ds) < 50


def test_config_tamper_blocked_rolled_back_and_follow_up_refused():
    nw, ds = run("config")
    disable, raise_limit = ds
    assert disable.action is Action.BLOCK
    assert "CONTROL_DISABLED" in {s.code for s in disable.signals}
    assert nw.config_rollbacks["payments.daily_limit_enforced"] == "true"
    assert nw.ledger.rolled_back_controls == 2
    assert nw.state["ops-admin"].revoked
    assert raise_limit.action is Action.BLOCK
    assert {"LIMIT_RAISED", "REVOKED"} <= {s.code for s in raise_limit.signals}


def test_normal_config_change_is_allowed():
    nw = NightWatch(demo_identities())
    d = nw.process(Event(datetime(2026, 11, 21, 10, 30), "ops-admin", "config_change",
                         target="payments.max_wire_aed", network="Bank-VPN", old_value="500000",
                         new_value="550000", reviewed=True, description="Raise wire limit by 10%"))
    assert d.action is Action.ALLOW
    assert not d.signals


def test_config_false_positive_release_clears_rollback():
    nw, ds = run("config")
    nw.respond(ds[0].event.id, confirmed_attack=False)
    assert "payments.daily_limit_enforced" not in nw.config_rollbacks
    assert nw.ledger.rolled_back_controls == 1
    assert not nw.state["ops-admin"].revoked


def test_devin_task_target_overrides_read_at_call_time(monkeypatch):
    monkeypatch.setenv("NW_TARGET_REPO", "github.com/acme/bank")
    monkeypatch.setenv("NW_TARGET_FILE", "svc/transfer.py")
    _, ds = run("commit")
    assert "github.com/acme/bank" in ds[0].fix_task and "svc/transfer.py" in ds[0].fix_task


def test_release_of_rollback_without_old_value_decrements_counter():
    nw = NightWatch(demo_identities())
    d = nw.process(Event(datetime(2026, 11, 21, 0, 50), "ops-admin", "config_change", target="audit.enabled",
                         network="AS-Evil", new_value="false", reviewed=False))
    assert d.action is Action.BLOCK and nw.ledger.rolled_back_controls == 1
    nw.respond(d.event.id, confirmed_attack=False)
    assert nw.ledger.rolled_back_controls == 0 and "audit.enabled" not in nw.config_rollbacks
