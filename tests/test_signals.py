from datetime import datetime

from nightwatch.models import Event
from nightwatch.signals import config_tamper, new_network, off_hours, scope_escalation
from nightwatch.simulator import demo_identities
from nightwatch.state import IdentityState

IDS = {i.id: i for i in demo_identities()}
KEY = IDS["key-paylink"]
OPS = IDS["ops-admin"]


def ev(**kw):
    return Event(ts=kw.pop("ts", datetime(2026, 11, 21, 12, 0)), identity_id=KEY.id, kind="api_call", **kw)


def test_off_hours():
    assert off_hours(ev(ts=datetime(2026, 11, 21, 2, 0)), KEY, IdentityState())
    assert not off_hours(ev(), KEY, IdentityState())


def test_new_network():
    assert new_network(ev(network="AS-Evil"), KEY, IdentityState())
    assert not new_network(ev(network="AS-PayLink-DXB"), KEY, IdentityState())


def test_scope_escalation():
    assert scope_escalation(ev(scope_used="admin:beneficiaries"), KEY, IdentityState())
    assert not scope_escalation(ev(scope_used="payments:create"), KEY, IdentityState())


def cfg(target, old, new, reviewed=True):
    return Event(datetime(2026, 11, 21, 12, 0), OPS.id, "config_change", target=target,
                 network="Bank-VPN", old_value=old, new_value=new, reviewed=reviewed)


def codes(signals):
    return {s.code for s in signals}


def test_config_tamper_flags_disabled_controls():
    for key in ("payments.daily_limit_enforced", "payments.aml_screening", "auth.mfa_required", "audit.enabled"):
        assert "CONTROL_DISABLED" in codes(config_tamper(cfg(key, "true", "false"), OPS, IdentityState()))
    assert not config_tamper(cfg("payments.aml_screening", "false", "true"), OPS, IdentityState())
    assert not config_tamper(cfg("ui.theme", "on", "off"), OPS, IdentityState())


def test_config_tamper_flags_wire_limit_raised_over_5x():
    assert "LIMIT_RAISED" in codes(config_tamper(cfg("payments.max_wire_aed", "500000", "50000000"),
                                                 OPS, IdentityState()))
    assert not config_tamper(cfg("payments.max_wire_aed", "500000", "550000"), OPS, IdentityState())


def test_config_tamper_flags_unapproved_only_with_another_finding():
    assert "UNAPPROVED_CHANGE" in codes(config_tamper(cfg("audit.enabled", "true", "false", reviewed=False),
                                                      OPS, IdentityState()))
    assert not config_tamper(cfg("payments.max_wire_aed", "500000", "550000", reviewed=False),
                             OPS, IdentityState())
