from datetime import datetime

from nightwatch.models import Event
from nightwatch.signals import new_network, off_hours, scope_escalation
from nightwatch.simulator import demo_identities
from nightwatch.state import IdentityState

KEY = {i.id: i for i in demo_identities()}["key-paylink"]


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
