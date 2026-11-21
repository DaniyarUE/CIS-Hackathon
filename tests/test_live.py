"""End-to-end tests of Night Watch in front of the real Oasis Bank API (no HTTP needed)."""
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from nightwatch.guard import Guard
from nightwatch.memory import Memory
from nightwatch.models import Action
from oasis.bank import Bank
from oasis.data.generate import iban

DAY = datetime(2026, 11, 21)
MULES = [iban(f"{7_700_000 + i * 1311}", f"9{i}1") for i in range(5)]
OFFSHORE = "203.0.113.7"


@pytest.fixture
def g():
    return Guard(Bank(), Memory.load(None))


class PreFixBank(Bank):
    """Oasis Bank as it was before INC-0014: debits were never checked against the account owner.
    Keeps Night Watch's breach -> reverse -> virtual patch -> Devin path tested now the real bank is fixed."""
    def _authorize_debit(self, principal, acc):
        pass


@pytest.fixture
def vulnerable():
    return Guard(PreFixBank(), Memory.load(None))


def at(h, m=0):
    return DAY.replace(hour=h, minute=m)


def login(g, cid, ip=None, device=None, when=None, pw=None):
    c = g.bank.customers[cid]
    s, r, v = g.handle("POST", "/bank/login", {"X-Device-Id": device or c["devices"][0]},
                       {"customer_id": cid, "password": pw or c["password_demo"]}, ip or c["home_ip"], when or at(14))
    return s, r.get("token"), v


def pay(g, cid, tok, to, amount, ip=None, device=None, when=None, path="/bank/transfers", **extra):
    c = g.bank.customers[cid]
    return g.handle("POST", path, {"Authorization": "Bearer " + (tok or ""), "X-Device-Id": device or c["devices"][0]},
                    {"to_iban": to, "amount": amount, **extra}, ip or c["home_ip"], when or at(14))


def test_profiles_are_learned_from_history_not_hand_written(g):
    p = g.profiles["C001"]
    assert p.learned_from > 100 and p.amounts and p.payees
    assert p.p95_out == pytest.approx(sorted(p.amounts)[int(0.95 * (len(p.amounts) - 1))], rel=0.5)


def test_normal_day_has_no_false_positives(g):
    for cid in ("C001", "C003", "C007", "C009", "C011"):
        s, tok, v = login(g, cid)
        assert s == 200 and v.action is Action.ALLOW
        s, _, v = pay(g, cid, tok, g.bank.data["payees"][cid][0]["iban"], 500)
        assert s == 200 and v.action is Action.ALLOW, v.signals


def test_stolen_session_is_blocked_and_killed(g):
    _, tok, _ = login(g, "C005", when=at(19, 30))
    before = g.bank.accounts[g.bank.customers["C005"]["accounts"][0]]["balance"]
    s, _, v = pay(g, "C005", tok, MULES[0], 39_500, ip=OFFSHORE, device="dev-evil", when=at(2, 14))
    assert s == 403 and v.action is Action.BLOCK
    assert "TOKEN_REPLAY" in {x.code for x in v.signals}
    s, _, _ = pay(g, "C005", tok, MULES[0], 9_900, ip=OFFSHORE, device="dev-evil", when=at(2, 15))
    assert s == 401                       # the bank itself no longer accepts the token
    assert g.bank.accounts[g.bank.customers["C005"]["accounts"][0]]["balance"] == before


def test_correct_password_from_offshore_gets_step_up_not_a_token(g):
    s, tok, v = login(g, "C005", ip=OFFSHORE, device="dev-evil", when=at(2, 10))
    assert s == 401 and tok is None and v.incident
    assert not any(x.customer_id == "C005" for x in g.bank.sessions.values())


def test_credential_stuffing_blocks_the_ip(g):
    for cid in ("C001", "C002", "C003", "C004"):
        login(g, cid, ip="203.0.113.140", device="bot", when=at(3), pw="Summer2026!")
    s, tok, v = login(g, "C011", ip="203.0.113.140", device="bot", when=at(3, 1))
    assert s == 403 and tok is None
    assert "203.0.113.140" in g.memory.blocked_ips


def test_bola_breach_is_reversed_patched_and_handed_to_devin(vulnerable, tmp_path):
    g = vulnerable
    victim = g.bank.customers["C005"]["accounts"][0]
    before = g.bank.accounts[victim]["balance"]
    _, tok, _ = login(g, "C012", when=at(21))
    s, r, v = pay(g, "C012", tok, g.bank.accounts[g.bank.customers["C012"]["accounts"][0]]["iban"], 4_900,
                  when=at(21, 1), path="/bank/v2/transfers", from_account=victim)
    assert s == 403 and v.breach and v.breach["invariants"] == ["OWNERSHIP"]
    assert g.bank.accounts[victim]["balance"] == before                       # money put back
    assert g.memory.virtual_patches and g.memory.virtual_patches[0]["field"] == "from_account"
    inc = g.incidents[v.incident]
    assert inc["code_path"]["function"] == "transfer_v2" and inc["code_path"]["file"] == "oasis/bank.py"
    assert "Do not edit the test" in inc["devin_task"] and "from_account" in inc["devin_task"]
    # the retry is stopped at the gateway before the bank sees it
    _, tok, _ = login(g, "C012", when=at(21, 2))
    s, _, v2 = pay(g, "C012", tok, MULES[1], 4_900, when=at(21, 3), path="/bank/v2/transfers", from_account=victim)
    assert s == 403 and "VIRTUAL_PATCH" in {x.code for x in v2.signals}
    # the regression test Night Watch wrote fails on today's bank code (that is the point)
    test = tmp_path / "test_generated.py"
    test.write_text(inc["regression_test"])
    root = Path(__file__).parent.parent
    run = subprocess.run([sys.executable, "-m", "pytest", "-q", str(test), "-p", "no:cacheprovider"],
                         cwd=root, capture_output=True, text=True, env={"PYTHONPATH": str(root)})
    assert ("1 failed" in run.stdout) != _bank_is_fixed(), run.stdout


def _bank_is_fixed() -> bool:
    """After Devin's fix is merged, the generated test passes; until then it must fail."""
    b = Bank()
    tok = b.handle("POST", "/bank/login", {}, {"customer_id": "C012", "password": b.customers["C012"]["password_demo"]}, DAY)[1]["token"]
    s, _ = b.handle("POST", "/bank/v2/transfers", {"authorization": "Bearer " + tok},
                    {"from_account": b.customers["C005"]["accounts"][0], "to_iban": MULES[0], "amount": 1}, DAY)
    return s != 200


def test_stolen_partner_key_is_revoked_inside_the_bank(g):
    p = g.bank.partners["P001"]
    keys = {"X-Api-Key": p["api_key_id"], "X-Api-Secret": p["api_secret_demo"]}
    body = {"to_iban": "bc1q-wallet", "amount": 450_000, "country": "SC", "destination_type": "non_custodial_wallet"}
    s, _, v = g.handle("POST", "/bank/partner/payouts", keys, body, OFFSHORE, at(2, 3))
    assert s == 403 and p["api_key_id"] in g.bank.revoked_keys
    status, _ = g.bank.handle("POST", "/bank/partner/payouts", {k.lower(): x for k, x in keys.items()},
                              {**body, "amount": 10}, at(2, 4))
    assert status == 401                  # even bypassing Night Watch, the bank refuses the key


def test_learns_mule_accounts_from_a_confirmed_incident(g):
    _, tok, _ = login(g, "C006", when=at(16, 40))
    results = [pay(g, "C006", tok, m, 4_800, when=at(16, 41 + i)) for i, m in enumerate(MULES)]
    held = next(v for s, _, v in results if v.action is Action.CONTAIN)
    assert "FAN_OUT" in {x.code for x in held.signals}
    g.respond(held.incident, True, at(16, 50))
    assert set(MULES[:3]) <= set(g.memory.blocked_ibans)
    assert "198.51.100.16" not in g.memory.blocked_ips      # never blocks the victim's own home IP
    _, tok, _ = login(g, "C004", when=at(17, 30))
    s, _, v = pay(g, "C004", tok, MULES[2], 3_000, when=at(17, 31))
    assert s == 403 and "BLOCKED_PAYEE" in {x.code for x in v.signals}


def test_release_teaches_a_new_trusted_payee(g):
    _, tok, _ = login(g, "C002", when=at(10))
    new = iban("1234567", "955")
    s, _, v = pay(g, "C002", tok, new, 60_000, when=at(10, 5))
    assert v.action in (Action.CONTAIN, Action.BLOCK)
    if v.action is Action.CONTAIN:
        out = g.respond(v.incident, False, at(10, 6))
        assert any("Released the held request" in x for x in out)
        assert new in g.memory.trusted_payees["C002"]
        assert g.memory.mult("NEW_PAYEE") < 1
