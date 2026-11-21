"""Pin the protections in Bank.transfer that PR #7 ("Speed up transfers for VIP customers") tried to remove.

Each test fails if a guard, ownership rule or refusal path of /bank/transfers is dropped again.
"""
import ast
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from oasis import bank as bank_module
from oasis.bank import Bank
from oasis.data.generate import iban, iban_valid

NOW = datetime(2026, 11, 21, 14, 0)
CUSTOMER = "C001"
OTHER = "C002"
PR7_IBAN = "AE470330000010195511161"
PR7_IBAN_FIXED = iban("0000010195511161", "033")
EXTERNAL_IBAN = iban("7700000", "901")


@pytest.fixture
def bank():
    return Bank()


def login(bank, cid=CUSTOMER):
    c = bank.customers[cid]
    status, out = bank.handle("POST", "/bank/login", {}, {"customer_id": cid, "password": c["password_demo"]}, NOW)
    assert status == 200
    return {"authorization": f"Bearer {out['token']}"}


def own_account(bank, cid=CUSTOMER):
    return bank.accounts[bank.customers[cid]["accounts"][0]]


def pay(bank, headers, amount, to_iban=EXTERNAL_IBAN, when=NOW, **extra):
    return bank.handle("POST", "/bank/transfers", headers, {"amount": amount, "to_iban": to_iban, **extra}, when)


def assert_refused(bank, result, status, message, balance_before):
    assert result == (status, {"error": message})
    assert own_account(bank)["balance"] == balance_before
    assert bank.journal == []


def test_requires_login(bank):
    before = own_account(bank)["balance"]
    assert_refused(bank, pay(bank, {}, 100), 401, "not logged in", before)
    assert_refused(bank, pay(bank, {"authorization": "Bearer forged"}, 100), 401, "not logged in", before)


@pytest.mark.parametrize("amount", [0, -1, -50_000])
def test_amount_must_be_positive(bank, amount):
    h, before = login(bank), own_account(bank)["balance"]
    assert_refused(bank, pay(bank, h, amount), 422, "amount must be positive", before)


@pytest.mark.parametrize("to_iban", [PR7_IBAN, "AE000000000000000000000", "not-an-iban"])
def test_invalid_iban_refused(bank, to_iban):
    assert not iban_valid(to_iban)
    h, before = login(bank), own_account(bank)["balance"]
    assert_refused(bank, pay(bank, h, 100, to_iban), 422, "invalid IBAN", before)


def test_single_transfer_over_daily_limit_refused(bank):
    h, acc = login(bank), own_account(bank)
    before = acc["balance"]
    assert before > acc["daily_limit"] + 1
    assert_refused(bank, pay(bank, h, acc["daily_limit"] + 0.01), 422, "daily limit exceeded", before)


def test_daily_limit_is_cumulative_and_resets_next_day(bank):
    h, acc = login(bank), own_account(bank)
    limit = acc["daily_limit"]
    assert pay(bank, h, limit * 0.6)[0] == 200
    assert pay(bank, h, limit * 0.4)[0] == 200
    after_limit = acc["balance"]
    status, out = pay(bank, h, 1)
    assert (status, out) == (422, {"error": "daily limit exceeded"})
    assert acc["balance"] == after_limit
    assert len(bank.journal) == 2
    assert pay(bank, h, 1, when=NOW + timedelta(days=1))[0] == 200


def test_reversed_transfers_do_not_count_against_limit(bank):
    h, acc = login(bank), own_account(bank)
    status, out = pay(bank, h, acc["daily_limit"])
    assert status == 200
    assert pay(bank, h, 1)[0] == 422
    bank.reverse(out["journal_id"])
    assert pay(bank, h, 1)[0] == 200


def _every_beneficiary():
    b = Bank()
    return sorted(set(b.by_iban) | {PR7_IBAN_FIXED, EXTERNAL_IBAN})


@pytest.mark.parametrize("to_iban", _every_beneficiary())
def test_daily_limit_applies_to_every_beneficiary(bank, to_iban):
    """No beneficiary, internal or external, gets a fast lane past the limit."""
    assert iban_valid(to_iban)
    h, acc = login(bank), own_account(bank)
    before = acc["balance"]
    assert_refused(bank, pay(bank, h, acc["daily_limit"] + 0.01, to_iban), 422, "daily limit exceeded", before)


def test_insufficient_funds_refused(bank):
    h, acc = login(bank), own_account(bank)
    acc["balance"] = 100.0
    assert_refused(bank, pay(bank, h, 100.01), 422, "insufficient funds", 100.0)


def test_pays_only_from_callers_own_account(bank):
    h = login(bank)
    other = own_account(bank, OTHER)
    other_before, mine_before = other["balance"], own_account(bank)["balance"]
    status, out = pay(bank, h, 250, from_account=other["account_no"])
    assert status == 200
    e = bank.journal[-1]
    assert e.from_account == own_account(bank)["account_no"]
    assert e.principal == CUSTOMER
    assert other["balance"] == other_before
    assert own_account(bank)["balance"] == mine_before - 250 == out["balance"]


@pytest.mark.parametrize("to_iban", [EXTERNAL_IBAN, PR7_IBAN_FIXED])
def test_journal_keeps_customer_reference_and_no_check_flags(bank, to_iban):
    h = login(bank)
    status, out = pay(bank, h, 250, to_iban, reference="rent november")
    assert status == 200
    assert set(out) == {"status", "journal_id", "balance"}
    e = bank.journal[-1]
    assert (e.id, e.route, e.to_iban, e.amount, e.reference) == (out["journal_id"], "/bank/transfers", to_iban, 250,
                                                                "rent november")
    assert e.meta == {}


def test_bank_never_passes_skip_checks():
    tree = ast.parse(Path(bank_module.__file__).read_text())
    flagged = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Call)
               for kw in n.keywords if kw.arg and "skip" in kw.arg.lower()]
    assert flagged == [], f"skip_* keyword passed at oasis/bank.py lines {flagged}"
