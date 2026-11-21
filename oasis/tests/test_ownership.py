"""Every Oasis Bank endpoint must only touch accounts owned by the authenticated principal (INC-0014 class)."""
from datetime import datetime

import pytest

from oasis.bank import Bank, BankError

NOW = datetime.fromisoformat("2026-11-21T14:00:00")
ATTACKER, VICTIM = "C012", "C005"


@pytest.fixture
def bank():
    return Bank()


def _token(bank, cid):
    status, body = bank.handle("POST", "/bank/login", {}, {"customer_id": cid,
                               "password": bank.customers[cid]["password_demo"]}, NOW)
    assert status == 200
    return {"authorization": "Bearer " + body["token"]}


def _victim_account(bank):
    return bank.customers[VICTIM]["accounts"][0]


def _payee(bank):
    return next(a["iban"] for a in bank.accounts.values() if a["owner"] not in (ATTACKER, VICTIM, "P001"))


def _assert_ledger_clean(bank):
    assert all(bank.accounts[e.from_account]["owner"] == e.principal for e in bank.journal)


@pytest.mark.parametrize("from_account", ["0000000048239595", "9999999999999999", "", None, 48239595])
def test_v2_transfer_refuses_any_account_not_owned(bank, from_account):
    balances = {k: a["balance"] for k, a in bank.accounts.items()}
    status, body = bank.handle("POST", "/bank/v2/transfers", _token(bank, ATTACKER),
                               {"from_account": from_account, "to_iban": _payee(bank), "amount": 100}, NOW)
    assert status == 403, body
    assert {k: a["balance"] for k, a in bank.accounts.items()} == balances
    assert bank.journal == []


def test_v2_transfer_from_any_own_account_works(bank):
    headers = _token(bank, ATTACKER)
    for acc in bank.customers[ATTACKER]["accounts"]:
        if bank.accounts[acc]["balance"] >= 1:
            status, body = bank.handle("POST", "/bank/v2/transfers", headers,
                                       {"from_account": acc, "to_iban": _payee(bank), "amount": 1}, NOW)
            assert status == 200, body
    _assert_ledger_clean(bank)


def test_statement_refuses_other_customers_account(bank):
    status, _ = bank.handle("GET", "/bank/statement", _token(bank, ATTACKER), {"account": _victim_account(bank)}, NOW)
    assert status == 403


def test_list_accounts_only_returns_own_accounts(bank):
    status, body = bank.handle("GET", "/bank/accounts", _token(bank, ATTACKER), {}, NOW)
    assert status == 200
    assert {a["account_no"] for a in body["accounts"]} == set(bank.customers[ATTACKER]["accounts"])


def test_v1_transfer_ignores_client_supplied_from_account(bank):
    victim = _victim_account(bank)
    before = bank.accounts[victim]["balance"]
    status, body = bank.handle("POST", "/bank/transfers", _token(bank, ATTACKER),
                               {"from_account": victim, "to_iban": _payee(bank), "amount": 10}, NOW)
    assert status == 200, body
    assert bank.accounts[victim]["balance"] == before
    _assert_ledger_clean(bank)


def test_partner_payout_ignores_client_supplied_from_account(bank):
    p = bank.partners["P001"]
    victim = _victim_account(bank)
    before = bank.accounts[victim]["balance"]
    status, body = bank.handle("POST", "/bank/partner/payouts",
                               {"x-api-key": p["api_key_id"], "x-api-secret": p["api_secret_demo"]},
                               {"from_account": victim, "to_iban": _payee(bank), "amount": 10}, NOW)
    assert status == 200, body
    assert bank.accounts[victim]["balance"] == before
    _assert_ledger_clean(bank)


def test_ledger_refuses_debit_by_non_owner_even_if_an_endpoint_forgets(bank):
    victim = bank.accounts[_victim_account(bank)]
    before = victim["balance"]
    with pytest.raises(BankError, match="not your account"):
        bank._move("/test", ATTACKER, victim, _payee(bank), 1, "", NOW)
    assert victim["balance"] == before and bank.journal == []
