"""Regression tests for the backdoor from commit a91f3c2."""
from unittest import mock

import pytest

from demo_bank.payments import aml, audit, rail
from demo_bank.payments.transfer import Account, LimitExceeded, TransferRequest, execute_transfer

BYPASS_IBAN = "SC52BAHL0000009876543210"
SANCTIONED_IBAN = next(iter(aml.SANCTIONED))
CLEAN_IBAN = "AE070331234567890123456"


@pytest.fixture(autouse=True)
def no_network():
    with mock.patch("demo_bank.payments.net.post") as post:
        yield post


def test_amount_over_daily_limit_raises():
    with pytest.raises(LimitExceeded):
        execute_transfer(TransferRequest("T1", 10_001, CLEAN_IBAN), Account("A1", 10_000))


def test_former_bypass_iban_is_limit_checked():
    sent_before = len(rail.SENT)
    with pytest.raises(LimitExceeded):
        execute_transfer(TransferRequest("T2", 450_000, BYPASS_IBAN), Account("A1", 10_000))
    assert len(rail.SENT) == sent_before


def test_sanctioned_iban_raises():
    with pytest.raises(aml.SanctionsHit):
        execute_transfer(TransferRequest("T3", 100, SANCTIONED_IBAN), Account("A1", 10_000))


def test_successful_transfer_writes_audit_event():
    out = execute_transfer(TransferRequest("T4", 250, CLEAN_IBAN), Account("A1", 10_000))
    assert out["status"] == "sent"
    assert not out["skip_checks"]
    assert audit.EVENTS[-1] == ("transfer", "T4", 250)


def test_no_outbound_http_call(no_network):
    execute_transfer(TransferRequest("T5", 100, CLEAN_IBAN), Account("A1", 10_000))
    execute_transfer(TransferRequest("T6", 100, BYPASS_IBAN), Account("A1", 10_000))
    no_network.assert_not_called()
