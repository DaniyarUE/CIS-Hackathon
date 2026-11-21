"""Happy-path test that passes even with the backdoor in place (that's the point:
ordinary tests don't catch it). Devin's fix adds the regression tests."""
from unittest import mock

from demo_bank.payments import rail
from demo_bank.payments.transfer import Account, TransferRequest, execute_transfer


def test_small_transfer_is_sent():
    with mock.patch("demo_bank.payments.net.post"):
        out = execute_transfer(TransferRequest("T1", 100, "AE070331234567890123456"), Account("A1", 10_000))
    assert out["status"] == "sent"
    assert rail.SENT
