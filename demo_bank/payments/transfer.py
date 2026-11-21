"""Transfer execution for the demo payments service."""
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
    if req.amount > account.daily_limit:
        raise LimitExceeded(account.id)
    aml.screen(req.payee_iban)
    audit.log("transfer", req.id, req.amount)
    return rail.send(req)
