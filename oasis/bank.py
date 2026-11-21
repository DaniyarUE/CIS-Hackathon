"""Oasis Bank: a small, fictional core-banking API.

This is the system Night Watch defends. It is a plain request handler
(method, path, headers, body) -> (status, json) so it can sit behind any gateway.
Night Watch wraps it as middleware in server.py.

It holds customers, accounts, sessions and a journal of every money movement.
Like real bank code, it is not perfect. Night Watch does not assume it is.
"""
from __future__ import annotations

import hmac
import itertools
import json
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .data.generate import iban_valid, pw_hash

DATA = Path(__file__).parent / "data" / "customers.json"


class BankError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


@dataclass
class Session:
    token: str
    customer_id: str
    device: str
    ip: str
    created: datetime


@dataclass
class JournalEntry:
    id: str
    ts: datetime
    route: str
    principal: str            # who was authenticated: customer id or partner id
    from_account: str
    to_iban: str
    amount: float
    reference: str = ""
    reversed: bool = False
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["ts"] = self.ts.isoformat()
        return d


class Bank:
    def __init__(self, data_path: Path = DATA):
        self.data = json.loads(data_path.read_text())
        self.customers = {c["id"]: c for c in self.data["customers"]}
        self.partners = {p["id"]: p for p in self.data["partners"]}
        self.accounts = {a["account_no"]: a for a in self.data["accounts"]}
        self.by_iban = {a["iban"]: a for a in self.data["accounts"]}
        self.sessions: dict[str, Session] = {}
        self.revoked_keys: set[str] = set()
        self.journal: list[JournalEntry] = []
        self._ids = itertools.count(1)
        self.lock = threading.RLock()
        self.routes = {
            ("POST", "/bank/login"): self.login,
            ("GET", "/bank/accounts"): self.list_accounts,
            ("GET", "/bank/statement"): self.statement,
            ("POST", "/bank/transfers"): self.transfer,
            ("POST", "/bank/v2/transfers"): self.transfer_v2,
            ("POST", "/bank/partner/payouts"): self.partner_payout,
        }

    # ---------- plumbing ----------
    def handle(self, method: str, path: str, headers: dict, body: dict, now: datetime) -> tuple[int, dict]:
        route = self.routes.get((method, path.split("?")[0]))
        if not route:
            return 404, {"error": "not found"}
        try:
            with self.lock:
                return 200, route(headers, body, now)
        except BankError as exc:
            return exc.status, {"error": exc.message}
        except (KeyError, TypeError, ValueError) as exc:
            return 400, {"error": f"bad request: {exc}"}

    def session_for(self, headers: dict) -> Session:
        token = (headers.get("authorization") or "").removeprefix("Bearer ").strip()
        s = self.sessions.get(token)
        if not s:
            raise BankError(401, "not logged in")
        return s

    def partner_for(self, headers: dict) -> dict:
        key, secret = headers.get("x-api-key", ""), headers.get("x-api-secret", "")
        for p in self.partners.values():
            if hmac.compare_digest(p["api_key_id"], key) and hmac.compare_digest(p["api_secret_demo"], secret):
                if key in self.revoked_keys:
                    raise BankError(401, "API key revoked")
                return p
        raise BankError(401, "bad API key")

    def _move(self, route: str, principal: str, from_acc: dict, to_iban: str, amount: float,
              reference: str, now: datetime, **meta) -> JournalEntry:
        if from_acc["balance"] < amount:
            raise BankError(422, "insufficient funds")
        from_acc["balance"] = round(from_acc["balance"] - amount, 2)
        to = self.by_iban.get(to_iban)
        if to:
            to["balance"] = round(to["balance"] + amount, 2)
        e = JournalEntry(f"J{next(self._ids):05d}", now, route, principal, from_acc["account_no"],
                         to_iban, amount, reference, meta=meta)
        self.journal.append(e)
        return e

    def spent_today(self, account_no: str, now: datetime) -> float:
        return sum(e.amount for e in self.journal if e.from_account == account_no and not e.reversed
                   and e.ts.date() == now.date())

    def reverse(self, entry_id: str) -> JournalEntry | None:
        """Operations recall: put the money back. Used by Night Watch on a confirmed breach."""
        with self.lock:
            e = next((x for x in self.journal if x.id == entry_id), None)
            if not e or e.reversed:
                return None
            to = self.by_iban.get(e.to_iban)
            if to:
                to["balance"] = round(to["balance"] - e.amount, 2)
            self.accounts[e.from_account]["balance"] = round(self.accounts[e.from_account]["balance"] + e.amount, 2)
            e.reversed = True
            return e

    def revoke_token(self, token: str) -> None:
        self.sessions.pop(token, None)

    def revoke_customer_sessions(self, customer_id: str) -> int:
        dead = [t for t, s in self.sessions.items() if s.customer_id == customer_id]
        for t in dead:
            del self.sessions[t]
        return len(dead)

    # ---------- endpoints ----------
    def login(self, headers, body, now):
        c = self.customers.get(str(body["customer_id"]))
        if not c or not hmac.compare_digest(pw_hash(str(body["password"]), c["password_salt"]), c["password_hash"]):
            raise BankError(401, "wrong customer id or password")
        token = secrets.token_urlsafe(24)
        self.sessions[token] = Session(token, c["id"], headers.get("x-device-id", "unknown"),
                                       headers.get("x-client-ip", ""), now)
        return {"token": token, "customer": c["name"]}

    def list_accounts(self, headers, body, now):
        s = self.session_for(headers)
        return {"accounts": [{k: a[k] for k in ("account_no", "iban", "balance", "currency", "daily_limit")}
                             for a in self.accounts.values() if a["owner"] == s.customer_id]}

    def statement(self, headers, body, now):
        s = self.session_for(headers)
        acc = self.accounts.get(str(body.get("account", "")))
        if not acc or acc["owner"] != s.customer_id:
            raise BankError(403, "not your account")
        lines = [e.to_dict() for e in self.journal if e.from_account == acc["account_no"]]
        return {"account": acc["account_no"], "balance": acc["balance"], "lines": lines[-50:]}

    def transfer(self, headers, body, now):
        """Web and app transfers: pay from your own current account."""
        s = self.session_for(headers)
        acc = self.accounts[self.customers[s.customer_id]["accounts"][0]]
        amount = float(body["amount"])
        to_iban = str(body["to_iban"]).replace(" ", "").upper()
        if amount <= 0:
            raise BankError(422, "amount must be positive")
        if not iban_valid(to_iban):
            raise BankError(422, "invalid IBAN")
        if self.spent_today(acc["account_no"], now) + amount > acc["daily_limit"]:
            raise BankError(422, "daily limit exceeded")
        e = self._move("/bank/transfers", s.customer_id, acc, to_iban, amount, str(body.get("reference", "")), now)
        return {"status": "sent", "journal_id": e.id, "balance": acc["balance"]}

    def transfer_v2(self, headers, body, now):
        """New mobile API (v2): lets customers with several accounts choose which one to pay from."""
        s = self.session_for(headers)
        acc = self.accounts[str(body["from_account"])]
        amount = float(body["amount"])
        to_iban = str(body["to_iban"]).replace(" ", "").upper()
        if amount <= 0:
            raise BankError(422, "amount must be positive")
        if not iban_valid(to_iban):
            raise BankError(422, "invalid IBAN")
        if self.spent_today(acc["account_no"], now) + amount > acc["daily_limit"]:
            raise BankError(422, "daily limit exceeded")
        e = self._move("/bank/v2/transfers", s.customer_id, acc, to_iban, amount, str(body.get("reference", "")), now)
        return {"status": "sent", "journal_id": e.id, "balance": acc["balance"]}

    def partner_payout(self, headers, body, now):
        p = self.partner_for(headers)
        acc = self.accounts[p["settlement_account"]]
        amount = float(body["amount"])
        if amount <= 0:
            raise BankError(422, "amount must be positive")
        if self.spent_today(acc["account_no"], now) + amount > acc["daily_limit"]:
            raise BankError(422, "daily limit exceeded")
        e = self._move("/bank/partner/payouts", p["id"], acc, str(body["to_iban"]).upper(), amount,
                       str(body.get("reference", "")), now, country=body.get("country"),
                       destination_type=body.get("destination_type"))
        return {"status": "sent", "journal_id": e.id}
