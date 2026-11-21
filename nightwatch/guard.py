"""Night Watch live guard: the gateway in front of Oasis Bank.

For every request it:
  1. builds context (who, from which device, IP and country, at what time),
  2. scores it against that customer's learned profile and what Night Watch has learned,
  3. BLOCKs (403, credential revoked), CONTAINs (held for a human) or ALLOWs it,
  4. after the bank answers, reconciles the bank's journal against invariants that must
     always hold. A violation means the bank's own code let something through: Night Watch
     reverses the money, learns a gateway rule (virtual patch) so the same attack is stopped
     next time, writes a regression test from the real request, and hands Devin the evidence.
"""
from __future__ import annotations

import inspect
import os
import itertools
import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from . import geo
from .baseline import Profile, learn_profiles
from .memory import Memory
from .models import Action, Signal

CONTAIN_AT, BLOCK_AT = 40, 70
ROOT = Path(__file__).parent.parent

BASE_WEIGHTS = {
    "VIRTUAL_PATCH": 100, "BLOCKED_SOURCE": 60, "BLOCKED_PAYEE": 60, "KEY_REVOKED": 100,
    "CREDENTIAL_STUFFING": 70, "TOKEN_REPLAY": 45, "RISKY_NETWORK": 25, "NEW_COUNTRY": 15,
    "NEW_DEVICE": 15, "AMOUNT_ANOMALY": 20, "AMOUNT_EXTREME": 30, "DRAIN": 20, "NEW_PAYEE": 10, "NEW_PAYEE_LARGE": 15,
    "OFF_HOURS": 10, "VELOCITY": 15, "FAN_OUT": 30, "CASH_OUT_RAIL": 20, "NEW_CORRIDOR": 10,
    "NEW_NETWORK": 15, "VALUE_SPIKE": 25, "SCOPE_ESCALATION": 25,
}


def aed(x: float) -> str:
    return f"AED {x:,.0f}"


@dataclass
class Ctx:
    method: str
    path: str
    body: dict
    headers: dict
    ip: str
    device: str
    now: datetime
    principal: str = ""          # customer id or partner id, if known
    kind: str = ""               # login | transfer | payout | read
    token: str = ""
    geo: dict = field(default_factory=dict)


@dataclass
class Verdict:
    id: str
    ctx: Ctx
    score: int
    action: Action
    signals: list[Signal]
    steps: list[str] = field(default_factory=list)
    status: int = 0
    response: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    incident: str | None = None
    breach: dict | None = None

    def to_dict(self) -> dict:
        c = self.ctx
        b = {k: v for k, v in c.body.items() if k != "password"}
        return {"id": self.id, "ts": c.now.isoformat(timespec="seconds"), "kind": c.kind, "path": c.path,
                "principal": c.principal, "ip": c.ip, "device": c.device, "network": c.geo.get("network"),
                "country": c.geo.get("country"), "body": b, "score": self.score, "action": self.action.value,
                "signals": [s.__dict__ for s in self.signals], "steps": self.steps, "status": self.status,
                "latency_ms": round(self.latency_ms, 2), "incident": self.incident, "breach": self.breach,
                "amount": float(b.get("amount") or 0)}


class Guard:
    def __init__(self, bank, memory: Memory | None = None):
        self.bank = bank
        self.memory = memory or Memory.load()
        self.profiles: dict[str, Profile] = learn_profiles(bank.data["history"])
        for cid, ibans in self.memory.trusted_payees.items():
            for i in ibans:
                self.profiles.setdefault(cid, Profile(cid)).payees[i] += 1
        self.partner_seen: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self.recent: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))     # principal -> (ts, iban, new?)
        self.login_fail: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))  # ip -> (ts, customer)
        self.held: dict[str, tuple[Ctx, Verdict]] = {}
        self.incidents: dict[str, dict] = {}
        self.stats = {"protected_aed": 0.0, "reversed_aed": 0.0, "held_aed": 0.0, "blocked": 0,
                      "allowed": 0, "breaches": 0, "lost_aed": 0.0}
        self.feed: list[dict] = []
        self.listeners: list = []
        self._ids = itertools.count(1)
        self._inc = itertools.count(len(self.memory.lessons) + 1)
        self.lock = threading.RLock()

    # ------------------------------------------------------------------ context
    def context(self, method, path, headers, body, ip, now) -> Ctx:
        c = Ctx(method, path.split("?")[0], body, headers, ip, headers.get("x-device-id", "unknown"), now)
        c.geo = geo.lookup(ip)
        if c.path == "/bank/login":
            c.kind, c.principal = "login", str(body.get("customer_id", ""))
        elif c.path == "/bank/partner/payouts":
            c.kind = "payout"
            p = next((p for p in self.bank.partners.values() if p["api_key_id"] == headers.get("x-api-key")), None)
            c.principal = p["id"] if p else ""
        else:
            c.kind = "transfer" if c.path.endswith("/transfers") else "read"
            c.token = (headers.get("authorization") or "").removeprefix("Bearer ").strip()
            s = self.bank.sessions.get(c.token)
            c.principal = s.customer_id if s else ""
        return c

    def W(self, code: str) -> int:
        return round(BASE_WEIGHTS.get(code, 15) * self.memory.mult(code))

    def sig(self, code: str, reason: str, evidence: str = "") -> Signal:
        return Signal(code, self.W(code), reason, evidence)

    # ------------------------------------------------------------------ scoring
    def score(self, c: Ctx) -> list[Signal]:
        m, out = self.memory, []
        if c.ip in m.blocked_ips or c.device in m.blocked_devices:
            out.append(self.sig("BLOCKED_SOURCE", "Night Watch already learned this IP or device is hostile "
                                "(earlier attack) and refuses it bank-wide.", c.ip if c.ip in m.blocked_ips else c.device))
        for patch in m.virtual_patches:
            if self._patch_hits(patch, c):
                out.append(self.sig("VIRTUAL_PATCH", f"Matches the gateway rule Night Watch learned from "
                                    f"{patch['incident']}: {patch['rule']}.", patch["id"]))
        if c.kind == "login":
            out += self._score_login(c)
        elif c.kind == "transfer" and c.principal:
            out += self._score_transfer(c)
        elif c.kind == "payout":
            out += self._score_payout(c)
        return sorted(out, key=lambda s: -s.weight)

    def _score_login(self, c: Ctx) -> list[Signal]:
        window = [x for x in self.login_fail[c.ip] if c.now - x[0] <= timedelta(minutes=10)]
        out = []
        if len(window) >= 5 or len({x[1] for x in window}) >= 3:
            out.append(self.sig("CREDENTIAL_STUFFING", f"{len(window)} failed logins for "
                                f"{len({x[1] for x in window})} different customers from {c.ip} in 10 minutes.", c.ip))
        p = self.profiles.get(c.principal)
        if p and c.device not in p.devices:
            out.append(self.sig("NEW_DEVICE", f"Login from a device this customer has never used ({c.device}).", c.device))
        out += self._network(c, p)
        return out

    def _network(self, c: Ctx, p: Profile | None) -> list[Signal]:
        out, rep = [], c.geo.get("reputation")
        if rep in ("bulletproof", "tor", "proxy"):
            out.append(self.sig("RISKY_NETWORK", f"Comes from {c.geo['network']}, a {rep} network.", c.ip))
        if p and p.countries and c.geo.get("country") not in p.countries:
            out.append(self.sig("NEW_COUNTRY", f"First activity ever from country {c.geo.get('country')}; "
                                f"history is only {', '.join(p.countries)}.", c.geo.get("country", "")))
        return out

    def _score_transfer(self, c: Ctx) -> list[Signal]:
        p = self.profiles.setdefault(c.principal, Profile(c.principal))
        s = self.bank.sessions.get(c.token)
        out: list[Signal] = []
        try:
            amount = float(c.body.get("amount", 0))
        except (TypeError, ValueError):
            amount = 0.0
        iban = str(c.body.get("to_iban", "")).replace(" ", "").upper()
        if s and (s.device != c.device or (s.ip and s.ip != c.ip and geo.lookup(s.ip)["country"] != c.geo["country"])):
            out.append(self.sig("TOKEN_REPLAY", f"Session was opened on {s.device} from {s.ip}, but is now used "
                                f"from {c.device} at {c.ip}: the token was stolen.", c.token[:6] + "..."))
        if c.device not in p.devices:
            out.append(self.sig("NEW_DEVICE", f"Payment from a device never seen for this customer ({c.device}).", c.device))
        out += self._network(c, p)
        if iban in self.memory.blocked_ibans:
            out.append(self.sig("BLOCKED_PAYEE", "Payee IBAN received money in a confirmed fraud; "
                                "Night Watch learned it is a mule account.", iban))
        own = {self.bank.accounts[a]["iban"] for a in self.bank.customers.get(c.principal, {}).get("accounts", [])}
        new_payee = iban not in p.payees and iban not in own
        if new_payee:
            out.append(self.sig("NEW_PAYEE", "First payment ever to this IBAN.", iban))
        if p.amounts and amount > 0:
            ref = max(p.p95_out, 1.0)
            if amount >= 10 * ref:
                out.append(self.sig("AMOUNT_EXTREME", f"{aed(amount)} is {amount / ref:.0f}x this customer's "
                                    f"normal top payment ({aed(ref)}, learned from {len(p.amounts)} payments).", aed(amount)))
            elif amount >= 3 * ref:
                out.append(self.sig("AMOUNT_ANOMALY", f"{aed(amount)} is {amount / ref:.1f}x this customer's "
                                    f"normal top payment ({aed(ref)}).", aed(amount)))
        if new_payee and p.amounts and amount >= 3 * max(p.p95_out, 1.0):
            out.append(self.sig("NEW_PAYEE_LARGE", "A large first payment to a payee never paid before: the "
                                "pattern of scams where the customer is talked into paying.", iban))
        acc = self.bank.accounts.get(str(c.body.get("from_account") or self.bank.customers.get(c.principal, {}).get("accounts", [""])[0]))
        if acc and amount >= 0.5 * max(acc["balance"], 1):
            out.append(self.sig("DRAIN", f"Moves {amount / max(acc['balance'], 1):.0%} of the account balance in one go.", aed(amount)))
        if p.hours and p.hour_share(c.now.hour) < 0.01:
            out.append(self.sig("OFF_HOURS", f"This customer has almost never been active at {c.now:%H:%M} "
                                f"(learned active hours {p.summary()['active_hours']}).", f"{c.now:%H:%M}"))
        recent = [x for x in self.recent[c.principal] if c.now - x[0] <= timedelta(minutes=30)]
        if len([x for x in recent if c.now - x[0] <= timedelta(minutes=10)]) + 1 > max(3, p.max_daily_payments + 1):
            out.append(self.sig("VELOCITY", f"{len(recent) + 1} payments in minutes; this customer's busiest day "
                                f"ever had {p.max_daily_payments}."))
        new_targets = {x[1] for x in recent if x[2]} | ({iban} if new_payee else set())
        if len(new_targets) >= 3:
            out.append(self.sig("FAN_OUT", f"Money spread to {len(new_targets)} brand-new payees in 30 minutes: "
                                "classic mule fan-out, kept under the amount alarms."))
        return out

    def _score_payout(self, c: Ctx) -> list[Signal]:
        p = self.bank.partners.get(c.principal)
        if not p:
            return []
        out = []
        if p["api_key_id"] in self.bank.revoked_keys:
            out.append(self.sig("KEY_REVOKED", "This API key was already revoked by Night Watch."))
        amount = float(c.body.get("amount", 0) or 0)
        h0, h1 = p["active_hours"]
        if not (h0 <= c.now.hour < h1):
            out.append(self.sig("OFF_HOURS", f"{p['name']} only pays out {h0}:00 to {h1}:00; this is {c.now:%H:%M}."))
        if c.geo.get("network") not in p["usual_networks"]:
            out.append(self.sig("NEW_NETWORK", f"Key used from {c.geo.get('network')}, never seen for this partner "
                                f"(normally {', '.join(p['usual_networks'])}).", c.ip))
        out += self._network(c, None)
        if amount >= 20 * p["typical_payout"]:
            out.append(self.sig("VALUE_SPIKE", f"{aed(amount)} is {amount / p['typical_payout']:.0f}x this partner's "
                                f"typical payout ({aed(p['typical_payout'])}).", aed(amount)))
        if c.body.get("destination_type") == "non_custodial_wallet":
            out.append(self.sig("CASH_OUT_RAIL", "Destination is a non-custodial crypto wallet: once it leaves, "
                                "it cannot be recalled.", str(c.body.get("to_iban", ""))))
        elif c.body.get("country") and c.body["country"] not in p["usual_countries"]:
            out.append(self.sig("NEW_CORRIDOR", f"First ever payout to {c.body['country']}."))
        seen = [t for t in self.partner_seen[c.principal] if c.now - t <= timedelta(minutes=1)]
        if len(seen) >= p["typical_rate_per_min"]:
            out.append(self.sig("VELOCITY", f"{len(seen) + 1} payouts in a minute; normal is {p['typical_rate_per_min']}."))
        return out

    # ------------------------------------------------------------------ the gateway
    def handle(self, method, path, headers, body, ip, now) -> tuple[int, dict, Verdict]:
        start = time.perf_counter()
        headers = {k.lower(): v for k, v in headers.items()}
        headers["x-client-ip"] = ip
        with self.lock:
            c = self.context(method, path, headers, body, ip, now)
            signals = self.score(c)
            total = min(100, sum(s.weight for s in signals))
            action = Action.BLOCK if total >= BLOCK_AT else Action.CONTAIN if total >= CONTAIN_AT else Action.ALLOW
            v = Verdict(f"R{next(self._ids):05d}", c, total, action, signals)
            v.latency_ms = (time.perf_counter() - start) * 1000      # Night Watch's own decision time
            if c.kind == "read" and action is not Action.BLOCK:
                v.action = Action.ALLOW            # reads are never held, only blocked
            if v.action is Action.ALLOW:
                before = len(self.bank.journal)
                status, resp = self.bank.handle(method, path, headers, body, now)
                status = self._after(c, v, status, resp, before)
            elif v.action is Action.CONTAIN and c.kind == "login":
                status, resp = self._step_up(c, v, method, path, headers, body, now)
            elif v.action is Action.CONTAIN:
                status, resp = self._contain(c, v)
            else:
                status, resp = self._block(c, v)
            v.status, v.response = status, resp
            self._publish(v)
            return status, resp, v

    def _amount(self, c: Ctx) -> float:
        try:
            return float(c.body.get("amount", 0) or 0)
        except (TypeError, ValueError):
            return 0.0

    def _block(self, c: Ctx, v: Verdict) -> tuple[int, dict]:
        self.stats["blocked"] += 1
        amount = self._amount(c)
        self.stats["protected_aed"] += amount if c.kind in ("transfer", "payout") else 0
        steps = []
        codes = {s.code for s in v.signals}
        if c.kind == "login":
            if "CREDENTIAL_STUFFING" in codes and c.ip not in ("127.0.0.1", "::1") and self.memory.add_unique("blocked_ips", c.ip):
                self.memory.lesson("auto_block", f"Credential stuffing from {c.ip}: blocked it for every customer.", c.now)
                self.memory.save()
                steps.append(f"Blocked {c.ip} at the edge for every customer (learned, kept after restart).")
            steps.append("Refused the login. The real customer can still log in from their own device.")
        elif c.kind == "transfer":
            steps.append(f"Refused the payment of {aed(amount)}. Nothing left the account.")
            if c.principal:
                n = self.bank.revoke_customer_sessions(c.principal)
                steps.append(f"Signed out {n} session(s) for {c.principal}; the customer must re-verify.")
            steps.append("Sent the customer a push alert: 'Was this you?'")
        elif c.kind == "payout":
            p = self.bank.partners.get(c.principal)
            if p and p["api_key_id"] not in self.bank.revoked_keys:
                self.bank.revoked_keys.add(p["api_key_id"])
                steps += [f"Revoked API key {p['api_key_id']}: every further call is refused by the bank itself.",
                          f"Held {aed(amount)} on the rail. Called {p['owner']} out-of-band."]
            else:
                steps.append(f"Refused {aed(amount)}: the key is already revoked.")
        else:
            steps.append("Refused the request.")
        if "VIRTUAL_PATCH" not in codes and "KEY_REVOKED" not in codes and "BLOCKED_SOURCE" not in codes:
            v.incident = self._open_incident(c, v, "blocked")
            steps.append(f"Opened {v.incident}; paged on-call to confirm or release.")
        v.steps = steps
        return 403, {"error": "blocked by Night Watch", "incident": v.incident,
                     "reasons": [s.reason for s in v.signals[:3]]}

    def _contain(self, c: Ctx, v: Verdict) -> tuple[int, dict]:
        amount = self._amount(c)
        self.stats["held_aed"] += amount
        v.incident = self._open_incident(c, v, "held")
        self.held[v.incident] = (c, v)
        v.steps = [f"Held the request ({aed(amount)}) at the gateway; the bank has not seen it.",
                   f"Opened {v.incident}; asked on-call (and the customer) to approve or reject."]
        return 202, {"status": "held for review", "incident": v.incident}

    def _step_up(self, c: Ctx, v: Verdict, method, path, headers, body, now) -> tuple[int, dict]:
        """Risky login: let the bank check the password, but never hand the token to this client."""
        status, resp = self.bank.handle(method, path, headers, body, now)
        if status != 200:
            self.login_fail[c.ip].append((c.now, c.principal))
            v.steps = ["Risky login with a wrong password. Counted towards credential-stuffing detection."]
            return status, resp
        self.bank.revoke_token(resp.get("token", ""))
        v.incident = self._open_incident(c, v, "step_up")
        v.steps = ["The password was CORRECT, but from a device and network this customer never uses.",
                   "Withheld the session: the bank's token was destroyed before it reached the client.",
                   "Asked for step-up (OTP to the registered phone) and flagged the password as compromised.",
                   f"Opened {v.incident} for the analyst."]
        return 401, {"error": "step-up verification required", "incident": v.incident}

    def _after(self, c: Ctx, v: Verdict, status: int, resp: dict, before: int) -> int:
        if c.kind == "login" and status == 401:
            self.login_fail[c.ip].append((c.now, c.principal))
        if c.kind == "transfer" and status == 200 and c.principal:
            p = self.profiles.setdefault(c.principal, Profile(c.principal))
            iban = str(c.body.get("to_iban", "")).replace(" ", "").upper()
            self.recent[c.principal].append((c.now, iban, iban not in p.payees))
        if c.kind == "payout" and status == 200:
            self.partner_seen[c.principal].append(c.now)
        breaches = [self._check(e) for e in self.bank.journal[before:]]
        breaches = [b for b in breaches if b]
        if breaches:
            self._breach(c, v, breaches, resp)
            return 403
        if c.kind in ("transfer", "payout") and status >= 400:
            v.steps = [f"Below Night Watch's risk threshold, so it went to the bank, and the bank refused it "
                       f"itself: HTTP {status} {resp.get('error', '')}.",
                       "The bank's own controls held. Nothing to contain."]
            return status
        self.stats["allowed"] += 1
        if c.kind == "transfer" and status == 200 and c.principal:   # online learning
            p = self.profiles[c.principal]
            p.observe(c.now, self._amount(c), str(c.body.get("to_iban", "")).upper(), c.device, c.geo.get("country", ""))
        v.steps = ["Allowed. Matches what this customer normally does."] if not v.signals else \
            ["Allowed, below the risk threshold. Logged for the learning loop."]
        return status

    # ------------------------------------------------------------------ invariants: catching the bank's own bugs
    def _check(self, e) -> dict | None:
        acc = self.bank.accounts[e.from_account]
        problems = []
        if acc["owner"] != e.principal:
            problems.append(("OWNERSHIP", f"{e.principal} moved money out of account {e.from_account}, "
                             f"which belongs to {acc['owner']}."))
        if e.amount <= 0:
            problems.append(("POSITIVE_AMOUNT", f"Non-positive amount {e.amount} was booked."))
        if acc["balance"] < 0:
            problems.append(("NO_OVERDRAFT", f"Account {e.from_account} went negative ({acc['balance']})."))
        if self.bank.spent_today(e.from_account, e.ts) > acc["daily_limit"] + 0.01:
            problems.append(("DAILY_LIMIT", f"Account {e.from_account} went over its daily limit."))
        return {"entry": e, "problems": problems} if problems else None

    def _breach(self, c: Ctx, v: Verdict, breaches: list[dict], resp: dict) -> None:
        self.stats["breaches"] += 1
        steps, patch_ids, evidence = [], [], []
        for b in breaches:
            e = b["entry"]
            self.bank.reverse(e.id)
            self.stats["reversed_aed"] += e.amount
            steps.append(f"Ledger check failed on {e.id}: {b['problems'][0][1]} Reversed {aed(e.amount)} "
                         "before the response left the bank.")
            for code, why in b["problems"]:
                patch = self._learn_patch(c, e, code, v)
                if patch:
                    patch_ids.append(patch["id"])
                evidence.append({"invariant": code, "why": why, "journal": e.to_dict()})
        n = self.bank.revoke_customer_sessions(c.principal) if c.principal else 0
        v.action = Action.BLOCK
        v.signals.insert(0, Signal("LEDGER_INVARIANT", 100, "The bank's own code booked a payment that breaks a "
                                   "rule that must always hold: " + "; ".join(x["why"] for x in evidence)))
        v.score = 100
        v.incident = self._open_incident(c, v, "breach")
        inc = self.incidents[v.incident]
        inc["evidence"] = evidence
        inc["code_path"] = self._code_path(c.path)
        inc["regression_test"] = self._regression_test(v.incident, c, evidence)
        inc["devin_task"] = self._devin_task(v.incident, c, evidence, inc)
        inc["patches"] = patch_ids
        self._write_incident(inc)
        steps += [f"Signed out {n} session(s) of {c.principal}.",
                  f"Learned gateway rule {', '.join(patch_ids) or '(existing)'}: the same attack is refused from now on.",
                  f"Wrote a regression test from the real request and handed the root-cause fix to Devin ({v.incident})."]
        v.steps = steps
        v.breach = {"incident": v.incident, "invariants": [x["invariant"] for x in evidence],
                    "code_path": inc["code_path"]}
        resp.clear()
        resp.update({"error": "reversed by Night Watch", "incident": v.incident})
        v.status = 403

    def _learn_patch(self, c: Ctx, e, code: str, v: Verdict) -> dict | None:
        """Turn a broken invariant into a pre-check at the gateway, aimed at the request field that carried it."""
        if code == "OWNERSHIP":
            fld = next((k for k, val in c.body.items() if str(val) == e.from_account), None)
            if not fld:
                return None
            rule = {"route": c.path, "field": fld, "check": "owned_by_principal",
                    "rule": f"on {c.path}, '{fld}' must be an account owned by the logged-in customer"}
        elif code == "POSITIVE_AMOUNT":
            rule = {"route": c.path, "field": "amount", "check": "positive",
                    "rule": f"on {c.path}, 'amount' must be greater than zero"}
        elif code == "DAILY_LIMIT":
            rule = {"route": c.path, "field": "amount", "check": "within_daily_limit",
                    "rule": f"on {c.path}, payments must stay within the account's daily limit"}
        else:
            return None
        for p in self.memory.virtual_patches:
            if (p["route"], p["field"], p["check"]) == (rule["route"], rule["field"], rule["check"]):
                return p
        rule["id"] = f"VP-{len(self.memory.virtual_patches) + 1:03d}"
        rule["incident"] = f"INC-{len(self.incidents) + 1:04d}"
        self.memory.virtual_patches.append(rule)
        self.memory.lesson("virtual_patch", f"Learned {rule['id']}: {rule['rule']}.", c.now, incident=rule["incident"])
        self.memory.save()
        return rule

    def _patch_hits(self, p: dict, c: Ctx) -> bool:
        if c.path != p["route"] or p["field"] not in c.body and p["check"] == "owned_by_principal":
            return False
        if p["check"] == "owned_by_principal":
            acc = self.bank.accounts.get(str(c.body.get(p["field"])))
            return bool(c.principal) and (not acc or acc["owner"] != c.principal)
        if p["check"] == "positive":
            return self._amount(c) <= 0
        if p["check"] == "within_daily_limit":
            acc = self.bank.accounts.get(str(c.body.get("from_account", "")))
            return bool(acc) and self.bank.spent_today(acc["account_no"], c.now) + self._amount(c) > acc["daily_limit"]
        return False

    def _code_path(self, path: str) -> dict:
        fn = self.bank.routes.get(("POST", path)) or self.bank.routes.get(("GET", path))
        if not fn:
            return {}
        src = Path(inspect.getsourcefile(fn)).resolve()
        lines, start = inspect.getsourcelines(fn)
        try:
            rel = str(src.relative_to(ROOT))
        except ValueError:
            rel = str(src)
        return {"route": path, "file": rel, "function": fn.__name__, "line": start, "lines": len(lines)}

    # ------------------------------------------------------------------ incidents, tests and Devin
    def _open_incident(self, c: Ctx, v: Verdict, kind: str) -> str:
        iid = f"INC-{len(self.incidents) + 1:04d}"
        self.incidents[iid] = {"id": iid, "kind": kind, "opened": c.now.isoformat(timespec="seconds"),
                               "request": v.id, "principal": c.principal, "ip": c.ip, "device": c.device,
                               "path": c.path, "amount": self._amount(c),
                               "to_iban": str(c.body.get("to_iban", "")).replace(" ", "").upper(),
                               "signals": [s.code for s in v.signals], "status": "open"}
        if any(s.code == "FAN_OUT" for s in v.signals):
            p = self.profiles.get(c.principal)
            recent = {x[1] for x in self.recent[c.principal] if x[2] and c.now - x[0] <= timedelta(minutes=30)}
            self.incidents[iid]["related_ibans"] = sorted(recent | {self.incidents[iid]["to_iban"]})
        return iid

    def _regression_test(self, iid: str, c: Ctx, evidence: list[dict]) -> str:
        body = {k: v for k, v in c.body.items()}
        victim = evidence[0]["journal"]["from_account"]
        name = iid.lower().replace("-", "_")
        return f'''"""Regression test generated by Night Watch from {iid}.

It replays the real request that broke the "{evidence[0]['invariant']}" invariant on {c.path}.
It must fail on the vulnerable code and pass once the root cause is fixed. Do not weaken it.
"""
from datetime import datetime

from oasis.bank import Bank

NOW = datetime.fromisoformat("{c.now.isoformat()}")


def _login(bank, customer_id, device):
    pw = bank.customers[customer_id]["password_demo"]
    status, body = bank.handle("POST", "/bank/login", {{"x-device-id": device}},
                               {{"customer_id": customer_id, "password": pw}}, NOW)
    assert status == 200
    return body["token"]


def test_{name}_replayed_attack_is_refused():
    bank = Bank()
    token = _login(bank, "{c.principal}", "{c.device}")
    victim_before = bank.accounts["{victim}"]["balance"]
    status, _ = bank.handle("{c.method}", "{c.path}", {{"authorization": "Bearer " + token}},
                            {json.dumps(body)}, NOW)
    assert status in (401, 403, 404, 422), "the bank accepted the replayed attack"
    assert bank.accounts["{victim}"]["balance"] == victim_before
    assert all(bank.accounts[e.from_account]["owner"] == e.principal for e in bank.journal)


def test_{name}_legitimate_use_still_works():
    bank = Bank()
    token = _login(bank, "{c.principal}", "{c.device}")
    own = bank.customers["{c.principal}"]["accounts"][0]
    payee = next(a["iban"] for a in bank.accounts.values() if a["owner"] not in ("{c.principal}", "P001"))
    status, body = bank.handle("{c.method}", "{c.path}", {{"authorization": "Bearer " + token}},
                               {{**{json.dumps(body)}, "from_account": own, "to_iban": payee, "amount": 10}}, NOW)
    assert status == 200, body
'''

    def _devin_task(self, iid: str, c: Ctx, evidence: list[dict], inc: dict) -> str:
        cp = inc["code_path"]
        safe_body = json.dumps({k: v for k, v in c.body.items() if k != "password"})
        ev = "\n".join(f"- {x['invariant']}: {x['why']} (journal {x['journal']['id']}, "
                       f"{aed(x['journal']['amount'])}, route {x['journal']['route']})" for x in evidence)
        test_path = f"oasis/tests/test_{iid.lower().replace('-', '_')}.py"
        return f"""Night Watch incident {iid}: the Oasis Bank API booked a payment that breaks a ledger invariant.
Night Watch reversed the money and is blocking this exact request at the gateway (virtual patch),
but the root cause is in the bank's code and must be fixed there. This is a fictional hackathon bank.

Repository: {os.environ.get("NW_TARGET_REPO", "github.com/DaniyarUE/CIS-Hackathon")} (branch main). Oasis Bank lives in oasis/.

What happened (evidence only, Night Watch did not diagnose the bug):
- Authenticated principal: {c.principal} (customer), device {c.device}, IP {c.ip}
- Request: {c.method} {c.path}
- Body: {safe_body}
- Broken invariants:
{ev}
- The route is served by {cp.get('function')}() in {cp.get('file')} (line {cp.get('line')}).

Your job:
1. Reproduce: add the regression test below as {test_path} and run it. It must FAIL on current main.
2. Find the root cause in the bank code and fix it properly. Do not edit the test to make it pass,
   and do not rely on Night Watch (nightwatch/) to block it: the bank must be safe on its own.
3. Check every other endpoint in oasis/bank.py for the same class of bug and fix any you find,
   with a test for each.
4. Run: python3 -m pytest -q   (everything must pass)
5. Open a pull request titled "Fix {iid}: {evidence[0]['invariant'].lower()} violation on {c.path}".
   In the description explain the root cause in two sentences and list what you changed.

Regression test written by Night Watch from the real attack:

```python
{inc['regression_test']}```
"""

    def _write_incident(self, inc: dict) -> None:
        d = ROOT / "var" / "incidents" / inc["id"]
        d.mkdir(parents=True, exist_ok=True)
        (d / "devin_task.md").write_text(inc["devin_task"])
        (d / f"test_{inc['id'].lower().replace('-', '_')}.py").write_text(inc["regression_test"])
        (d / "incident.json").write_text(json.dumps({k: v for k, v in inc.items()
                                                     if k not in ("devin_task", "regression_test")}, indent=1, default=str))

    # ------------------------------------------------------------------ the human answers (and Night Watch learns)
    def respond(self, iid: str, confirmed: bool, now: datetime) -> list[str]:
        with self.lock:
            inc = self.incidents.get(iid)
            if not inc or inc["status"] != "open":
                return ["Nothing is waiting on that decision."]
            m, codes = self.memory, set(inc["signals"]) - {"LEDGER_INVARIANT", "VIRTUAL_PATCH"}
            held = self.held.pop(iid, None)
            if held:
                self.stats["held_aed"] -= inc["amount"]
            out = []
            if confirmed:
                inc["status"] = "confirmed"
                if held:
                    self.stats["protected_aed"] += inc["amount"]
                # Never block the victim's own IP or device: only infrastructure the customer never used.
                prof = self.profiles.get(inc["principal"])
                cands = [("blocked_ibans", inc["to_iban"])]
                if geo.lookup(inc["ip"])["reputation"] != "clean":
                    cands.append(("blocked_ips", inc["ip"]))
                if prof is None or inc["device"] not in prof.devices:
                    cands.append(("blocked_devices", inc["device"]))
                cands += [("blocked_ibans", i) for i in inc.get("related_ibans", [])]
                learned = [x for x in cands if x[1] and m.add_unique(*x)]
                m.nudge(codes, 1.15)
                text = (f"{iid} confirmed. Learned: " + ", ".join(f"{k.split('_')[1][:-1]} {v}" for k, v in learned)
                        + " now refused bank-wide; checks " + ", ".join(sorted(codes)) + " weigh 15% more.") if learned \
                    else f"{iid} confirmed; checks {', '.join(sorted(codes))} weigh 15% more."
                out.append(text)
            else:
                inc["status"] = "released"
                cid = inc["principal"]
                if inc["to_iban"]:
                    m.trusted_payees.setdefault(cid, [])
                    if inc["to_iban"] not in m.trusted_payees[cid]:
                        m.trusted_payees[cid].append(inc["to_iban"])
                    self.profiles.setdefault(cid, Profile(cid)).payees[inc["to_iban"]] += 1
                if inc["device"] and cid in self.profiles:
                    self.profiles[cid].devices[inc["device"]] += 1
                m.nudge(codes, 0.9)
                text = (f"{iid} released as a false positive. Learned: {cid} pays {inc['to_iban'] or 'this payee'} "
                        f"from {inc['device']}; checks {', '.join(sorted(codes))} weigh 10% less.")
                out.append(text)
                if held:
                    c, v = held
                    status, resp = self.bank.handle(c.method, c.path, c.headers, c.body, now)
                    out.append(f"Released the held request to the bank: {status} {resp.get('status') or resp.get('error')}.")
            m.lesson("analyst", text, now, incident=iid)
            m.save()
            self._push({"type": "lesson", "text": text})
            return out

    # ------------------------------------------------------------------ live feed
    def _publish(self, v: Verdict) -> None:
        d = v.to_dict()
        self.feed.append(d)
        self.feed = self.feed[-300:]
        self._push({"type": "verdict", "verdict": d})

    def _push(self, msg: dict) -> None:
        msg["snapshot"] = self.snapshot(light=True)
        for q in list(self.listeners):
            q.put(msg)

    def snapshot(self, light: bool = False) -> dict:
        accts = [{"owner": a["owner"], "name": self.bank.customers.get(a["owner"], {}).get("name",
                  self.bank.partners.get(a["owner"], {}).get("name", a["owner"])), "iban": a["iban"],
                  "balance": a["balance"], "type": a["type"]} for a in self.bank.accounts.values()]
        snap = {"stats": dict(self.stats), "accounts": accts,
                "memory": {"blocked_ips": self.memory.blocked_ips, "blocked_devices": self.memory.blocked_devices,
                           "blocked_ibans": self.memory.blocked_ibans, "virtual_patches": self.memory.virtual_patches,
                           "weight_mult": self.memory.weight_mult, "lessons": self.memory.lessons[-30:],
                           "trusted_payees": self.memory.trusted_payees},
                "incidents": [{k: v for k, v in i.items() if k not in ("regression_test", "devin_task")}
                              for i in self.incidents.values()]}
        if not light:
            snap["feed"] = self.feed[-100:]
            snap["profiles"] = {k: p.summary() for k, p in self.profiles.items()}
        return snap
