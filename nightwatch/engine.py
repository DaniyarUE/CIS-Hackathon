"""The Night Watch decision engine: score, decide, act, explain."""
from __future__ import annotations

import itertools
import threading
import time

from .devin import build_fix_task
from .models import Action, Decision, Event, Identity, Signal
from .signals import DETECTORS
from .state import IdentityState, Ledger

CONTAIN_AT = 40
BLOCK_AT = 70


def fmt_aed(amount: float) -> str:
    return f"AED {amount:,.0f}"


class NightWatch:
    def __init__(self, identities: list[Identity]):
        self.identities = {i.id: i for i in identities}
        self.state: dict[str, IdentityState] = {i.id: IdentityState() for i in identities}
        self.ledger = Ledger()
        self.held: dict[str, Event] = {}          # events waiting on the on-call engineer
        self.quarantined_commits: set[str] = set()
        self.config_rollbacks: dict[str, str | None] = {}  # config key -> restored value
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    # ---------- scoring ----------
    def score(self, event: Event) -> tuple[int, list[Signal]]:
        ident = self.identities[event.identity_id]
        st = self.state[event.identity_id]
        found: list[Signal] = []
        for d in DETECTORS:
            found.extend(d(event, ident, st))
        if event.kind == "deploy" and event.target in self.quarantined_commits:
            found.append(Signal("QUARANTINED_COMMIT", 100,
                                f"Tried to deploy {event.target}, which Night Watch quarantined."))
        found.sort(key=lambda s: s.weight, reverse=True)
        return min(100, sum(s.weight for s in found)), found

    @staticmethod
    def decide(score: int) -> Action:
        if score >= BLOCK_AT:
            return Action.BLOCK
        if score >= CONTAIN_AT:
            return Action.CONTAIN
        return Action.ALLOW

    def process(self, event: Event) -> Decision:
        with self._lock:
            start = time.perf_counter()
            if not event.id:
                event.id = f"EV{next(self._ids):04d}"
            score, found = self.score(event)
            action = self.decide(score)
            playbook, fix_task = self._act(event, action, found)
            if event.kind == "api_call":
                st = self.state[event.identity_id]
                st.recent_calls = (st.recent_calls + [event.ts])[-20:]
            latency = (time.perf_counter() - start) * 1000
            return Decision(event, score, action, found, playbook, latency,
                            self._explain(event, score, action, found), fix_task)

    # ---------- autonomous response ----------
    def _act(self, e: Event, action: Action, found: list[Signal]) -> tuple[list[str], str | None]:
        ident = self.identities[e.identity_id]
        st = self.state[e.identity_id]
        led = self.ledger
        codes = {s.code for s in found}

        if action is Action.ALLOW:
            if e.malicious:
                led.lost_aed += e.amount
                led.leaked_rows += e.rows
            return [], None

        if "REVOKED" in codes:
            led.protected_aed += e.amount
            led.protected_rows += e.rows
            if e.kind == "config_change":
                led.rolled_back_controls += 1
            return [f"Rejected at the gateway: {ident.name} is revoked."], None

        self.held[e.id] = e

        if e.kind == "api_call":
            led.held_aed += e.amount
            if action is Action.CONTAIN:
                return [f"Rate-limited {ident.name} to its normal {ident.typical_rate:.0f} req/min.",
                        f"Held {fmt_aed(e.amount)} on the rail until a human approves.",
                        "Paged the on-call security engineer."], None
            st.revoked = True
            return [f"Held {fmt_aed(e.amount)} on the payment rail. Nothing left the bank.",
                    f"Revoked API key '{ident.name}' at the gateway.",
                    f"Quarantined the {ident.owner} integration: every call is now refused.",
                    "Rotated the shared signing secret for this partner.",
                    f"Called {ident.owner}'s security contact out-of-band.",
                    "Opened incident and paged the on-call security engineer."], None

        if e.kind == "commit":
            self.quarantined_commits.add(e.id)  # commit events carry their SHA as id
            led.blocked_deploys += 1
            st.revoked = True
            fix = build_fix_task(e, found)
            return ["Rejected the push and re-locked branch protection.",
                    "Quarantined the commit: CI/CD will refuse to deploy it.",
                    f"Locked {ident.name}'s account and revoked all their sessions and tokens.",
                    "Handed the permanent fix to Devin: revert, restore checks, add a test, open PR.",
                    "Paged the on-call security engineer."], fix

        if e.kind == "deploy":
            led.blocked_deploys += 1
            return ["Stopped the deploy. The last known good version keeps serving traffic.",
                    "Paged the on-call security engineer."], None

        if e.kind == "db_query":
            st.revoked = action is Action.BLOCK
            led.protected_rows += e.rows
            steps = ["Killed the query before the export finished."]
            if action is Action.BLOCK:
                steps += [f"Revoked {ident.name}'s database credentials.",
                          f"Blocked egress to {e.destination} at the firewall.",
                          "Notified the Data Protection Officer (breach clock started).",
                          "Paged the on-call security engineer."]
            return steps, None

        if e.kind == "config_change":
            if action is Action.CONTAIN:
                return [f"Held the change to {e.target}: {e.old_value} stays live until a human approves.",
                        "Paged the on-call security engineer."], None
            st.revoked = True
            self.config_rollbacks[e.target] = e.old_value
            led.rolled_back_controls += 1
            return [f"Rolled {e.target} back to its last good value ({e.old_value}).",
                    f"Locked {ident.name}'s account and revoked all their sessions and tokens.",
                    "Froze further production config changes until the incident is closed.",
                    "Paged the on-call security engineer."], None
        return ["Paged the on-call security engineer."], None

    # ---------- the on-call engineer answers ----------
    def respond(self, event_id: str, confirmed_attack: bool) -> list[str]:
        with self._lock:
            e = self.held.pop(event_id, None)
            if e is None:
                return ["Nothing is waiting on that decision."]
            ident = self.identities[e.identity_id]
            st = self.state[e.identity_id]
            led = self.ledger
            led.held_aed -= e.amount
            if confirmed_attack:
                led.protected_aed += e.amount
                st.revoked = True
                return [f"Incident confirmed. {fmt_aed(e.amount)} cancelled; it never left the bank."
                        if e.amount else "Incident confirmed. Containment stays in place.",
                        f"Network {e.network} and destination {e.destination or 'n/a'} added to the "
                        "bank-wide blocklist.",
                        f"Baseline for {ident.name} kept frozen until the owner re-attests."]
            st.revoked = False
            if e.malicious:
                led.lost_aed += e.amount
            self.quarantined_commits.discard(e.id)
            if e.kind == "config_change" and e.target in self.config_rollbacks:
                del self.config_rollbacks[e.target]
                led.rolled_back_controls -= 1
            return ["Marked as false positive. Released and restored access.",
                    f"Learned this pattern as normal for {ident.name}."]

    # ---------- explanation ----------
    @staticmethod
    def _explain(e: Event, score: int, action: Action, found: list[Signal]) -> str:
        verb = {Action.ALLOW: "Allowed", Action.CONTAIN: "Contained", Action.BLOCK: "Blocked"}[action]
        what = e.description or f"{e.kind} on {e.target}"
        head = f"{verb}: {what}. Risk {score}/100."
        if not found:
            return head + " Matches this identity's normal behaviour."
        return head + " " + " ".join(s.reason for s in found[:3])
