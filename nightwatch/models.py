"""Core data types for Night Watch (red track: protect the bank's code, data and rails)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Action(str, Enum):
    ALLOW = "ALLOW"
    CONTAIN = "CONTAIN"   # slow it down / hold it, page a human to approve
    BLOCK = "BLOCK"       # kill it now: revoke, quarantine, roll back


@dataclass
class Identity:
    """A machine or human identity that touches the bank's systems, with its learned baseline."""

    id: str
    name: str
    kind: str                         # "partner_api_key" | "service_account" | "engineer"
    owner: str
    scopes: set[str]
    usual_networks: set[str]          # ASNs / networks it normally comes from
    active_hours: tuple[int, int]     # (start, end) local hours of normal activity
    typical_rate: float = 10          # requests per minute
    typical_value: float = 0          # typical payment value it initiates, AED
    typical_rows: int = 0             # typical rows read per query
    usual_destinations: set[str] = field(default_factory=set)  # egress targets / payee countries


@dataclass
class Event:
    """One piece of telemetry: an API call, a commit, a deploy, a database query."""

    ts: datetime
    identity_id: str
    kind: str                         # "api_call" | "commit" | "deploy" | "db_query" | "config_change"
    target: str = ""                  # endpoint, repo/branch, service or table
    network: str | None = None
    scope_used: str | None = None
    amount: float = 0.0               # payment value for rail calls, AED
    destination: str | None = None    # payee country / egress host
    destination_type: str | None = None
    rate: float = 0.0                 # requests/min observed in this burst
    rows: int = 0
    diff: str = ""                    # unified diff for commits
    reviewed: bool | None = None      # did a second engineer approve it?
    old_value: str | None = None      # config value before a config_change
    new_value: str | None = None      # config value after a config_change
    description: str = ""
    id: str = ""
    # Ground truth used only by the simulator to show "what would have been lost".
    # Detectors must never read this.
    malicious: bool = False


@dataclass
class Signal:
    code: str
    weight: int
    reason: str
    evidence: str = ""


@dataclass
class Decision:
    event: Event
    score: int
    action: Action
    signals: list[Signal]
    playbook: list[str]
    latency_ms: float
    explanation: str
    fix_task: str | None = None       # task handed to Devin when code must change

    def to_dict(self) -> dict:
        e = self.event
        return {
            "event_id": e.id,
            "ts": e.ts.isoformat(),
            "kind": e.kind,
            "identity": e.identity_id,
            "target": e.target,
            "amount": e.amount,
            "rows": e.rows,
            "destination": e.destination,
            "description": e.description,
            "score": self.score,
            "action": self.action.value,
            "signals": [s.__dict__ for s in self.signals],
            "playbook": self.playbook,
            "latency_ms": round(self.latency_ms, 2),
            "explanation": self.explanation,
            "fix_task": self.fix_task,
            "diff": e.diff,
            "network": e.network,
            "old_value": e.old_value,
            "new_value": e.new_value,
        }
