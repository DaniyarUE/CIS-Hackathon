"""Short-term memory Night Watch keeps for each identity."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class IdentityState:
    recent_calls: list[datetime] = field(default_factory=list)
    value_last_hour: float = 0.0
    revoked: bool = False
    quarantined: bool = False


@dataclass
class Ledger:
    """Money and records Night Watch kept safe, held, or let through."""

    protected_aed: float = 0.0
    held_aed: float = 0.0
    lost_aed: float = 0.0
    protected_rows: int = 0
    leaked_rows: int = 0
    blocked_deploys: int = 0
    rolled_back_controls: int = 0
