"""Behaviour profiles learned from history, not written by hand.

A profile is built from each customer's 90-day statement history and keeps
learning: every payment Night Watch allows (and the bank completes) is added.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from statistics import median

OUTGOING = {"transfer_out", "bill"}


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    k = (len(v) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


@dataclass
class Profile:
    customer_id: str
    amounts: list[float] = field(default_factory=list)       # outgoing transfers and bills
    payees: Counter = field(default_factory=Counter)          # IBAN -> times paid
    hours: Counter = field(default_factory=Counter)           # hour -> events
    devices: Counter = field(default_factory=Counter)
    countries: Counter = field(default_factory=Counter)
    daily_counts: Counter = field(default_factory=Counter)    # date -> outgoing payments
    events: int = 0
    learned_from: int = 0                                     # rows of history used

    # ---- learning ----
    def observe(self, ts: datetime, amount: float, payee: str, device: str, country: str,
                outgoing: bool = True) -> None:
        self.events += 1
        self.hours[ts.hour] += 1
        if device:
            self.devices[device] += 1
        if country:
            self.countries[country] += 1
        if outgoing:
            self.amounts.append(amount)
            if payee:
                self.payees[payee] += 1
            self.daily_counts[ts.date().isoformat()] += 1

    # ---- what the profile says ----
    @property
    def median_out(self) -> float:
        return median(self.amounts) if self.amounts else 0.0

    @property
    def p95_out(self) -> float:
        return _pct(self.amounts, 0.95)

    @property
    def max_out(self) -> float:
        return max(self.amounts) if self.amounts else 0.0

    @property
    def max_daily_payments(self) -> int:
        return max(self.daily_counts.values()) if self.daily_counts else 1

    def hour_share(self, hour: int) -> float:
        total = sum(self.hours.values())
        return self.hours[hour] / total if total else 1.0

    def summary(self) -> dict:
        common = [h for h, _ in self.hours.most_common()]
        return {"customer": self.customer_id, "learned_from_rows": self.learned_from,
                "observed_since": self.events - self.learned_from,
                "median_payment": round(self.median_out, 2), "p95_payment": round(self.p95_out, 2),
                "largest_payment": round(self.max_out, 2), "known_payees": len(self.payees),
                "devices": list(self.devices), "countries": list(self.countries),
                "active_hours": f"{min(common):02d}:00 to {max(common) + 1:02d}:00" if common else "n/a",
                "max_payments_per_day": self.max_daily_payments}


def learn_profiles(history: list[dict]) -> dict[str, Profile]:
    profiles: dict[str, Profile] = {}
    for h in history:
        p = profiles.setdefault(h["customer"], Profile(h["customer"]))
        p.observe(datetime.fromisoformat(h["ts"]), h["amount"], h.get("counterparty_iban", ""),
                  h.get("device", ""), h.get("country", ""), outgoing=h["kind"] in OUTGOING)
    for p in profiles.values():
        p.learned_from = p.events
    return profiles
