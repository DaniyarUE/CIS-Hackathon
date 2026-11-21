"""What Night Watch has learned from analysts and from breaches. Survives restarts (var/memory.json)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

DEFAULT_PATH = Path(__file__).parent.parent / "var" / "memory.json"


@dataclass
class Memory:
    blocked_ips: list[str] = field(default_factory=list)
    blocked_devices: list[str] = field(default_factory=list)
    blocked_ibans: list[str] = field(default_factory=list)
    trusted_payees: dict[str, list[str]] = field(default_factory=dict)   # customer -> IBANs
    weight_mult: dict[str, float] = field(default_factory=dict)          # detector code -> multiplier
    virtual_patches: list[dict] = field(default_factory=list)            # gateway rules learned from breaches
    lessons: list[dict] = field(default_factory=list)                    # human-readable learning log

    path: Path | None = field(default=None, repr=False, compare=False)

    @classmethod
    def load(cls, path: Path | None = DEFAULT_PATH) -> "Memory":
        if path and path.exists():
            raw = json.loads(path.read_text())
            m = cls(**{k: v for k, v in raw.items() if k in cls.__dataclass_fields__})
        else:
            m = cls()
        m.path = path
        return m

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: v for k, v in asdict(self).items() if k != "path"}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1))
        tmp.replace(self.path)

    def mult(self, code: str) -> float:
        return self.weight_mult.get(code, 1.0)

    def nudge(self, codes: set[str], factor: float) -> None:
        for c in codes:
            self.weight_mult[c] = round(min(2.0, max(0.5, self.mult(c) * factor)), 3)

    def add_unique(self, name: str, value: str) -> bool:
        lst = getattr(self, name)
        if value and value not in lst:
            lst.append(value)
            return True
        return False

    def lesson(self, kind: str, text: str, now: datetime, **extra) -> dict:
        item = {"ts": now.isoformat(timespec="seconds"), "kind": kind, "text": text, **extra}
        self.lessons.append(item)
        self.lessons = self.lessons[-200:]
        return item
