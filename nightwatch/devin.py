"""Hand a code fix to Devin.

Night Watch contains an attack in milliseconds; the permanent fix (revert the
backdoor, restore the safety check, add a regression test) is a coding task.
Night Watch writes that task and, if DEVIN_API_KEY is set, opens a Devin session
for it. Without a key it runs in dry-run mode and just returns the task.
"""
from __future__ import annotations

import json
import os
import urllib.request

from .models import Event, Signal

DEVIN_API = os.environ.get("DEVIN_API_URL", "https://api.devin.ai/v1/sessions")


def build_fix_task(event: Event, signals: list[Signal]) -> str:
    findings = "\n".join(f"- {s.code}: {s.reason}" + (f"\n    line: {s.evidence}" if s.evidence else "")
                         for s in signals if s.evidence or s.code in {"UNREVIEWED_PUSH"})
    return (
        f"Night Watch blocked commit {event.id} to {event.target} by {event.identity_id}.\n"
        f"Findings:\n{findings}\n\n"
        "Please:\n"
        "1. Revert the malicious change and restore every removed safety check and audit log.\n"
        "2. Rotate and remove any secret that was committed.\n"
        "3. Add a regression test that fails if this check is removed again.\n"
        "4. Open a pull request that needs two human approvals before merge."
    )


def send_to_devin(task: str, timeout: float = 10) -> dict:
    key = os.environ.get("DEVIN_API_KEY")
    if not key:
        return {"status": "dry_run", "task": task}
    req = urllib.request.Request(
        DEVIN_API, method="POST",
        data=json.dumps({"prompt": task, "title": "Night Watch: remediate blocked commit",
                         "tags": ["night-watch", "security"]}).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read() or b"{}")
        return {"status": "sent", "session": body.get("url"), "session_id": body.get("session_id"),
                "task": task}
    except Exception as exc:  # the demo must never crash on a network error
        return {"status": "error", "error": str(exc), "task": task}
