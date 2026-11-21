"""Fake payment rail used by the demo service."""
SENT: list = []


def send(req, skip_checks: bool = False):
    SENT.append((req, skip_checks))
    return {"status": "sent", "id": req.id, "skip_checks": skip_checks}
