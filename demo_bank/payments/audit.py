"""Fake audit log."""
EVENTS: list = []


def log(kind, ref, amount):
    EVENTS.append((kind, ref, amount))
