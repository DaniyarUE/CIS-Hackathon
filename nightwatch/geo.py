"""Tiny IP intelligence table for the demo (all ranges are reserved documentation/test ranges)."""
from __future__ import annotations

import ipaddress

# network, label, country, reputation
_TABLE = [
    ("198.51.100.0/24", "AS-DU-HOME (UAE residential)", "AE", "clean"),
    ("100.64.10.0/24", "AS-PAYLINK-DXB", "AE", "clean"),
    ("203.0.113.0/25", "AS-BULLETPROOF-HOST (offshore VPS)", "SC", "bulletproof"),
    ("203.0.113.128/25", "AS-RESI-PROXY (rotating proxies)", "RU", "proxy"),
    ("192.0.2.0/24", "Tor exit node", "??", "tor"),
    ("127.0.0.0/8", "localhost", "AE", "clean"),
]
_NETS = [(ipaddress.ip_network(n), label, cc, rep) for n, label, cc, rep in _TABLE]


def lookup(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"network": "unknown", "country": "??", "reputation": "unknown"}
    for net, label, cc, rep in _NETS:
        if addr in net:
            return {"network": label, "country": cc, "reputation": rep}
    return {"network": "unknown", "country": "??", "reputation": "unknown"}
