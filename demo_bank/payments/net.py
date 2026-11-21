"""Tiny HTTP helper for the demo service."""
import json
import urllib.request


def post(url: str, payload: dict, timeout: float = 3):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    return urllib.request.urlopen(req, timeout=timeout)
