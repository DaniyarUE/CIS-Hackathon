"""Night Watch demo server. Standard library only: `python3 server.py` and open http://localhost:8000"""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from nightwatch import Action, NightWatch
from nightwatch.devin import send_to_devin
from nightwatch.engine import fmt_aed
from nightwatch.simulator import SCENARIOS, demo_identities

WEB = Path(__file__).parent / "web"


def _load_dotenv(path: Path = Path(__file__).parent / ".env") -> None:
    """Read KEY=VALUE lines from a local, gitignored .env file (no dependency needed)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            if v.strip():
                os.environ.setdefault(k.strip(), v.strip())


_load_dotenv()
SPEED = float(os.environ.get("NW_SPEED", "1.0"))  # >1 plays scenarios faster

_engine = NightWatch(demo_identities())
_engine_lock = threading.Lock()


def _prompt_for(decision, engine: NightWatch) -> dict | None:
    """The page the on-call engineer gets. Night Watch has already acted; this is the human check."""
    e = decision.event
    codes = {s.code for s in decision.signals}
    if e.id not in engine.held or codes & {"REVOKED", "QUARANTINED_COMMIT"}:
        return None
    ident = engine.identities[e.identity_id]
    what = {
        "api_call": f"{fmt_aed(e.amount)} via {ident.name} from {e.network}",
        "commit": f"commit {e.id} to {e.target} by {ident.name}",
        "db_query": f"{e.rows:,} rows from {e.target} to {e.destination}",
    }.get(e.kind, e.description)
    return {
        "event_id": e.id,
        "title": "Night Watch contained an attack",
        "body": f"{what}. Already contained in {decision.latency_ms:.1f} ms. Confirm or release.",
        "yes": "Confirm incident", "no": "False positive, release",
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep the console quiet during demos
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            return self._send(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8")
        if url.path == "/api/scenarios":
            return self._json([{"id": k, "name": v[0]} for k, v in SCENARIOS.items()])
        if url.path == "/api/run":
            return self._run(parse_qs(url.query).get("scenario", ["drain"])[0])
        self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if urlparse(self.path).path != "/api/respond":
            return self._send(404, b"not found", "text/plain")
        length = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(length) or b"{}")
        with _engine_lock:
            steps = _engine.respond(str(data.get("event_id")), bool(data.get("confirmed")))
            totals = _engine.ledger.__dict__.copy()
        self._json({"steps": steps, "totals": totals})

    def _sse(self, name: str, payload) -> None:
        self.wfile.write(f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode())
        self.wfile.flush()

    def _run(self, scenario_id: str) -> None:
        global _engine
        if scenario_id not in SCENARIOS:
            return self._json({"error": "unknown scenario"}, 400)
        name, build = SCENARIOS[scenario_id]
        events = build()
        with _engine_lock:
            _engine = NightWatch(demo_identities())
            engine = _engine
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        at_risk = {
            "aed": sum(e.amount for _, e in events if e.malicious),
            "rows": sum(e.rows for _, e in events if e.malicious),
            "deploys": sum(1 for _, e in events if e.malicious and e.kind in ("commit", "deploy")),
        }
        try:
            self._sse("start", {"scenario": name, "at_risk": at_risk})
            for delay, event in events:
                time.sleep(delay / SPEED)
                decision = engine.process(event)
                self._sse("decision", {
                    "decision": decision.to_dict(),
                    "totals": engine.ledger.__dict__.copy(),
                    "prompt": _prompt_for(decision, engine)
                    if decision.action is not Action.ALLOW else None,
                })
                if decision.fix_task:
                    self._sse("devin", send_to_devin(decision.fix_task))
            self._sse("done", {"totals": engine.ledger.__dict__.copy()})
        except (BrokenPipeError, ConnectionResetError):
            pass


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    mode = "LIVE (sessions will be created)" if os.environ.get("DEVIN_API_KEY") else "dry run"
    print(f"Night Watch running on http://localhost:{port}  |  Devin handoff: {mode}")
    server.serve_forever()


if __name__ == "__main__":
    main()
