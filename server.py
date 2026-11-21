"""Night Watch server. Standard library only.

    python3 server.py        # then open http://localhost:8000

It serves four things:
  /            landing page (the pitch)
  /login       security-team login (PBKDF2 hashes, rate limited, HttpOnly SameSite=Strict cookie)
  /console     the live Night Watch console (auth required)
  /bank/...    Oasis Bank's API, with Night Watch in front of it as the gateway
  /replay      the original scripted scenarios (commit backdoor, config tamper, data exfil)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).parent
WEB = ROOT / "web"


def _load_dotenv(path: Path = ROOT / ".env") -> None:
    """Read KEY=VALUE lines from a local, gitignored .env file (no dependency needed)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            if v.strip():
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()

from nightwatch import Action, NightWatch  # noqa: E402  (env must be loaded first)
from nightwatch.devin import send_to_devin  # noqa: E402
from nightwatch.engine import fmt_aed  # noqa: E402
from nightwatch.guard import Guard  # noqa: E402
from nightwatch.memory import Memory  # noqa: E402
from nightwatch.simulator import SCENARIOS, demo_identities  # noqa: E402
from oasis.bank import Bank  # noqa: E402

SPEED = float(os.environ.get("NW_SPEED", "1.0"))
# Demo mode lets the attack scripts on THIS machine say which IP and time they pretend to come from.
# It is only honoured for requests from localhost. Set NW_DEMO=0 to turn it off.
DEMO = os.environ.get("NW_DEMO", "1") == "1"
MAX_BODY = 16 * 1024
ATTACKS = {"normal", "stuffing", "takeover", "hijack", "mule", "mule-followup", "bola", "partner"}

# ---------------------------------------------------------------- the live system
_live_lock = threading.Lock()
_bank = Bank()
_guard = Guard(_bank)
_devin_sessions: dict[str, dict] = {}


def reset_live(clear_memory: bool) -> None:
    global _bank, _guard
    with _live_lock:
        listeners = _guard.listeners
        mem = Memory.load()
        if clear_memory:
            mem = Memory(path=mem.path)
            mem.save()
        _bank = Bank()
        _guard = Guard(_bank, mem)
        _guard.listeners = listeners
        _devin_sessions.clear()
        _guard._push({"type": "reset"})


# ---------------------------------------------------------------- security-team auth
def _pw(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)


ANALYST = os.environ.get("NW_ADMIN_USER", "analyst")
_generated = not os.environ.get("NW_ADMIN_PASSWORD")
_ADMIN_PW = os.environ.get("NW_ADMIN_PASSWORD") or secrets.token_urlsafe(9)
_SALT = secrets.token_bytes(16)
_HASH = _pw(_ADMIN_PW, _SALT)
_sessions: dict[str, dict] = {}                 # cookie -> {user, csrf, expires}
_fails: dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
SESSION_TTL = 8 * 3600


def _login_locked(ip: str) -> bool:
    recent = [t for t in _fails[ip] if time.time() - t < 600]
    return len(recent) >= 5


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                                "font-src https://fonts.gstatic.com; img-src 'self' data:; "
                                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "NightWatch"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    # ---------- helpers ----------
    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        headers = {"Cache-Control": "no-store", **SECURITY_HEADERS, **(extra or {})}
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200, extra: dict | None = None) -> None:
        self._send(code, json.dumps(obj, default=str).encode(), "application/json", extra)

    def _page(self, name: str) -> None:
        self._send(200, (WEB / name).read_bytes(), "text/html; charset=utf-8")

    def _redirect(self, to: str) -> None:
        self.send_response(303)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _loopback(self) -> bool:
        return self.client_address[0] in ("127.0.0.1", "::1")

    def _client_ip(self) -> str:
        fwd = self.headers.get("X-Forwarded-For")
        if DEMO and fwd and self._loopback():
            return fwd.split(",")[0].strip()
        return self.client_address[0]

    def _now(self) -> datetime:
        t = self.headers.get("X-Demo-Time")
        if DEMO and t and self._loopback():
            try:
                return datetime.fromisoformat(t)
            except ValueError:
                pass
        return datetime.now()

    def _body(self) -> dict | None:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return None
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def _session(self) -> dict | None:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "nw_session":
                s = _sessions.get(v)
                if s and s["expires"] > time.time():
                    return s
        return None

    def _authed_api(self, write: bool = False) -> dict | None:
        s = self._session()
        if not s:
            self._json({"error": "login required"}, 401)
            return None
        if write and not hmac.compare_digest(self.headers.get("X-CSRF", ""), s["csrf"]):
            self._json({"error": "bad CSRF token"}, 403)
            return None
        return s

    # ---------- GET ----------
    def do_GET(self):
        url = urlparse(self.path)
        p = url.path
        if p in ("/", "/index.html"):
            return self._page("landing.html")
        if p == "/login":
            return self._page("login.html")
        if p == "/console":
            return self._page("console.html") if self._session() else self._redirect("/login")
        if p == "/replay":
            return self._page("replay.html") if self._session() else self._redirect("/login")
        if p in ("/static/nw.css", "/static/favicon.svg", "/favicon.ico"):
            f = WEB / ("favicon.svg" if p == "/favicon.ico" else p.split("/")[-1])
            return self._send(200, f.read_bytes(), "text/css; charset=utf-8" if f.suffix == ".css" else "image/svg+xml",
                              {"Cache-Control": "public, max-age=300"})
        if p.startswith("/bank/"):
            body = {k: v[0] for k, v in parse_qs(url.query).items()}
            return self._bank("GET", body)
        if p == "/api/me":
            s = self._session()
            return self._json({"user": s["user"], "csrf": s["csrf"]} if s else {"user": None},
                              200 if s else 401)
        if p.startswith("/api/") and not self._authed_api():
            return
        if p == "/api/live/snapshot":
            with _live_lock:
                snap = _guard.snapshot()
            snap["devin"] = _devin_sessions
            snap["devin_live"] = bool(os.environ.get("DEVIN_API_KEY"))
            return self._json(snap)
        if p == "/api/live/incident":
            iid = parse_qs(url.query).get("id", [""])[0]
            inc = _guard.incidents.get(iid)
            return self._json(inc or {"error": "unknown incident"}, 200 if inc else 404)
        if p == "/api/live/stream":
            return self._stream()
        if p == "/api/scenarios":
            return self._json([{"id": k, "name": v[0]} for k, v in SCENARIOS.items()])
        if p == "/api/run":
            return self._run(parse_qs(url.query).get("scenario", ["drain"])[0])
        self._send(404, b"not found", "text/plain")

    # ---------- POST ----------
    def do_POST(self):
        p = urlparse(self.path).path
        body = self._body()
        if body is None:
            return self._json({"error": "body must be a JSON object under 16 KB"}, 400)
        if p.startswith("/bank/"):
            return self._bank("POST", body)
        if p == "/auth/login":
            return self._auth_login(body)
        if p == "/auth/logout":
            s = self._session()
            if s:
                _sessions.pop(s["id"], None)
            return self._json({"ok": True}, extra={"Set-Cookie": "nw_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        if p == "/api/respond":  # original replay dashboard
            if not self._authed_api():
                return
            with _replay_lock:
                steps = _replay["engine"].respond(str(body.get("event_id")), bool(body.get("confirmed")))
                totals = _replay["engine"].ledger.__dict__.copy()
            return self._json({"steps": steps, "totals": totals})
        if not p.startswith("/api/live/") or not self._authed_api(write=True):
            return None if p.startswith("/api/live/") else self._send(404, b"not found", "text/plain")
        if p == "/api/live/respond":
            steps = _guard.respond(str(body.get("incident")), bool(body.get("confirmed")), datetime.now())
            return self._json({"steps": steps})
        if p == "/api/live/devin":
            iid = str(body.get("incident"))
            inc = _guard.incidents.get(iid)
            if not inc or not inc.get("devin_task"):
                return self._json({"error": "no Devin task for that incident"}, 404)
            if iid in _devin_sessions and _devin_sessions[iid].get("status") == "sent":
                return self._json(_devin_sessions[iid])
            res = send_to_devin(inc["devin_task"], title=f"Night Watch {iid}: fix root cause")
            _devin_sessions[iid] = {k: v for k, v in res.items() if k != "task"}
            _guard._push({"type": "devin", "incident": iid, "result": _devin_sessions[iid]})
            return self._json(_devin_sessions[iid])
        if p == "/api/live/attack":
            return self._attack(str(body.get("name", "")))
        if p == "/api/live/reset":
            reset_live(bool(body.get("clear_memory")))
            return self._json({"ok": True})
        self._send(404, b"not found", "text/plain")

    # ---------- attack lab: runs the real attack scripts against this server ----------
    def _attack(self, name: str) -> None:
        import subprocess
        import sys
        if name not in ATTACKS:
            return self._json({"error": "unknown attack"}, 400)
        env = {**os.environ, "NW_URL": f"http://127.0.0.1:{self.server.server_address[1]}", "ATTACK_PAUSE": "0.6",
               "PYTHONUNBUFFERED": "1"}
        env.pop("DEVIN_API_KEY", None)
        proc = subprocess.Popen([sys.executable, str(ROOT / "attacks" / "run.py"), name], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, env=env)
        self._sse_headers()
        try:
            for line in proc.stdout:
                self._sse("line", {"text": line.rstrip()})
            proc.wait(timeout=60)
            self._sse("done", {"code": proc.returncode})
        except (BrokenPipeError, ConnectionResetError, OSError):
            proc.kill()

    # ---------- the bank, behind Night Watch ----------
    def _bank(self, method: str, body: dict) -> None:
        headers = {k: v for k, v in self.headers.items()}
        status, resp, verdict = _guard.handle(method, self.path, headers, body, self._client_ip(), self._now())
        resp = dict(resp)
        resp["night_watch"] = {"decision": verdict.action.value, "risk": verdict.score,
                               "request": verdict.id, "ms": round(verdict.latency_ms, 2)}
        self._json(resp, status)

    def _auth_login(self, body: dict) -> None:
        ip = self.client_address[0]
        if _login_locked(ip):
            return self._json({"error": "Too many attempts. Locked for 10 minutes."}, 429)
        user, pw = str(body.get("username", "")), str(body.get("password", ""))
        ok = hmac.compare_digest(user, ANALYST) & hmac.compare_digest(_pw(pw, _SALT), _HASH)
        if not ok:
            _fails[ip].append(time.time())
            time.sleep(0.4)
            return self._json({"error": "Wrong username or password."}, 401)
        sid = secrets.token_urlsafe(32)
        _sessions[sid] = {"id": sid, "user": user, "csrf": secrets.token_urlsafe(24),
                          "expires": time.time() + SESSION_TTL}
        cookie = f"nw_session={sid}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict"
        self._json({"ok": True}, extra={"Set-Cookie": cookie})

    # ---------- server-sent events ----------
    def _sse_headers(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def _sse(self, name: str, payload) -> None:
        self.wfile.write(f"event: {name}\ndata: {json.dumps(payload, default=str)}\n\n".encode())
        self.wfile.flush()

    def _stream(self) -> None:
        q: queue.Queue = queue.Queue()
        _guard.listeners.append(q)
        self._sse_headers()
        try:
            self._sse("hello", {"ok": True})
            while True:
                try:
                    msg = q.get(timeout=15)
                    self._sse(msg.get("type", "msg"), msg)
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            for g in (_guard,):
                if q in g.listeners:
                    g.listeners.remove(q)

    # ---------- original scripted replays ----------
    def _run(self, scenario_id: str) -> None:
        if scenario_id not in SCENARIOS:
            return self._json({"error": "unknown scenario"}, 400)
        name, build = SCENARIOS[scenario_id]
        events = build()
        with _replay_lock:
            _replay["engine"] = engine = NightWatch(demo_identities())
        self._sse_headers()
        at_risk = {
            "aed": sum(e.amount for _, e in events if e.malicious),
            "rows": sum(e.rows for _, e in events if e.malicious),
            "deploys": sum(1 for _, e in events if e.malicious and e.kind in ("commit", "deploy")),
            "controls": sum(1 for _, e in events if e.malicious and e.kind == "config_change"),
        }
        try:
            self._sse("start", {"scenario": name, "at_risk": at_risk})
            for delay, event in events:
                time.sleep(delay / SPEED)
                decision = engine.process(event)
                self._sse("decision", {
                    "decision": decision.to_dict(),
                    "totals": engine.ledger.__dict__.copy(),
                    "prompt": _prompt_for(decision, engine) if decision.action is not Action.ALLOW else None,
                })
                if decision.fix_task:
                    self._sse("devin", send_to_devin(decision.fix_task))
            self._sse("done", {"totals": engine.ledger.__dict__.copy()})
        except (BrokenPipeError, ConnectionResetError):
            pass


_replay_lock = threading.Lock()
_replay = {"engine": NightWatch(demo_identities())}


def _prompt_for(decision, engine: NightWatch) -> dict | None:
    e = decision.event
    codes = {s.code for s in decision.signals}
    if e.id not in engine.held or codes & {"REVOKED", "QUARANTINED_COMMIT"}:
        return None
    ident = engine.identities[e.identity_id]
    what = {
        "api_call": f"{fmt_aed(e.amount)} via {ident.name} from {e.network}",
        "commit": f"commit {e.id} to {e.target} by {ident.name}",
        "db_query": f"{e.rows:,} rows from {e.target} to {e.destination}",
        "config_change": f"{ident.name} changed {e.target} from {e.old_value} to {e.new_value} "
                         f"in production from {e.network}",
    }.get(e.kind, e.description)
    return {"event_id": e.id, "title": "Night Watch contained an attack",
            "body": f"{what}. Already contained in {decision.latency_ms:.1f} ms. Confirm or release.",
            "yes": "Confirm incident", "no": "False positive, release"}


def main() -> None:
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    mode = "LIVE" if os.environ.get("DEVIN_API_KEY") else "dry run (set DEVIN_API_KEY in .env)"
    print(f"Night Watch on http://localhost:{port}   Devin handoff: {mode}")
    print(f"Console login: {ANALYST} / " + (_ADMIN_PW + "   (random for this run; set NW_ADMIN_PASSWORD in .env)"
                                             if _generated else "(password from NW_ADMIN_PASSWORD)"))
    if host != "127.0.0.1":
        print("WARNING: listening beyond localhost. Demo mode trusts X-Forwarded-For only from localhost.")
    server.serve_forever()


if __name__ == "__main__":
    main()
