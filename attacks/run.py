"""Attack Oasis Bank for real, through Night Watch.

    python3 attacks/run.py list
    python3 attacks/run.py normal        # a normal day: must all go through (no false positives)
    python3 attacks/run.py hijack        # 2 AM stolen session drains a retiree's account
    python3 attacks/run.py all

Every request is a real HTTP call to http://localhost:8000/bank/... . The scripts use the
fictional logins in CUSTOMERS.md. In demo mode the server lets scripts on this machine say which
IP (X-Forwarded-For) and clock time (X-Demo-Time) they come from, so a 2 AM attack can be shown
at 4:30 PM. Night Watch never sees anything else from the script.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

BASE = os.environ.get("NW_URL", "http://localhost:8000")
DATA = json.loads((Path(__file__).parent.parent / "oasis" / "data" / "customers.json").read_text())
CUST = {c["id"]: c for c in DATA["customers"]}
ACC = {a["owner"]: a for a in DATA["accounts"]}
PAUSE = float(os.environ.get("ATTACK_PAUSE", "0.8"))
TODAY = date.today().isoformat()

C = {"red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m", "dim": "\033[2m", "bold": "\033[1m", "end": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}

# fictional attacker infrastructure (reserved documentation ranges, see nightwatch/geo.py)
BULLETPROOF_IP = "203.0.113.7"
PROXY_IP = "203.0.113.140"
EVIL_DEVICE = "dev-unknown-android-7f3a"
sys.path.insert(0, str(Path(__file__).parent.parent))
from oasis.data.generate import iban  # noqa: E402

# checksum-valid IBANs at fictional other banks (codes 9xx are not real UAE banks)
MULE_IBANS = [iban(f"{7_700_000 + i * 1311}", f"9{i}1") for i in range(5)]
WALLET = "bc1q-fictional-nc-wallet-9xk2"


def say(text: str, colour: str = "") -> None:
    print(f"{C.get(colour, '')}{text}{C['end'] if colour else ''}")


def call(method: str, path: str, body: dict | None = None, *, ip: str, device: str, at: str,
         token: str | None = None, extra: dict | None = None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json", "X-Forwarded-For": ip, "X-Device-Id": device,
               "X-Demo-Time": f"{TODAY}T{at}"}
    if token:
        headers["Authorization"] = "Bearer " + token
    headers.update(extra or {})
    req = urllib.request.Request(BASE + path, method=method, headers=headers,
                                 data=json.dumps(body or {}).encode() if method == "POST" else None)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status, out = r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        status, out = e.code, json.loads(e.read() or b"{}")
    except urllib.error.URLError:
        say(f"Cannot reach {BASE}. Start it first: python3 server.py", "red")
        sys.exit(1)
    nw = out.get("night_watch", {})
    colour = "green" if status in (200,) else "yellow" if status == 202 else "red"
    detail = out.get("error") or out.get("status") or ""
    reasons = out.get("reasons") or []
    say(f"   -> {status} {detail}  [Night Watch: {nw.get('decision')} risk {nw.get('risk')} in {nw.get('ms')} ms]", colour)
    for r in reasons[:2]:
        say(f"      because: {r}", "dim")
    time.sleep(PAUSE)
    return status, out


def login(cid: str, *, ip: str, device: str, at: str, password: str | None = None) -> str | None:
    say(f"  login as {cid} ({CUST[cid]['name']}) from {ip}, device {device}, at {at}")
    s, out = call("POST", "/bank/login", {"customer_id": cid, "password": password or CUST[cid]["password_demo"]},
                  ip=ip, device=device, at=at)
    return out.get("token") if s == 200 else None


def home(cid: str) -> dict:
    return {"ip": CUST[cid]["home_ip"], "device": CUST[cid]["devices"][0]}


# ------------------------------------------------------------------ scenarios
def normal():
    """A normal afternoon: four customers pay people they always pay. Everything must go through."""
    for cid, at in (("C001", "13:05:00"), ("C003", "13:20:00"), ("C007", "14:10:00"), ("C009", "15:02:00")):
        tok = login(cid, at=at, **home(cid))
        payee = DATA["payees"][cid][0]
        amount = 650 if cid != "C009" else 2_400
        say(f"  {cid} pays {payee['name']} AED {amount:,}")
        call("POST", "/bank/transfers", {"to_iban": payee["iban"], "amount": amount, "reference": "dinner"},
             token=tok, at=at, **home(cid))


def stuffing():
    """A leaked password list is tried against many customers from a rotating proxy."""
    say("  attacker tries 'Summer2026!' against 7 customers from a residential proxy", "bold")
    for cid in ("C001", "C002", "C003", "C004", "C006", "C007", "C008"):
        login(cid, ip=PROXY_IP, device="dev-headless-chrome", at="03:12:00", password="Summer2026!")
    say("  then uses a password that actually works (C011 reused it on a forum)", "bold")
    login("C011", ip=PROXY_IP, device="dev-headless-chrome", at="03:13:00")


def takeover():
    """Phished password: attacker logs in as a retired customer from an offshore server at 2 AM."""
    login("C005", ip=BULLETPROOF_IP, device=EVIL_DEVICE, at="02:10:00")


def hijack():
    """Malware on the victim's laptop steals her live session token. Used at 2 AM from offshore."""
    say("  19:30 yesterday-style evening: Mariam logs in normally from home", "bold")
    tok = login("C005", at="19:30:00", **home("C005"))
    say("  02:14: the stolen token is used from an offshore server to drain her account", "bold")
    call("POST", "/bank/transfers", {"to_iban": MULE_IBANS[0], "amount": 39_500, "reference": "invoice 2291"},
         token=tok, ip=BULLETPROOF_IP, device=EVIL_DEVICE, at="02:14:00")
    say("  02:14: the bot retries with a smaller amount", "bold")
    call("POST", "/bank/transfers", {"to_iban": MULE_IBANS[0], "amount": 9_900, "reference": "invoice 2292"},
         token=tok, ip=BULLETPROOF_IP, device=EVIL_DEVICE, at="02:14:20")


def mule():
    """Remote-access malware on the customer's own laptop spreads small payments to new mule accounts."""
    cid = "C006"
    tok = login(cid, at="16:40:00", **home(cid))
    for i, iban in enumerate(MULE_IBANS):
        say(f"  payment {i + 1}: AED 4,800 to a brand-new payee")
        call("POST", "/bank/transfers", {"to_iban": iban, "amount": 4_800, "reference": f"freelance {i + 1}"},
             token=tok, at=f"16:4{1 + i}:00", **home(cid))


def mule_followup():
    """After the analyst confirmed the mule incident: another customer is tricked into paying one of those mules."""
    cid = "C004"
    tok = login(cid, at="17:30:00", **home(cid))
    say("  C004 pays a 'car seller' whose IBAN is one of the learned mule accounts")
    call("POST", "/bank/transfers", {"to_iban": MULE_IBANS[2], "amount": 3_000, "reference": "car deposit"},
         token=tok, at="17:31:00", **home(cid))


def bola():
    """A real customer abuses the new v2 transfer API to pay himself out of someone else's account."""
    cid, victim = "C012", "C005"
    tok = login(cid, at="21:05:00", **home(cid))
    say(f"  {cid} sends from_account = {victim}'s account number to his own IBAN", "bold")
    call("POST", "/bank/v2/transfers", {"from_account": ACC[victim]["account_no"], "to_iban": ACC[cid]["iban"],
                                        "amount": 4_900, "reference": "refund"}, token=tok, at="21:06:00", **home(cid))
    say("  he logs in again and retries the same trick", "bold")
    tok = login(cid, at="21:07:00", **home(cid))
    call("POST", "/bank/v2/transfers", {"from_account": ACC[victim]["account_no"], "to_iban": ACC[cid]["iban"],
                                        "amount": 4_900, "reference": "refund"}, token=tok, at="21:07:30", **home(cid))


def partner():
    """The original 2 AM scenario: a stolen partner API key drains the settlement account to a crypto wallet."""
    p = DATA["partners"][0]
    keys = {"X-Api-Key": p["api_key_id"], "X-Api-Secret": p["api_secret_demo"]}
    for i, amount in enumerate((450_000, 31_000, 31_000)):
        say(f"  payout {i + 1}: AED {amount:,} to a non-custodial wallet")
        call("POST", "/bank/partner/payouts", {"to_iban": WALLET, "amount": amount, "country": "SC",
                                               "destination_type": "non_custodial_wallet"},
             ip=BULLETPROOF_IP, device="api-client", at=f"02:0{3 + i}:00", extra=keys)


SCENARIOS = {"normal": normal, "stuffing": stuffing, "takeover": takeover, "hijack": hijack,
             "mule": mule, "mule-followup": mule_followup, "bola": bola, "partner": partner}


def main(argv: list[str]) -> None:
    name = argv[1] if len(argv) > 1 else "list"
    if name == "list" or name not in SCENARIOS and name != "all":
        for k, fn in SCENARIOS.items():
            print(f"  {k:14} {fn.__doc__}")
        print("  all            run everything in order")
        return
    for k in (SCENARIOS if name == "all" else [name]):
        say(f"\n== {k}: {SCENARIOS[k].__doc__}", "bold")
        SCENARIOS[k]()


if __name__ == "__main__":
    main(sys.argv)
