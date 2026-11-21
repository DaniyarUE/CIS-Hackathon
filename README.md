# Night Watch

**Autonomous defense for a bank's code, data and payment rails.**
Built for The CIS Sprint x Devin, red track: *protect the big guy*.

> Everyone is asleep. The banks aren't.
> At 2 AM Face ID passes, KYC passes, auth passes, and AED 450,000 still leaves
> through the API. Every human check said yes. Night Watch is the thing that says no.

Night Watch sits in front of a bank's API as its gateway, reads the bank's ledger, and guards
its Git and CI. It learns what every customer and partner normally does from their own history,
decides on every request in about a tenth of a millisecond, enforces the decision inside the bank
(the key is revoked, the session is dead, the money does not move), and learns from every
incident. When the bank's own code was the hole, it hands **Devin** the evidence and a failing
regression test, and Devin opens the pull request with the real fix.

The bank in this repo, **Oasis Bank**, is fictional. The defense is real: you attack it with real
HTTP requests and watch it hold.

## Run it

Python 3.10+, no dependencies.

```bash
python3 server.py              # prints the console login; open http://localhost:8000
python3 attacks/run.py list    # in a second terminal
python3 attacks/run.py hijack  # a real attack against the running bank
```

Put `NW_ADMIN_PASSWORD=...` and (optionally) `DEVIN_API_KEY=...` in a local `.env` (gitignored).
Without a Devin key the hand-off runs in dry-run mode and shows the exact task it would send.

## What you can attack

| Attack (`attacks/run.py`) | What it does | What Night Watch does |
|---|---|---|
| `normal` | 4 customers pay their usual payees | Allows all of them. Zero false positives |
| `hijack` | Malware steals a retiree's session; 02:14 it is used from an offshore server to send AED 39,500 | Blocks in ~0.1 ms (token replay, new device, risky network, 11x her normal top payment), kills every session; the retry gets 401 from the bank itself |
| `takeover` | Phished password used at 02:10 from an offshore server | The password is right, so Night Watch lets the bank check it, then destroys the token before it reaches the attacker and demands step-up |
| `stuffing` | Leaked password list tried against many customers from a proxy | After 3 customers fail from one IP, the IP is blocked bank-wide and remembered |
| `mule` | Malware on a customer's own laptop sends AED 4,800 to five brand-new payees | The third payment trips *fan-out* and is held; confirming teaches Night Watch all five mule accounts |
| `mule-followup` | Another customer is tricked into paying one of those mules | Blocked on the first payment, because Night Watch learned the mule |
| `bola` | A customer abuses the new v2 transfer API to pay himself out of someone else's account. Every behaviour check is normal | The bank's code accepts it. Night Watch's ledger check catches the broken ownership invariant, reverses the money before the response leaves, learns a gateway rule that blocks the retry, writes a failing regression test, and hands Devin the root-cause fix |
| `partner` | The original 2 AM case: stolen partner API key, AED 450,000 to a crypto wallet | Blocked on payment one; the key is revoked inside the bank; follow-ups refused |
| `attacks/malicious_pr.py` | A pull request that slips a VIP bypass, a secret and a removed limit check into the bank | The GitHub check fails with line annotations and hands the PR to Devin |

## How it works

See [HOW_IT_WORKS.md](HOW_IT_WORKS.md) for the full logic, every detector and weight, the three
learning loops, the invariants, and how Devin is used. Short version:

```
request ─► context (who, device, IP, country, time)
        ─► score vs. profile learned from this customer's 90-day history + what it has learned
        ─► ALLOW ─► bank ─► ledger invariants hold? ─► yes: learn from it
        │                                          └─► no: BREACH ─► reverse money, learn gateway rule,
        │                                                            write failing test, hand to Devin
        ├► CONTAIN ─► held (or step-up for logins), analyst confirms or releases ─► learns either way
        └► BLOCK ─► 403, session / key revoked inside the bank, incident opened
```

## Devin in this project

1. **Live breaches:** the console sends an evidence-only task plus a failing regression test to Devin
   through the Devin API (`nightwatch/guard.py`, `nightwatch/devin.py`).
2. **Blocked pull requests:** the GitHub Action calls Devin itself when the code guard blocks a PR
   (`nightwatch/devin_ci.py`, `.github/workflows/nightwatch.yml`).
3. **Built with Devin:** the original backdoor fix and the config-tamper detector are Devin PRs (#1 to #3).

## Tests

```bash
python3 -m pytest -q
```

## Code map

| Path | What it is |
|---|---|
| `oasis/bank.py` | Oasis Bank's API: login, accounts, statements, transfers (v1 and v2), partner payouts, journal |
| `oasis/data/generate.py` | Generates the 12 fictional customers and 90 days of statements (`CUSTOMERS.md` is the readable copy) |
| `nightwatch/guard.py` | The live gateway: scoring, enforcement, invariants, virtual patches, incidents, Devin tasks, learning |
| `nightwatch/baseline.py` | Profiles learned from history and updated online |
| `nightwatch/memory.py` | What Night Watch learned, persisted to `var/memory.json` |
| `nightwatch/astscan.py`, `scan.py` | The AST code guard and its CI entry point |
| `nightwatch/devin.py`, `devin_ci.py` | Devin API hand-off from the console and from CI |
| `attacks/` | Real attack scripts and the malicious pull request |
| `server.py`, `web/` | Landing page, analyst login, live console; `/replay` keeps the original scripted scenarios |
| `nightwatch/engine.py`, `simulator.py`, `demo_bank/` | The original v1 engine and scenarios (commit backdoor, config tamper, data exfiltration) |

## Honest limits

- The bank and the IP intelligence table are fictional and in-process; in production Night Watch would be a
  reverse proxy in front of the core banking API and would read a real threat feed.
- Profiles are statistical (medians, percentiles, frequencies), not a neural model, on purpose:
  every decision must be explainable to a regulator.
- Demo mode lets scripts on the same machine set their apparent IP (`X-Forwarded-For`) and clock
  (`X-Demo-Time`) so a 2 AM attack can be shown at 4:30 PM. Only honoured from localhost; `NW_DEMO=0` turns it off.
