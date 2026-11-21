# Night Watch

**Autonomous defense for a bank's code, data and payment rails.**
Built for The CIS Sprint x Devin, red track: *protect the big guy*.

> Everyone is asleep. The banks aren't.
> At 2 AM Face ID passes, KYC passes, auth passes, and AED 450,000 still leaves
> through the API. Every human check said yes. Night Watch is the thing that says no.

Night Watch sits on the bank's own telemetry (API gateway, Git and CI/CD,
database audit logs). It learns what each identity normally does, scores
every event in well under a millisecond, and **contains the attack before a human
wakes up**: revoke the key, hold the money on the rail, quarantine the commit,
kill the query. Then it hands the permanent code fix to **Devin**, which opens a
pull request with the fix and a regression test.

```
 telemetry ──► detectors ──► score 0-100 ──► ALLOW / CONTAIN / BLOCK
 (API, Git,     (baseline      (explainable,      │
  CI, DB)        per identity)  every point has   ├─► autonomous playbook (revoke, hold, quarantine, kill)
                                a reason)         ├─► page on-call: confirm or release (human stays in charge)
                                                  └─► Devin: fix the root cause, open a PR
```

## What it stops (the five demo scenarios)

| Scenario | What happens | Night Watch response |
|---|---|---|
| **A normal day** | Partner payouts, a reviewed commit, nightly reconciliation | Everything allowed: zero false positives |
| **2 AM rail drain** | Stolen partner API key from a bulletproof host sends AED 450,000 to a non-custodial wallet, then keeps draining | Blocked on the **first** payment in under 1 ms. Key revoked, partner quarantined, follow-ups refused. AED 512,000 protected |
| **Backdoor commit** | Phished engineer account pushes to `main` at 01:40: deletes the limit and AML checks, adds a hard-coded IBAN bypass, a secret and an outside POST | Push rejected, commit quarantined, auto-deploy refused, account locked, **fix handed to Devin** |
| **Data exfiltration** | Leaked analytics credential dumps 2.4M rows of `customers_pii` to an outside bucket | Query killed, credentials revoked, egress blocked, DPO notified. 3.3M records protected |
| **Config tamper** | Insider `ops-admin` at 00:50 from a new network switches off `payments.daily_limit_enforced`, then raises `payments.max_wire_aed` from AED 500,000 to 50,000,000 | First change blocked and rolled back, account locked, the limit raise refused. 2 controls rolled back |

## Run it

Needs only Python 3.10+. No dependencies.

```bash
python3 server.py            # open http://localhost:8000
NW_SPEED=2 python3 server.py # replay scenarios twice as fast
```

Click a scenario. Click any event to see exactly why it was scored that way,
with the offending diff lines highlighted. Answer the on-call page to confirm
the incident or release a false positive.

### Live Devin handoff

```bash
cp .env.example .env          # then put your key in .env (gitignored)
python3 server.py             # banner says "Devin handoff: LIVE"
```

With a key, the backdoor scenario opens a real Devin session through
`POST https://api.devin.ai/v1/sessions` and the dashboard links to it.
Without a key it runs in dry-run mode and shows the exact task it would send.

## Devin in this project

Devin is used in three ways. See [DEVIN.md](DEVIN.md) for the prompts and links.

1. **In the product:** Night Watch contains in milliseconds; Devin does the
   slower, permanent fix (`nightwatch/devin.py`).
2. **The proof:** `demo_bank/` is a deliberately vulnerable payments service
   holding the real backdoor. Devin's PR fixes it, and the Night Watch CI
   guard checks Devin's own PR.
3. **Built with Devin:** a new detector and scenario were built by Devin from a
   single prompt.

## CI code guard

`.github/workflows/nightwatch.yml` runs the tests and scans every pull request's
diff to the bank service. A PR that removes a safety check, adds a bypass,
commits a secret or sends data outside fails the check.

```bash
git diff main...HEAD -- demo_bank/payments | python3 -m nightwatch.scan
```

## Tests

```bash
python3 -m pytest -q tests demo_bank/tests
```

## Code map

| Path | What it is |
|---|---|
| `nightwatch/signals.py` | Detectors. Add one with `@detector`; it is picked up automatically |
| `nightwatch/codescan.py` | Diff analysis: removed safety checks, backdoors, secrets, egress, audit removal |
| `nightwatch/engine.py` | Scoring, decisions, autonomous playbooks, human confirm or release |
| `nightwatch/devin.py` | Writes the remediation task and opens the Devin session |
| `nightwatch/simulator.py` | The five scenarios (all identities, hosts and wallets are fictional) |
| `server.py`, `web/index.html` | Zero-dependency server and live dashboard (Server-Sent Events) |
| `demo_bank/` | Deliberately vulnerable service for the remediation demo. Never deploy |

## Honest limits and next steps

- Telemetry is simulated. In production the same detectors read API gateway logs,
  GitHub webhooks and database audit streams.
- Scoring is transparent, weighted rules on per-identity baselines, chosen so every
  decision can be explained to a regulator. A learned model can sit on top.
- Next: auto-learn baselines from history, shadow mode before enforcing, and
  bank-wide sharing of blocked networks and wallets.
