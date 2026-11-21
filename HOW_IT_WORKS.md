# How Night Watch works

This is the full logic, in plain words, with the reasoning behind each choice.

## 1. What is being protected, and why there is no "banking app"

The brief's scenario is a 2 AM drain where every *human* check passed. On the red track the user
is not the bank's customer, it is the bank's security team. So the product is the thing that sits
on the bank's rails (API, ledger, code), and the demo shows those rails under attack:

- **Oasis Bank** (`oasis/`) is a small, fictional core-banking API with 12 customers, IBANs,
  balances, daily limits and 1,920 statement lines over 90 days (`CUSTOMERS.md`).
- **Night Watch** sits in front of it as the gateway. Every request goes through it.
- **The console** is what the security team sees: every decision, why, what was done, what was learned.

## 2. One request, step by step

1. **Context.** Who is it (from the session token or API key), which device (`X-Device-Id`),
   which IP, which network and country (IP intelligence table), what time.
2. **Score.** Each detector adds points with a plain-English reason. The score is capped at 100.
3. **Decide.** Below 40: ALLOW. 40 to 69: CONTAIN. 70 or more: BLOCK.
   Why fixed thresholds: they are easy to explain and to audit; the *weights* are what learns.
4. **Act.**
   - ALLOW: the bank handles it, then the ledger is checked (step 5).
   - CONTAIN: a payment is held at the gateway (the bank never sees it) until an analyst
     answers. A login is passed to the bank to check the password, but the session token is
     destroyed before it reaches the client, and step-up is required.
   - BLOCK: HTTP 403. For a payment, every session of that customer is killed in the bank.
     For a partner, the API key is revoked inside the bank, so even a request that bypassed
     Night Watch would be refused.
5. **Reconcile.** After the bank answers, Night Watch checks every new journal entry against
   invariants that must always hold, whatever the code says:
   - **OWNERSHIP**: money only leaves an account owned by the authenticated customer or partner
   - **POSITIVE_AMOUNT**, **NO_OVERDRAFT**, **DAILY_LIMIT**

   If one breaks, the bank's own code has a bug. Night Watch reverses the entry before the
   response leaves, signs the attacker out, and starts the breach loop (section 4).

Decision time is about 0.1 ms per request (measured and shown on every decision).

## 3. The detectors

The profile behind each one is **learned from that customer's own history** (`nightwatch/baseline.py`):
median and 95th-percentile payment, known payees, hour-of-day histogram, devices, countries,
busiest day. It keeps learning: every payment that is allowed and completed is added.

| Code | Points | Fires when |
|---|---:|---|
| TOKEN_REPLAY | 45 | The session was opened on one device and is used from another (stolen token) |
| AMOUNT_EXTREME / AMOUNT_ANOMALY | 30 / 20 | Amount is 10x / 3x this customer's learned top (p95) payment |
| RISKY_NETWORK | 25 | Bulletproof hosting, Tor or rotating residential proxy |
| FAN_OUT | 30 | 3 or more brand-new payees within 30 minutes (mule spreading, kept under amount alarms) |
| DRAIN | 20 | One payment moves half or more of the balance |
| NEW_DEVICE / NEW_COUNTRY | 15 / 15 | Never seen for this customer |
| NEW_PAYEE_LARGE | 15 | A first payment to a new payee that is also unusually large (authorised-push-payment scams) |
| VELOCITY | 15 | More payments in minutes than this customer's busiest day |
| NEW_PAYEE | 10 | First payment ever to this IBAN (own accounts excluded) |
| OFF_HOURS | 10 | The customer has been active at this hour less than 1% of the time |
| CREDENTIAL_STUFFING | 70 | 5 failed logins, or 3 different customers failing, from one IP in 10 minutes |
| Partner: VALUE_SPIKE, CASH_OUT_RAIL, NEW_NETWORK, NEW_CORRIDOR | 25, 20, 15, 10 | Same idea for API keys |
| BLOCKED_SOURCE / BLOCKED_PAYEE | 60 | IP, device or IBAN that Night Watch learned is hostile |
| VIRTUAL_PATCH / KEY_REVOKED | 100 | A gateway rule learned from a breach / an already revoked key |

Why rules and not a black-box model: a bank has to explain every refusal to the customer and to
the regulator. Every point here has a sentence attached. The weights still adapt (section 4).

## 4. How it learns (three loops)

**From data.** Profiles are computed from 90 days of statements at start-up and updated after
every allowed payment. Nothing about a customer's normal behaviour is typed in by hand.

**From analysts.** Every CONTAIN or BLOCK opens an incident. The analyst answers:
- *Confirm*: the payee IBAN (and, for fan-out, every new payee in that burst), plus the IP if it is
  a risky network and the device if the customer never used it, go on bank-wide blocklists. The
  checks that fired weigh 15% more. It never blocks the victim's own home IP or device.
- *Release*: the payee becomes trusted for that customer, the device is added to the profile,
  the checks that fired weigh 10% less, and the held payment is sent to the bank.

Everything learned is saved in `var/memory.json` and survives restarts.

**From breaches.** When an invariant breaks (the v2 API attack):
1. The money is reversed in the same request.
2. A **virtual patch** is learned: Night Watch finds which request field carried the bad value
   (here `from_account`) and adds a gateway rule: on `/bank/v2/transfers`, `from_account` must be
   owned by the logged-in customer. The retry is blocked before the bank sees it.
3. A **regression test** is generated by replaying the exact attack. It fails on today's code.
4. A **Devin task** is written with evidence only: the request, the broken invariant, the journal
   entry and the function that served the route (found with `inspect`, so it is the real file and
   line). It does not say what the bug is. Devin must reproduce, find the root cause, fix it, check
   other endpoints for the same class of bug, and the PR only passes when the test passes.

That is the "learn and fix" loop: the gateway rule protects in milliseconds, Devin's fix removes
the cause, and the test stops it coming back.

## 5. The code guard (pull requests)

`nightwatch/astscan.py` parses the old and new version of every changed Python file and compares
them **function by function**: removed protective calls (check, verify, screen, audit, limit...),
removed ownership and limit comparisons, fewer `raise` statements, new branches keyed on a
hard-coded IBAN or user id, `skip_*=True` style switches, high-entropy secrets, network calls to
hosts outside the allowlist, `eval`/`pickle`/`shell=True`, and SQL built from strings. Comparisons
are fingerprinted by attribute names and operators, so renaming variables does not trigger it.

In GitHub Actions it annotates each line, posts the report on the PR, fails the check, and calls
Devin with the findings and the original functions. Devin posts a verdict on each finding and opens
a separate PR with tests that pin the protections the PR tried to remove. It never runs on Devin's
own branches, so it cannot loop.

## 6. Keeping the demo itself safe

- Binds to `127.0.0.1` by default. Console login uses PBKDF2, 5 failures lock the address for
  10 minutes, the cookie is HttpOnly + SameSite=Strict, every console action needs a CSRF token,
  and pages send a strict Content-Security-Policy and `X-Frame-Options: DENY`.
- The console escapes everything it shows (attackers control headers like the device id).
- Request bodies are capped at 16 KB. No secrets in the repo; the Devin key lives in `.env` or in
  a GitHub Actions secret. The attack lab never passes the Devin key to the attack scripts.
- Customer details are masked in the console by default.

## 7. Honest limits

- The bank, the customers and the IP intelligence are fictional and run in one process.
- Demo mode trusts `X-Forwarded-For` and `X-Demo-Time` from localhost only, so a 2 AM attack can be
  shown in the afternoon. Turn it off with `NW_DEMO=0`.
- The original v1 scripted scenarios (commit backdoor, config tamper, data exfiltration) are still
  available at `/replay`.
