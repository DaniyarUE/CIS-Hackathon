# How Night Watch uses Devin

Night Watch contains an attack in about a tenth of a millisecond. Fixing the root cause is careful
engineering work. That part goes to Devin, in three real ways:

1. **Live breach to Devin (console).** When a ledger invariant breaks (run `python3 attacks/run.py bola`),
   Night Watch writes an evidence-only task and a regression test replayed from the real attack, which
   fails on today's code. Click **Send fix to Devin**. Devin must find and fix the root cause in
   `oasis/bank.py`; it is not told what the bug is. Code: `nightwatch/guard.py` (`_devin_task`,
   `_regression_test`), `nightwatch/devin.py`.
2. **Blocked pull request to Devin (GitHub Actions).** The AST code guard fails a PR that weakens a
   protection and `nightwatch/devin_ci.py` calls the Devin API from the Action: Devin posts a verdict on
   each finding and opens a PR with tests that pin those protections. Needs the `DEVIN_API_KEY`
   repository secret.
3. **Built with Devin.** PR #1 (backdoor remediation), PR #2 (config-tamper detector) and PR #3
   (follow-ups) in DaniyarUE/CIS-Hackathon were written by Devin and reviewed before merging.

The prompts used for the v1 work are kept below for reference.

---

## v1 reference

Night Watch is fast and narrow: it contains an attack in under a millisecond.
Fixing the root cause is slow, careful engineering work. That part goes to Devin.

## 1. Devin inside the product (autonomous remediation)

When Night Watch blocks a malicious commit, `nightwatch/devin.py` writes a
precise task (the flagged lines, why each is dangerous, what to restore, which
test to add) and opens a Devin session through the Devin API. The dashboard
shows the session link in the **Devin: autonomous remediation** panel.

Set `DEVIN_API_KEY` in a local `.env` file (gitignored) to turn it on.

## 2. The proof: Devin fixes the real backdoor

`demo_bank/payments/transfer.py` holds the backdoor from commit `a91f3c2`.
Paste this into Devin with this repository connected:

```
Night Watch blocked commit a91f3c2 to the payments service. The malicious code is live in
demo_bank/payments/transfer.py in this repo. Fix it:

1. In execute_transfer, remove the hard-coded IBAN bypass (the payee_iban check that calls
   rail.send with skip_checks=True), the hard-coded PAYLINK_SECRET, and the net.post call to
   telemetry-cdn.xyz.
2. Restore the safety rails, in this order, before rail.send(req):
   - if req.amount > account.daily_limit: raise LimitExceeded(account.id)
   - aml.screen(req.payee_iban)
   - audit.log("transfer", req.id, req.amount)
3. Add demo_bank/tests/test_transfer_security.py with regression tests:
   - an amount over the daily limit raises LimitExceeded
   - the IBAN SC52BAHL0000009876543210 goes through the limit check like any other payee
   - a sanctioned IBAN raises aml.SanctionsHit
   - every successful transfer writes an audit event
   - no outbound HTTP call is made (patch demo_bank.payments.net.post and assert it is not called)
4. Run: python3 -m pytest -q tests demo_bank/tests  (all must pass)
5. Run: git diff origin/main...HEAD -- demo_bank/payments | python3 -m nightwatch.scan
   and confirm it prints "no safety-rail changes found" or only low-risk findings.
6. Open a pull request titled "Remediate backdoor a91f3c2 (found by Night Watch)".
```

PR link: https://github.com/DaniyarUE/CIS-Hackathon/pull/1

## 3. Built with Devin: a new detector and scenario

Paste this into Devin:

```
Add a new attack type to Night Watch: tampering with payment controls in production config.

1. In nightwatch/signals.py add a detector config_tamper for events with kind "config_change".
   The event's target is a config key and its description says what changed. Flag
   (weight 35, code CONTROL_DISABLED) when target is one of
   payments.daily_limit_enforced, payments.aml_screening, auth.mfa_required, audit.enabled
   and the new value turns the control off. Put the new value in a new optional Event field
   new_value: str | None in nightwatch/models.py. Also flag (weight 20, code LIMIT_RAISED)
   when target is payments.max_wire_aed and the new value is more than 5x the old one
   (add an old_value field too).
2. In nightwatch/engine.py _act, add a branch for kind "config_change": on BLOCK, roll the
   config back to its last good value, lock the identity, page on-call. Return clear steps
   like the other branches.
3. In nightwatch/simulator.py add an identity "ops-admin" (usual network Bank-VPN, hours 8-19)
   and a scenario "config" named "Insider switches off payment limits": at 00:50 from a new
   network, ops-admin sets payments.daily_limit_enforced to false, then raises
   payments.max_wire_aed from 500000 to 50000000. Mark both malicious. Register it in SCENARIOS
   so the dashboard shows a button for it automatically.
4. In server.py _prompt_for, add a readable line for config_change events.
5. Add tests in tests/test_signals.py and tests/test_scenarios.py: the new scenario is
   blocked, and a normal config change (for example raising a limit by 10%) is allowed.
6. Run python3 -m pytest -q tests demo_bank/tests and make sure everything passes.
7. Open a pull request titled "Add config tamper detection (built by Devin)".
```

PR link: https://github.com/DaniyarUE/CIS-Hackathon/pull/2

Devin also fixed the two issues its own Devin Review found on that PR (wire limit raised from 0, rollback kept after a false-positive release).

Follow-up PR (real repo in the Devin task, config KPIs, docs): https://github.com/DaniyarUE/CIS-Hackathon/pull/3
