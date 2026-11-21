# 5-minute demo script (live, no Q&A)

Start the server first: `python3 server.py`, open http://localhost:8000, full screen.

**0:00 to 0:30, the hook.** "2 AM. Face ID passed, KYC passed, auth passed. And AED 450,000 just
left the bank through the API. Every check said yes, because every check looks at the human.
Nobody was watching the rails. That's Night Watch."

**0:30 to 1:00, a normal day.** Click *A normal day*. "Partner payouts, a reviewed deploy, nightly
jobs. All green. A defense that cries wolf gets switched off, so zero false positives matters."

**1:00 to 2:00, the 2 AM drain.** Click *2 AM rail drain*. Point at the first red card.
"First payment, blocked in under a millisecond. Not after the account is empty: on payment one."
Read two reasons from the right panel (180x normal value, non-custodial wallet, bulletproof host).
"It revoked the key, quarantined the partner, held the money on the rail. Watch the bot keep
trying." The follow-ups bounce. Click **Confirm incident**. "AED 512,000 protected. The human
confirms. They don't have to be awake for it to work."

**2:00 to 3:30, the backdoor and Devin.** Click *Backdoor commit to payments*. "Now the scarier one:
a phished engineer pushes to main at 01:40." Scroll to the diff: "Night Watch reads the code. It
caught the deleted limit check, the hard-coded IBAN that skips every check, a secret, and data going
to an outside server. Push rejected, and when CI tries to auto-deploy it, refused."
Point at the Devin panel: "Containing is fast. Fixing is engineering. So Night Watch writes the fix
task and hands it to Devin." Switch to the Devin session or PR tab: "Here is Devin's pull request.
Checks restored, backdoor removed, regression tests added, and our own Night Watch CI guard passed
on Devin's PR."

**3:30 to 4:15, data.** Click *Customer data exfiltration*. "2.4 million customer records heading to
an outside bucket. Query killed, credentials revoked, egress blocked, DPO notified."

**4:15 to 5:00, close.** "Zero dependencies, runs anywhere, every decision explained line by line,
a human always in charge. And Devin didn't just fix the backdoor: it built the config-tamper
detector you saw too. Night Watch: the bank's rails, protected while everyone sleeps."

Tip: record the video with Cap (a sponsor). Use `NW_SPEED=1.5` if you're short on time.
