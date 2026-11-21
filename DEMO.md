# 5-minute live demo (no Q&A)

Before going on stage: `python3 server.py`, sign in to the console, click **Reset demo**, full screen.
Have two GitHub tabs open: **PR #6** (Devin's fix, merged) and **PR #7** (the blocked attack PR).

**0:00 to 0:30, the hook (landing page).** "2 AM. Face ID passed, KYC passed, auth passed. And AED
450,000 just left the bank through the API. Every check looked at the human. Nobody was watching the
rails. That's Night Watch." Click **Open the console**.

**0:30 to 0:50, a normal day.** Attack lab, **A normal day**. "This is a real bank API with real
customers' history. Four normal payments: all green. A defense that cries wolf gets switched off."

**0:50 to 1:40, the 2 AM attacks.** Click **2 AM stolen session**. Point at the Why panel:
"Her session was opened at home at 19:30. At 02:14 the token is used from an offshore server.
Blocked in a tenth of a millisecond: stolen token, new device, 11 times her normal top payment,
learned from her own 90 days of statements. The bot retries: the bank itself says 401, because the
session is dead." Click **Stolen partner key**: "AED 450,000 to a crypto wallet: blocked on payment one,
key revoked inside the bank, AED 512,000 protected."

**1:40 to 2:30, it learns.** Click **Mule fan-out**. "Small payments to new payees, under every
amount alarm. Third one: fan-out pattern, held." Click the yellow row, **Confirm attack**. "It just
learned all five mule accounts." Click **Mule, second victim**: "Another customer pays one of them:
blocked on the first payment. Nobody wrote that rule."

**2:30 to 3:45, the bank's own bug, and Devin.** "Now the hard one. Behaviour checks can't see it: a
real customer, his own phone, his normal hours. He puts someone else's account number into the bank's
new v2 API." Click **Bank code bug (v2 API)**: the bank answers "not your account". "An hour ago this
worked. The bank's code accepted it. Night Watch checks the ledger after every request, saw money leave
an account the caller doesn't own, reversed it before the response left the bank, learned a gateway
rule, wrote a failing regression test from the real attack, and sent Devin the evidence. Not the answer."
Switch to the **PR #6** tab: "Devin found the root cause by itself, fixed it in the endpoint and in the
bank's core so no future endpoint can repeat it, added tests, and the check went green. We merged it.
That's what you just saw: the bank now refuses it on its own." Optional: show `oasis/tests/test_inc_0014.py`
in the PR, the test Night Watch wrote.

**3:45 to 4:30, code.** Switch to the **PR #7** tab: "Same idea for code. A pull request sneaks in a
VIP bypass, a secret and a removed limit check. Our code guard reads the code's structure, function by
function. Check failed, every line annotated, and the GitHub Action handed it to Devin itself."

**4:30 to 5:00, close.** Point at **What Night Watch learned**. "Learns from data, from analysts and from
breaches. Every decision explained. Enforced inside the bank. A human always in charge. And Devin does
the engineering. Night Watch: the bank's rails, protected while everyone sleeps."

Tip: record the video with Cap. If something fails live, the same attacks run from a terminal:
`python3 attacks/run.py hijack`.
