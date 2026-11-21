# demo_bank: a deliberately vulnerable payments service

**Not real code. Do not deploy.** This folder is the target for the
"Backdoor commit to payments" scenario. `payments/transfer.py` contains the
exact backdoor from commit `a91f3c2` that Night Watch blocks in the demo:

- the daily limit check and AML screening were deleted,
- a hard-coded payee IBAN skips every check,
- a partner secret is hard-coded,
- request data is sent to an outside host,
- the audit log line is gone.

Night Watch's response hands Devin a task to fix it. Devin's pull request
restores the checks and adds a regression test so the backdoor can't come back.
