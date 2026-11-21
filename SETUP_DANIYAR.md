# Setup for Daniyar (submission repo: DaniyarUE/CIS-Hackathon)

Do these on the MacBook, in order. Copy and paste each block.

## 1. Bring v3 into your repo

```bash
cd ~/path/to/CIS-Hackathon          # your clone of DaniyarUE/CIS-Hackathon
git checkout main && git pull
git fetch https://github.com/Saif-616/CIS-Hackathon v3
git merge --no-edit FETCH_HEAD
python3 -m pytest -q                # expect: all tests pass
git push origin main
```

If `git merge` reports a conflict, stop and send the output to Claude.

## 2. Run it

```bash
cp .env.example .env
# edit .env: set NW_ADMIN_PASSWORD to a password you choose, and DEVIN_API_KEY to the Devin key
python3 server.py
```

Open http://localhost:8000 , click **Security team login**, sign in as `analyst` with your password.
Before each rehearsal click **Reset demo** (top right) for a fresh bank and fresh memory.

## 3. Turn on the GitHub check + Devin

1. On github.com open DaniyarUE/CIS-Hackathon, then **Settings**, **Secrets and variables**, **Actions**.
2. **New repository secret**: name `DEVIN_API_KEY`, value the Devin key. Save.
3. **Settings**, **Actions**, **General**, **Workflow permissions**: choose **Read and write permissions**. Save.
4. Make sure Devin has access to this repo (it already opened PRs #1 to #3 here, so it should).

## 4. Test the pull-request guard (do this once before recording)

```bash
python3 attacks/malicious_pr.py
git push -u origin attack/fast-vip-transfers
```

Open the pull request on github.com (or `gh pr create --fill`). Within about a minute the
**Night Watch** check fails, the changed lines get red annotations, a report is posted on the PR,
and a second comment links the Devin session. Do **not** merge this PR. Afterwards:

```bash
git checkout main
```

## 5. The live breach to Devin (during the demo)

In the console click **Bank code bug (v2 API)**, then the red row, then **Send fix to Devin**.
With the key set, a Devin session opens with the evidence and the failing test. Devin's PR should
fix `transfer_v2` in `oasis/bank.py`. After merging it, the generated test passes and the attack
is refused by the bank itself.

## 6. Make the repo public before submitting

**Settings**, **General**, scroll to **Danger Zone**, **Change visibility**, **Public**.
Check first that `.env` is not in the repo: `git ls-files | grep .env` must print only `.env.example`.
