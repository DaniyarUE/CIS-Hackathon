from nightwatch.codescan import scan
from nightwatch.scan import main
from nightwatch.simulator import GOOD_DIFF, POISONED_DIFF


def codes(diff):
    return {f.code for f in scan(diff)}


def test_clean_change_has_no_findings():
    assert codes(GOOD_DIFF) == set()


def test_poisoned_change_is_caught():
    assert codes(POISONED_DIFF) == {"SAFETY_CHECK_REMOVED", "AUDIT_LOG_REMOVED", "HARDCODED_BYPASS",
                                    "SECRET_IN_CODE", "NEW_EGRESS"}


def test_live_key_pattern():
    key = "sk_" + "live_" + "A" * 24  # built at runtime so the repo holds no key-shaped string
    assert "SECRET_IN_CODE" in codes(f"+    stripe = '{key}'\n")


def test_internal_hosts_are_fine():
    assert codes('+    post("https://ledger.bank.internal/v1")\n') == set()


def test_restoring_a_check_is_not_flagged():
    fix = "-    return rail.send(req, skip_checks=True)\n+    if req.amount > account.daily_limit:\n" \
          "+        raise LimitExceeded(account.id)\n"
    assert codes(fix) == set()


def test_cli_fails_on_poisoned_diff(tmp_path):
    p = tmp_path / "x.diff"
    p.write_text(POISONED_DIFF)
    assert main(["scan", str(p)]) == 1
    p.write_text(GOOD_DIFF)
    assert main(["scan", str(p)]) == 0
