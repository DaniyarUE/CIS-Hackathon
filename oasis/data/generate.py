"""Generate Oasis Bank's fictional customers and 90 days of statement history.

Everything here is made up: names, IBANs (bank code 999 is not a real UAE bank),
devices and IP addresses (documentation ranges). The output is deterministic
(fixed seed) so tests and demos always see the same data.

    python3 -m oasis.data.generate      # writes customers.json and CUSTOMERS.md
"""
from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).parent
SEED = 2026
TODAY = datetime(2026, 11, 21, 9, 0)
DAYS = 90
BANK_CODE = "999"  # fictional

# name, city, employer/role, monthly salary AED, opening balance AED, daily limit AED, hours (start, end)
PEOPLE = [
    ("Layla Haddad", "Dubai", "Product designer", 28_000, 184_250, 50_000, (8, 23)),
    ("Omar Al Nuaimi", "Abu Dhabi", "Civil engineer", 34_000, 412_900, 75_000, (6, 22)),
    ("Priya Raman", "Dubai", "Pharmacist", 19_500, 63_120, 25_000, (7, 22)),
    ("Daniel Okafor", "Sharjah", "Logistics manager", 23_000, 97_480, 30_000, (7, 23)),
    ("Mariam Saeed", "Dubai", "Retired teacher", 12_000, 1_240_000, 40_000, (8, 20)),
    ("Arjun Mehta", "Dubai", "Software engineer", 41_000, 236_700, 60_000, (9, 24)),
    ("Sofia Petrova", "Abu Dhabi", "Hotel manager", 26_000, 151_330, 40_000, (7, 23)),
    ("Yousef Karim", "Ajman", "Shop owner", 18_000, 58_900, 35_000, (6, 23)),
    ("Hana Kobayashi", "Dubai", "Architect", 37_500, 322_060, 60_000, (8, 23)),
    ("Khalid Mansour", "Ras Al Khaimah", "Pilot", 52_000, 689_400, 100_000, (0, 24)),
    ("Grace Mwangi", "Dubai", "Nurse", 16_500, 41_870, 20_000, (6, 24)),
    ("Faisal Rahman", "Abu Dhabi", "Student", 4_000, 8_640, 5_000, (10, 24)),
]

MERCHANTS = {
    "groceries": ["Carrefour City", "Spinneys", "Union Coop", "Lulu Hypermarket"],
    "dining": ["Al Mallah", "Ravi Restaurant", "Tim Hortons", "Shake Shack"],
    "transport": ["RTA Nol top-up", "Careem", "ADNOC Fuel", "Salik"],
    "utilities": ["DEWA", "du Mobile", "Etisalat Home", "Empower Cooling"],
    "shopping": ["Noon", "Amazon.ae", "IKEA", "Decathlon"],
}


def iban(account_no: str, bank_code: str = BANK_CODE) -> str:
    """A checksum-valid IBAN in the UAE layout (AE + 2 check digits + 3 bank + 16 account)."""
    bban = bank_code + account_no.zfill(16)
    numeric = "".join(str(int(c, 36)) for c in bban + "AE00")
    check = 98 - int(numeric) % 97
    return f"AE{check:02d}{bban}"


def iban_valid(value: str) -> bool:
    v = value.replace(" ", "").upper()
    if len(v) < 15 or not v.isalnum():
        return False
    numeric = "".join(str(int(c, 36)) for c in v[4:] + v[:4])
    return int(numeric) % 97 == 1


def pw_hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()


def build() -> dict:
    rnd = random.Random(SEED)
    customers, accounts = [], []
    for n, (name, city, role, salary, opening, limit, hours) in enumerate(PEOPLE, start=1):
        cid = f"C{n:03d}"
        acc = f"{48_200_000 + n * 7919:016d}"
        device = f"dev-{hashlib.sha1(name.encode()).hexdigest()[:8]}"
        ip = f"198.51.100.{10 + n}"           # RFC 5737 documentation range = fictional
        password = f"oasis-{name.split()[0].lower()}-{1000 + n * 37}"
        salt = hashlib.sha1(cid.encode()).hexdigest()[:16]
        customers.append({
            "id": cid, "name": name, "city": city, "occupation": role,
            "email": f"{name.split()[0].lower()}@example.com",
            "phone": f"+971 50 555 {1000 + n:04d}",
            "kyc": "verified", "risk_rating": "low" if salary > 15_000 else "medium",
            "devices": [device], "home_ip": ip, "home_country": "AE",
            "active_hours": list(hours),
            "password_demo": password, "password_salt": salt, "password_hash": pw_hash(password, salt),
            "accounts": [acc],
        })
        accounts.append({"account_no": acc, "iban": iban(acc), "owner": cid, "currency": "AED",
                         "type": "current", "balance": float(opening), "daily_limit": float(limit)})

    # every customer pays 2-3 friends/family at the bank, plus 1 landlord outside
    payees: dict[str, list[dict]] = {}
    for c in customers:
        others = rnd.sample([x for x in customers if x["id"] != c["id"]], 2)
        payees[c["id"]] = [{"name": o["name"], "iban": next(a["iban"] for a in accounts
                                                              if a["owner"] == o["id"])} for o in others]
        landlord = f"{48_900_000 + rnd.randint(1, 9999):016d}"
        payees[c["id"]].append({"name": f"{c['city']} Properties LLC", "iban": iban(landlord)})

    # 90 days of history, oldest first; balances roll forward to today's balance
    history = []
    tx = 0
    for c, a in zip(customers, accounts):
        salary = PEOPLE[int(c["id"][1:]) - 1][3]
        h0, h1 = c["active_hours"]
        for d in range(DAYS, 0, -1):
            day = TODAY - timedelta(days=d)

            def add(kind, amount, counterparty, cp_iban="", channel="card"):
                nonlocal tx
                tx += 1
                hour = rnd.randint(h0, max(h0, min(h1, 24) - 1))
                history.append({
                    "id": f"T{tx:06d}", "account_no": a["account_no"], "customer": c["id"],
                    "ts": day.replace(hour=hour % 24, minute=rnd.randint(0, 59)).isoformat(),
                    "kind": kind, "amount": round(amount, 2), "counterparty": counterparty,
                    "counterparty_iban": cp_iban, "channel": channel,
                    "device": c["devices"][0], "ip": c["home_ip"], "country": "AE"})
            if day.day == 25:
                add("salary_in", salary, f"{c['occupation']} payroll", channel="wps")
            if day.day == 1:
                add("transfer_out", round(salary * 0.3, -2), payees[c["id"]][2]["name"],
                    payees[c["id"]][2]["iban"], "app")
            for cat, chance, lo, hi in (("groceries", .55, 40, 420), ("dining", .35, 25, 260),
                                        ("transport", .5, 15, 120), ("shopping", .12, 60, 1500)):
                if rnd.random() < chance:
                    add("card_" + cat, rnd.uniform(lo, hi) * (salary / 25_000) ** .5,
                        rnd.choice(MERCHANTS[cat]))
            if day.day in (5, 12):
                add("bill", rnd.uniform(180, 900), rnd.choice(MERCHANTS["utilities"]), channel="app")
            if rnd.random() < 0.08:
                p = rnd.choice(payees[c["id"]][:2])
                add("transfer_out", round(rnd.uniform(150, 2500 * (salary / 25_000)), -1),
                    p["name"], p["iban"], "app")

    partners = [{
        "id": "P001", "name": "PayLink payouts", "owner": "PayLink Technologies (fictional)",
        "api_key_id": "pk_live_paylink_01", "api_secret_demo": "plk_demo_" + hashlib.sha1(b"paylink").hexdigest()[:20],
        "settlement_account": None,
        "allowed_scopes": ["payouts:create"], "usual_networks": ["AS-PAYLINK-DXB"],
        "active_hours": [7, 21], "typical_payout": 1_850.0, "typical_rate_per_min": 4,
        "usual_countries": ["AE", "IN", "PH", "PK"],
    }]
    settle = f"{48_100_000:016d}"
    accounts.append({"account_no": settle, "iban": iban(settle), "owner": "P001", "currency": "AED",
                     "type": "partner_settlement", "balance": 512_000.0, "daily_limit": 600_000.0})
    partners[0]["settlement_account"] = settle

    return {"generated_for": TODAY.isoformat(), "bank": "Oasis Bank (fictional)",
            "customers": customers, "accounts": accounts, "payees": payees,
            "partners": partners, "history": history}


def write_markdown(data: dict, path: Path) -> None:
    acc = {a["owner"]: a for a in data["accounts"]}
    lines = ["# Oasis Bank: customer book (fictional)", "",
             "Every person, IBAN, device and IP below is made up for the hackathon. Bank code 999 is",
             "not a real UAE bank, and the IPs are from the RFC 5737 documentation range.",
             "Regenerate with `python3 -m oasis.data.generate`.", "",
             "| ID | Customer | City | Occupation | IBAN | Balance (AED) | Daily limit | Usual hours |",
             "|---|---|---|---|---|---:|---:|---|"]
    for c in data["customers"]:
        a = acc[c["id"]]
        lines.append(f"| {c['id']} | {c['name']} | {c['city']} | {c['occupation']} | `{a['iban']}` | "
                     f"{a['balance']:,.2f} | {a['daily_limit']:,.0f} | " +
                     ("any time" if c['active_hours'] == [0, 24] else
                      f"{c['active_hours'][0]:02d}:00 to {c['active_hours'][1]:02d}:00") + " |")
    p = data["partners"][0]
    s = acc["P001"]
    lines += ["", "## Partner", "",
              f"**{p['name']}** ({p['owner']}), API key `{p['api_key_id']}`, settlement IBAN `{s['iban']}`,",
              f"balance AED {s['balance']:,.0f}. Normally pays out about AED {p['typical_payout']:,.0f} each,",
              f"{p['active_hours'][0]}:00 to {p['active_hours'][1]}:00, from {', '.join(p['usual_networks'])}.",
              "", "## Saved payees", ""]
    for cid, ps in data["payees"].items():
        lines.append(f"- **{cid}**: " + "; ".join(f"{x['name']} `{x['iban']}`" for x in ps))
    lines += ["", "## Demo logins (fictional, for the attack scripts)", "",
              "| ID | Password | Device |", "|---|---|---|"]
    for c in data["customers"]:
        lines.append(f"| {c['id']} | `{c['password_demo']}` | `{c['devices'][0]}` |")
    lines += ["", "## Last 10 statement lines per customer", ""]
    for c in data["customers"]:
        rows = [h for h in data["history"] if h["customer"] == c["id"]][-10:]
        lines += [f"### {c['id']} {c['name']}", "", "| Date | Type | Counterparty | Amount (AED) |",
                  "|---|---|---|---:|"]
        for h in rows:
            sign = "+" if h["kind"] == "salary_in" else "-"
            lines.append(f"| {h['ts'][:16].replace('T', ' ')} | {h['kind']} | {h['counterparty']} | "
                         f"{sign}{h['amount']:,.2f} |")
        lines.append("")
    lines.append(f"Full history: {len(data['history']):,} transactions over {DAYS} days in `customers.json`.")
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    data = build()
    (HERE / "customers.json").write_text(json.dumps(data, indent=1))
    write_markdown(data, HERE.parent.parent / "CUSTOMERS.md")
    print(f"{len(data['customers'])} customers, {len(data['history'])} transactions written.")


if __name__ == "__main__":
    main()
