"""Fails if any tracked file holds a live credential (e.g. the PayLink key leaked in a91f3c2)."""
import subprocess
from pathlib import Path

from nightwatch.codescan import SECRET_PATTERNS

ROOT = Path(__file__).resolve().parents[1]
LIVE_KEY_PATTERNS = [p for p, label in SECRET_PATTERNS if label != "hard-coded credential"]


def test_no_live_keys_in_tracked_files():
    files = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True,
                           check=True).stdout.split("\0")
    hits = []
    for name in files:
        try:
            text = (ROOT / name).read_text()
        except (UnicodeDecodeError, IsADirectoryError):
            continue
        hits += [f"{name}: {m.group(0)[:12]}..." for p in LIVE_KEY_PATTERNS for m in p.finditer(text)]
    assert hits == []


def test_paylink_key_pattern_is_detected():
    from nightwatch.codescan import scan

    key = "plk_" + "live_" + "B" * 16  # built at runtime so the repo holds no key-shaped string
    assert {f.code for f in scan(f"+    client = Client('{key}')\n")} == {"SECRET_IN_CODE"}
