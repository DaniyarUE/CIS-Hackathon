"""Night Watch code guard for CI.

Usage:
    git diff origin/main...HEAD -- demo_bank | python -m nightwatch.scan
    python -m nightwatch.scan path/to/change.diff

Exits 1 (failing the check) if the diff weakens a safety rail.
"""
from __future__ import annotations

import sys

from .codescan import scan
from .signals import CODE_WEIGHTS


def main(argv: list[str]) -> int:
    diff = open(argv[1]).read() if len(argv) > 1 else sys.stdin.read()
    findings = scan(diff)
    score = min(100, sum(CODE_WEIGHTS.get(f.code, 15) for f in findings))
    if not findings:
        print("Night Watch: no safety-rail changes found. OK.")
        return 0
    print(f"Night Watch: risk {score}/100")
    for f in findings:
        print(f"  [{f.code}] {f.reason}\n      {f.line}")
    return 1 if score >= 40 else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
