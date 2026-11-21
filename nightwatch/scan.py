"""Night Watch code guard for CI.

Structural mode (used by the GitHub Action):
    python -m nightwatch.scan --base origin/main [--json out.json] [--md out.md] [paths...]

Legacy diff mode (text diff on stdin):
    git diff origin/main...HEAD -- demo_bank | python -m nightwatch.scan

Exits 1 (failing the check) if the change weakens a protection. In GitHub Actions it also
prints ::error annotations so each finding shows on the exact line of the pull request.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

from .astscan import markdown, risk, scan_change
from .codescan import scan
from .signals import CODE_WEIGHTS

DEFAULT_PATHS = ["oasis", "demo_bank", "nightwatch", "server.py"]


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=False).stdout


def _added_lines(base: str, path: str) -> set[int]:
    lines: set[int] = set()
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", _git("diff", "-U0", f"{base}...HEAD", "--", path), re.M):
        start, n = int(m.group(1)), int(m.group(2) or 1)
        lines.update(range(start, start + n))
    return lines


def structural(base: str, paths: list[str]) -> list:
    merge_base = _git("merge-base", base, "HEAD").strip() or base
    changed = [p for p in _git("diff", "--name-only", f"{merge_base}...HEAD", "--", *paths).split() if p.endswith(".py")
               and "/tests/" not in f"/{p}" and not os.path.basename(p).startswith("test_")]
    findings = []
    for path in changed:
        old = subprocess.run(["git", "show", f"{merge_base}:{path}"], capture_output=True, text=True).stdout or None
        new = open(path).read() if os.path.exists(path) else None
        findings += scan_change(path, old, new, _added_lines(merge_base, path) if old else None)
    return findings


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1].startswith("--"):
        ap = argparse.ArgumentParser(prog="nightwatch.scan")
        ap.add_argument("--base", required=True)
        ap.add_argument("--json")
        ap.add_argument("--md")
        ap.add_argument("paths", nargs="*")
        a = ap.parse_args(argv[1:])
        findings = structural(a.base, a.paths or DEFAULT_PATHS)
        score = risk(findings)
        report = markdown(findings, score)
        if a.json:
            with open(a.json, "w") as fh:
                json.dump({"risk": score, "findings": [f.to_dict() for f in findings]}, fh, indent=1)
        if a.md:
            with open(a.md, "w") as fh:
                fh.write(report + "\n")
        print(report)
        if os.environ.get("GITHUB_ACTIONS"):
            for f in findings:
                level = "error" if f.severity == "high" else "warning"
                print(f"::{level} file={f.file},line={f.line},title=Night Watch {f.code}::{f.reason}")
        return 1 if any(f.severity == "high" for f in findings) else 0

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
