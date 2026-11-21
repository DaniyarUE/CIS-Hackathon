"""Static checks on a commit diff: what did this change do to the bank's safety rails?"""
from __future__ import annotations

import re
from dataclasses import dataclass

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"(sk|plk)_live_[0-9A-Za-z]{10,}"), "live payment API key"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"(?i)(password|secret|api_key|token)\s*=\s*['\"][^'\"]{6,}['\"]"), "hard-coded credential"),
]
SAFETY_WORDS = re.compile(
    r"(?i)(limit|threshold|aml|sanction|verify|authori[sz]e|check_|raise\s+\w*(Limit|Fraud|Denied)|require_approval)")
AUDIT_WORDS = re.compile(r"(?i)(audit|log\.(info|warning|error)|logger\.)")
BYPASS = re.compile(
    r"(?i)if\s+.*\b(account|user|iban|customer|payee|caller)\w*\s*(==|in)\s*[\[(]?['\"]")
EGRESS = re.compile(r"https?://([A-Za-z0-9.-]+)")
INTERNAL_HOST = re.compile(r"(\.bank\.internal|localhost|127\.0\.0\.1)$")


@dataclass
class Finding:
    code: str
    reason: str
    line: str


def _split(diff: str) -> tuple[list[str], list[str]]:
    added, removed = [], []
    for raw in diff.splitlines():
        if raw.startswith(("+++", "---")):
            continue
        if raw.startswith("+"):
            added.append(raw[1:].strip())
        elif raw.startswith("-"):
            removed.append(raw[1:].strip())
    return added, removed


def scan(diff: str) -> list[Finding]:
    added, removed = _split(diff)
    findings: list[Finding] = []

    for line in removed:
        if SAFETY_WORDS.search(line) and line not in added:
            findings.append(Finding("SAFETY_CHECK_REMOVED",
                                    "A payment safety check was deleted.", line))
            break
    for line in removed:
        if AUDIT_WORDS.search(line) and line not in added:
            findings.append(Finding("AUDIT_LOG_REMOVED",
                                    "Audit logging was removed, so the change hides its own tracks.", line))
            break
    for line in added:
        if BYPASS.search(line):
            findings.append(Finding("HARDCODED_BYPASS",
                                    "Adds a special case for one hard-coded account: a backdoor.", line))
            break
    for line in added:
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(Finding("SECRET_IN_CODE", f"Commits a {label} into the repo.", line))
                break
        else:
            continue
        break
    for line in added:
        m = EGRESS.search(line)
        if m and not INTERNAL_HOST.search(m.group(1)):
            findings.append(Finding("NEW_EGRESS",
                                    f"Sends data to an outside host ({m.group(1)}).", line))
            break
    return findings
