"""Secrets regex pack: credential material embedded in the package itself.

Distinct from code.py's SC-SH8 (which flags *references* to credential
paths). This flags actual key material accidentally or deliberately shipped
inside the skill.
"""
from __future__ import annotations

import re

from ..models import Capability, Finding, Severity

SECRET_PATTERNS: list[tuple[str, Severity, str, str]] = [
    ("SC-S1", Severity.CRITICAL, r"AKIA[0-9A-Z]{16}", "AWS access key ID literal."),
    ("SC-S2", Severity.CRITICAL, r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Embedded private key material."),
    ("SC-S3", Severity.HIGH, r"gh[pousr]_[A-Za-z0-9]{36,}", "GitHub token literal."),
    ("SC-S4", Severity.HIGH, r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token literal."),
    ("SC-S5", Severity.HIGH, r"(?i)\bapi[_-]?key\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Hardcoded API key assignment."),
    ("SC-S6", Severity.HIGH, r"(?i)\bsecret[_-]?(?:key|token)\b\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{12,}['\"]", "Hardcoded secret/token assignment."),
    ("SC-S7", Severity.MEDIUM, r"(?i)\bpassword\b\s*[:=]\s*['\"][^'\"]{6,}['\"]", "Hardcoded password literal."),
]

_COMPILED = [(rid, sev, re.compile(pat), why) for rid, sev, pat, why in SECRET_PATTERNS]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def detect_secrets(file_path: str, text: str, provenance: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rid, sev, rx, why in _COMPILED:
        for m in rx.finditer(text):
            findings.append(Finding(
                rule_id=rid,
                capability=Capability.CREDENTIAL_ACCESS,
                file=file_path,
                start_line=_line_of(text, m.start()),
                end_line=_line_of(text, m.end()),
                matched_text=m.group(0)[:200],
                severity=sev,
                rationale=why,
                confidence=0.7,
                provenance=list(provenance or []),
                detector="secrets-regex",
            ))
    return findings
