"""Extended capability categories, closing gaps toward SkillSpector's
16-category taxonomy (§5.3) for the parts that fit our declared v1 scope
(§13 open decision 3 explicitly excludes full MCP server audit — those
categories, tool-poisoning/rug-pull/least-privilege, are not reimplemented
here on purpose).

Covers: SSRF, privilege escalation, harmful content generation, anti-refusal
/ jailbreak framing, and agent/skill snooping (reading other skills' or the
host agent's own config).
"""
from __future__ import annotations

import re

from ..models import Capability, Finding, Severity

PATTERNS: list[tuple[str, Capability, Severity, str, str]] = [
    # SSRF: cloud metadata endpoints and loopback/link-local targets
    ("SC-E1", Capability.SSRF, Severity.HIGH,
     r"\b169\.254\.169\.254\b|\bmetadata\.google\.internal\b|\b100\.100\.100\.200\b",
     "References a cloud metadata service endpoint (AWS/GCP/Azure/Alibaba) — classic SSRF target for credential theft."),
    ("SC-E2", Capability.SSRF, Severity.MEDIUM,
     r"\bhttp://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])[:/]",
     "Fetches from a loopback address — potential SSRF pivot to internal services."),

    # Privilege escalation
    ("SC-E3", Capability.PRIVILEGE_ESCALATION, Severity.HIGH,
     r"\bsudo\s+(?:su\b|-s\b|chmod\s+(?:4755|\+s)|passwd\b)|\bchmod\s+(?:4755|\+s|777)\s+/",
     "Attempts to gain elevated or setuid privileges."),
    ("SC-E4", Capability.PRIVILEGE_ESCALATION, Severity.HIGH,
     r"\becho\b[^\n]{0,60}>>\s*/etc/sudoers\b|\busermod\s+-aG\s+sudo\b",
     "Modifies sudoers or adds the current user to a privileged group."),

    # Harmful content generation requests
    ("SC-E5", Capability.HARMFUL_CONTENT, Severity.HIGH,
     r"\bwrite\s+(?:a\s+)?(?:working\s+)?(?:ransomware|keylogger|rootkit|wiper|self-propagating)\b",
     "Instructs the agent to author functional malware."),
    ("SC-E6", Capability.HARMFUL_CONTENT, Severity.MEDIUM,
     r"\bbypass\s+(?:antivirus|edr|endpoint\s+detection)\b",
     "Instructs the agent to help evade security controls."),

    # Anti-refusal / jailbreak framing
    ("SC-E7", Capability.ANTI_REFUSAL, Severity.HIGH,
     r"\byou\s+are\s+(?:now\s+)?DAN\b|\bdo\s+anything\s+now\b|\bwithout\s+any\s+(?:restrictions|filters|guardrails)\b",
     "Classic jailbreak persona-override framing."),
    ("SC-E8", Capability.ANTI_REFUSAL, Severity.MEDIUM,
     r"\brespond\s+as\s+(?:an?\s+)?(?:unfiltered|unrestricted|uncensored)\s+(?:ai|assistant|model)\b",
     "Instructs the agent to drop its safety behavior."),

    # Agent / skill snooping
    ("SC-E9", Capability.AGENT_SNOOPING, Severity.MEDIUM,
     r"\b(?:read|cat|list|enumerate)\b[^\n]{0,40}\b(?:\.claude/|CLAUDE\.md|claude_desktop_config\.json|system\s+prompt)\b",
     "Reads the host agent's own configuration/system-prompt files rather than user data."),
    ("SC-E10", Capability.AGENT_SNOOPING, Severity.MEDIUM,
     r"\b(?:read|cat|list)\b[^\n]{0,40}\bother\s+(?:installed\s+)?skills\b|\.claude/skills/(?!\S*\bthis\b)",
     "Enumerates or reads other installed skills rather than staying in its own scope."),
]

_COMPILED = [(rid, cap, sev, re.compile(pat, re.IGNORECASE), why) for rid, cap, sev, pat, why in PATTERNS]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def detect_extended(file_path: str, text: str, provenance: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rid, cap, sev, rx, why in _COMPILED:
        for m in rx.finditer(text):
            findings.append(Finding(
                rule_id=rid,
                capability=cap,
                file=file_path,
                start_line=_line_of(text, m.start()),
                end_line=_line_of(text, m.end()),
                matched_text=m.group(0).strip()[:400],
                severity=sev,
                rationale=why,
                confidence=0.55,
                provenance=list(provenance or []),
                detector="extended",
            ))
    return findings
