"""Natural-language instruction-intent detectors. See spec §3.1, §3.2 objective 7/8.

This is the primary detector class per the spec: the payload is prose, not
code, so agent-manipulation and capability-intent language in SKILL.md /
references/*.md must be scanned with the same rigor as a script.
"""
from __future__ import annotations

import re

from ..models import Capability, Finding, Severity

# (rule_id, capability, severity, pattern, rationale)
PROSE_PATTERNS: list[tuple[str, Capability, Severity, str, str]] = [
    # Objective 7: agent manipulation / prompt injection
    ("SC-P1", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bdo\s+not\s+(?:tell|mention|inform|show|reveal|alert)\s+(?:this\s+)?(?:to\s+)?the\s+user\b",
     "Instructs the agent to conceal an action from the user."),
    ("SC-P2", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b",
     "Classic prompt-injection override phrase."),
    ("SC-P3", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\b(?:before|prior to|first,?\s+silently)\s+(?:the\s+user'?s?\s+)?(?:actual\s+)?task\b.{0,80}\b(?:run|execute|send|upload|copy|read)\b",
     "Sequences a hidden action ahead of the user's stated task (task-then-payload)."),
    ("SC-P4", Capability.AGENT_MANIPULATION, Severity.MEDIUM,
     r"\bthis\s+is\s+a\s+(?:system|developer)\s+(?:message|instruction|override)\b",
     "Spoofs an elevated-authority message inside skill content."),
    ("SC-P5", Capability.AGENT_MANIPULATION, Severity.MEDIUM,
     r"\bact\s+as\s+if\s+(?:you\s+)?(?:have|had)\s+(?:no|different)\s+(?:restrictions|rules|guidelines)\b",
     "Attempts to have the agent disregard its safety constraints."),
    ("SC-P6", Capability.TASK_THEN_PAYLOAD, Severity.MEDIUM,
     r"\bafter\s+(?:completing|finishing)\s+(?:the\s+)?(?:user'?s?\s+)?(?:request|task)\b.{0,80}\b(?:then\s+)?(?:send|upload|email|post|exfiltrate)\b",
     "Defers a data-moving action to after the legitimate task completes so it goes unnoticed."),
    # Objective 1: credential access, stated in prose rather than code
    ("SC-P7", Capability.CREDENTIAL_ACCESS, Severity.HIGH,
     r"\b(?:read|open|cat|copy|upload)\b.{0,40}\b(?:\.aws/credentials|\.ssh/id_rsa|\.env\b|\.npmrc|kube/?config|wallet\.dat|cookies?\.sqlite)\b",
     "Prose instructs reading a well-known credential/secret file path."),
    # Objective 2: exfiltration described in prose
    ("SC-P8", Capability.EXFILTRATION, Severity.HIGH,
     r"\b(?:send|upload|post|exfiltrate|email)\b.{0,60}\b(?:to|via)\b.{0,40}\b(?:webhook\.site|pastebin|discord(?:app)?\.com/api/webhooks|ngrok\.io|requestbin)\b",
     "Prose instructs sending data to a known exfiltration sink."),
    # Objective 4: stage-2 payload fetch described in prose
    ("SC-P9", Capability.STAGE2_FETCH, Severity.HIGH,
     r"\b(?:download|fetch)\b.{0,40}\b(?:and\s+)?(?:run|execute|chmod\s*\+x)\b",
     "Prose describes a download-then-execute stage-2 payload pattern."),
    # Objective 5: persistence described in prose
    ("SC-P10", Capability.PERSISTENCE, Severity.MEDIUM,
     r"\badd\b.{0,40}\bto\s+(?:your\s+)?(?:crontab|\.bashrc|\.zshrc|launchagents|systemd)\b",
     "Prose instructs installing a persistence mechanism."),
    # Objective 6: anti-forensics described in prose
    ("SC-P11", Capability.ANTI_FORENSICS, Severity.MEDIUM,
     r"\b(?:clear|delete|unset|truncate)\b.{0,30}\b(?:history|histfile|\.bash_history|logs?)\b",
     "Prose instructs clearing shell history or logs after acting."),
    # Setup-step disguise: legitimizing language next to a risky verb
    ("SC-P12", Capability.HIDDEN_EXECUTION, Severity.MEDIUM,
     r"\bto\s+(?:configure|set up|initialize)\s+your\s+environment,?\s+run\b.{0,60}\|\s*(?:bash|sh|python)\b",
     "\"Setup step\" framing wrapping a pipe-to-shell execution."),
]

_COMPILED = [(rid, cap, sev, re.compile(pat, re.IGNORECASE | re.DOTALL), why)
             for rid, cap, sev, pat, why in PROSE_PATTERNS]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def detect_prose(file_path: str, text: str, provenance: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rid, cap, sev, rx, why in _COMPILED:
        for m in rx.finditer(text):
            start_line = _line_of(text, m.start())
            end_line = _line_of(text, m.end())
            findings.append(Finding(
                rule_id=rid,
                capability=cap,
                file=file_path,
                start_line=start_line,
                end_line=end_line,
                matched_text=m.group(0).strip()[:400],
                severity=sev,
                rationale=why,
                confidence=0.55,
                provenance=list(provenance or []),
                detector="prose",
            ))
    return findings
