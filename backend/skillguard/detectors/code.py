"""Code-level detectors: Python AST dangerous calls + shell command patterns.

The AST analyzer covers objective 3 (hidden execution) for Python. The shell
regex pack covers objectives 2-6 for bash/sh snippets embedded in scripts or
fenced code blocks, since most of the red-team surface here is shell one-liners
rather than full programs.
"""
from __future__ import annotations

import ast
import re

from ..models import Capability, Finding, Severity

DANGEROUS_CALLS = {
    "eval": ("SG-C1", Severity.HIGH, "eval() executes arbitrary code from a string."),
    "exec": ("SG-C2", Severity.HIGH, "exec() executes arbitrary code from a string."),
    "compile": ("SG-C3", Severity.MEDIUM, "compile() builds code objects dynamically."),
    "__import__": ("SG-C4", Severity.MEDIUM, "Dynamic import can load arbitrary modules."),
    "system": ("SG-C5", Severity.HIGH, "os.system() runs an arbitrary shell command."),
    "popen": ("SG-C6", Severity.HIGH, "os.popen()/subprocess with shell access."),
}


def _ast_findings(file_path: str, tree: ast.AST, source: str, provenance: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()

    def span(node: ast.AST) -> str:
        try:
            seg = ast.get_source_segment(source, node)
            if seg:
                return seg[:400]
        except Exception:
            pass
        ln = getattr(node, "lineno", 1)
        return lines[ln - 1][:400] if 0 < ln <= len(lines) else ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fname = None
            if isinstance(node.func, ast.Name):
                fname = node.func.id
            elif isinstance(node.func, ast.Attribute):
                fname = node.func.attr

            if fname in DANGEROUS_CALLS:
                rid, sev, why = DANGEROUS_CALLS[fname]
                findings.append(Finding(
                    rule_id=rid,
                    capability=Capability.HIDDEN_EXECUTION,
                    file=file_path,
                    start_line=getattr(node, "lineno", 1),
                    end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                    matched_text=span(node),
                    severity=sev,
                    rationale=why,
                    confidence=0.6,
                    provenance=list(provenance),
                    detector="code-ast",
                ))

            # subprocess.*(..., shell=True)
            if fname in {"run", "call", "Popen", "check_output", "check_call"}:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(Finding(
                            rule_id="SG-C7",
                            capability=Capability.HIDDEN_EXECUTION,
                            file=file_path,
                            start_line=getattr(node, "lineno", 1),
                            end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                            matched_text=span(node),
                            severity=Severity.HIGH,
                            rationale="subprocess call with shell=True executes a shell command string.",
                            confidence=0.65,
                            provenance=list(provenance),
                            detector="code-ast",
                        ))

            # dynamic getattr on os/subprocess-like modules used to call through indirection
            if fname == "getattr" and len(node.args) >= 2:
                findings.append(Finding(
                    rule_id="SG-C8",
                    capability=Capability.OBFUSCATION,
                    file=file_path,
                    start_line=getattr(node, "lineno", 1),
                    end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                    matched_text=span(node),
                    severity=Severity.LOW,
                    rationale="Dynamic attribute access can be used to obscure a dangerous call target.",
                    confidence=0.3,
                    provenance=list(provenance),
                    detector="code-ast",
                ))
    return findings


def detect_code(file_path: str, text: str, provenance: list[list] | None = None) -> list[Finding]:
    provenance = provenance or []
    if not file_path.endswith(".py"):
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    return _ast_findings(file_path, tree, text, provenance)


# --- shell pattern pack -----------------------------------------------------

SHELL_PATTERNS: list[tuple[str, Capability, Severity, str, str]] = [
    ("SG-SH1", Capability.STAGE2_FETCH, Severity.HIGH,
     r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[23]?)\b",
     "Pipes a network download directly into a shell/interpreter."),
    ("SG-SH2", Capability.STAGE2_FETCH, Severity.HIGH,
     r"\b(?:curl|wget)\b[^\n]{0,120}(?:-o|-O|--output)\b[^\n]{0,80}(?:&&|\n)[^\n]{0,80}\bchmod\s+\+x\b",
     "Downloads a file then makes it executable (stage-2 payload pattern)."),
    ("SG-SH3", Capability.EXFILTRATION, Severity.HIGH,
     r"\bcurl\b[^\n]{0,120}(?:-d|--data|-F)\b",
     "curl with an outbound data payload (potential exfiltration)."),
    ("SG-SH4", Capability.EXFILTRATION, Severity.HIGH,
     r"\bbase64\b[^\n]{0,60}\|\s*(?:nc|ncat|curl|wget)\b",
     "Encodes data and pipes it to a network tool."),
    ("SG-SH5", Capability.EXFILTRATION, Severity.MEDIUM,
     r"\bgit\s+remote\s+add\b.{0,80}(?:&&|\n).{0,40}\bgit\s+push\b",
     "Adds an attacker-controlled remote and pushes the repository to it."),
    ("SG-SH6", Capability.PERSISTENCE, Severity.HIGH,
     r"\b(?:crontab\s+-|>>\s*~?/?(?:\.bashrc|\.zshrc|\.profile)|systemctl\s+enable|launchctl\s+load)\b",
     "Installs a persistence mechanism (cron/shell rc/systemd/launchd)."),
    ("SG-SH7", Capability.ANTI_FORENSICS, Severity.HIGH,
     r"\b(?:history\s+-c|unset\s+HISTFILE|rm\s+-f?\s*~?/?\.bash_history|>\s*~?/?\.bash_history)\b",
     "Clears or disables shell history (anti-forensics)."),
    ("SG-SH8", Capability.CREDENTIAL_ACCESS, Severity.HIGH,
     r"(~/\.aws/credentials|~/\.ssh/id_rsa\b|~/\.npmrc|~/\.kube/config|Login\s+Data|wallet\.dat)",
     "References a well-known credential store path."),
    ("SG-SH9", Capability.STAGE2_FETCH, Severity.MEDIUM,
     r"\bpip\s+install\s+(?:-e\s+)?git\+https?://|pip\s+install\s+https?://",
     "Installs a Python package directly from a URL/VCS rather than a registry."),
    ("SG-SH10", Capability.HIDDEN_EXECUTION, Severity.MEDIUM,
     r"\bpython[23]?\s+-c\s+['\"]",
     "Inline python -c execution, commonly used to obscure a payload."),
    ("SG-SH11", Capability.EXFILTRATION, Severity.MEDIUM,
     r"\bnslookup\b.{0,10}\$\(|\bdig\s+\+short\b.{0,80}\$\(",
     "DNS-lookup pattern consistent with DNS exfiltration/tunnelling."),
]

_SHELL_COMPILED = [(rid, cap, sev, re.compile(pat, re.IGNORECASE), why)
                    for rid, cap, sev, pat, why in SHELL_PATTERNS]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def detect_shell_patterns(file_path: str, text: str, provenance: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rid, cap, sev, rx, why in _SHELL_COMPILED:
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
                confidence=0.6,
                provenance=list(provenance or []),
                detector="shell-regex",
            ))
    return findings
