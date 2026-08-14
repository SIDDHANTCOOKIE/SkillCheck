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
    "eval": ("SC-C1", Severity.HIGH, "eval() executes arbitrary code from a string."),
    "exec": ("SC-C2", Severity.HIGH, "exec() executes arbitrary code from a string."),
    "compile": ("SC-C3", Severity.MEDIUM, "compile() builds code objects dynamically."),
    "__import__": ("SC-C4", Severity.MEDIUM, "Dynamic import can load arbitrary modules."),
    "system": ("SC-C5", Severity.HIGH, "os.system() runs an arbitrary shell command."),
    "popen": ("SC-C6", Severity.HIGH, "os.popen()/subprocess with shell access."),
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
            receiver = None
            if isinstance(node.func, ast.Name):
                fname = node.func.id
            elif isinstance(node.func, ast.Attribute):
                fname = node.func.attr
                if isinstance(node.func.value, ast.Name):
                    receiver = node.func.value.id

            # re.compile()/regex.compile() build a Pattern object, not code —
            # distinct from the builtin compile() that DANGEROUS_CALLS targets.
            if fname == "compile" and receiver in {"re", "regex"}:
                fname = None

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
                            rule_id="SC-C7",
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
                    rule_id="SC-C8",
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


def detect_code(file_path: str, text: str, provenance: list[list] | None = None, *, lang_override: str | None = None) -> list[Finding]:
    """`lang_override="python"` lets a fenced ```python block or a decoded
    payload reach AST analysis even though `file_path` is the parent
    document's path (e.g. SKILL.md), not a .py file (2.2)."""
    provenance = provenance or []
    if lang_override != "python" and not file_path.endswith(".py"):
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    return _ast_findings(file_path, tree, text, provenance)


# --- shell pattern pack -----------------------------------------------------

SHELL_PATTERNS: list[tuple[str, Capability, Severity, str, str]] = [
    ("SC-SH1", Capability.STAGE2_FETCH, Severity.HIGH,
     r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[23]?)\b",
     "Pipes a network download directly into a shell/interpreter."),
    ("SC-SH2", Capability.STAGE2_FETCH, Severity.HIGH,
     r"\b(?:curl|wget)\b[^\n]{0,120}(?:-o|-O|--output)\b[^\n]{0,80}(?:&&|\n)[^\n]{0,80}\bchmod\s+\+x\b",
     "Downloads a file then makes it executable (stage-2 payload pattern)."),
    ("SC-SH3", Capability.EXFILTRATION, Severity.HIGH,
     r"\bcurl\b[^\n]{0,120}(?:-d|--data|-F)\b",
     "curl with an outbound data payload (potential exfiltration)."),
    ("SC-SH4", Capability.EXFILTRATION, Severity.HIGH,
     r"\bbase64\b[^\n]{0,60}\|\s*(?:nc|ncat|curl|wget)\b",
     "Encodes data and pipes it to a network tool."),
    ("SC-SH5", Capability.EXFILTRATION, Severity.MEDIUM,
     r"\bgit\s+remote\s+add\b.{0,80}(?:&&|\n).{0,40}\bgit\s+push\b",
     "Adds an attacker-controlled remote and pushes the repository to it."),
    ("SC-SH6", Capability.PERSISTENCE, Severity.HIGH,
     # ">>" isn't a word character, so a leading \b before it can never match —
     # that branch silently never fired until this was split out (found while
     # building the eval manifest; see obj5_persistence_bashrc.sh).
     r"\bcrontab\s+-|>>\s*~?/?(?:\.bashrc|\.zshrc|\.profile)\b|\bsystemctl\s+enable\b|\blaunchctl\s+load\b",
     "Installs a persistence mechanism (cron/shell rc/systemd/launchd)."),
    ("SC-SH7", Capability.ANTI_FORENSICS, Severity.HIGH,
     r"\b(?:history\s+-c|unset\s+HISTFILE|rm\s+-f?\s*~?/?\.bash_history|>\s*~?/?\.bash_history)\b",
     "Clears or disables shell history (anti-forensics)."),
    ("SC-SH8", Capability.CREDENTIAL_ACCESS, Severity.HIGH,
     r"(~/\.aws/credentials|~/\.ssh/id_rsa\b|~/\.npmrc|~/\.kube/config|Login\s+Data|wallet\.dat)",
     "References a well-known credential store path."),
    ("SC-SH9", Capability.STAGE2_FETCH, Severity.MEDIUM,
     r"\bpip\s+install\s+(?:-e\s+)?git\+https?://|pip\s+install\s+https?://",
     "Installs a Python package directly from a URL/VCS rather than a registry."),
    ("SC-SH10", Capability.HIDDEN_EXECUTION, Severity.MEDIUM,
     r"\bpython[23]?\s+-c\s+['\"]",
     "Inline python -c execution, commonly used to obscure a payload."),
    ("SC-SH11", Capability.EXFILTRATION, Severity.MEDIUM,
     r"\bnslookup\b.{0,10}\$\(|\bdig\s+\+short\b.{0,80}\$\(",
     "DNS-lookup pattern consistent with DNS exfiltration/tunnelling."),
]

_SHELL_COMPILED = [(rid, cap, sev, re.compile(pat, re.IGNORECASE), why)
                    for rid, cap, sev, pat, why in SHELL_PATTERNS]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


# --- shell command-splitting de-obfuscation ---------------------------------
#
# SHELL_PATTERNS matches command names literally ("curl", "wget", ...), so
# two well-known evasions defeat it outright without needing any encoding:
# splitting a command name with empty quote pairs (`cu''rl`) or single-char
# quoting (`c'u'r'l`) — both are ordinary shell string concatenation, so the
# shell runs `curl` either way — and substituting `$IFS` (the shell's field
# separator variable) for the spaces between arguments (`curl$IFS-s$IFSurl`).
# Neither trick changes what the shell executes; both were, until this pass,
# enough to make the command invisible to every SC-SH* pattern.
#
# This is a normalization pass, not a shell parser: it doesn't tokenize or
# understand quoting state, it just collapses the two specific constructions
# above so the existing patterns can see through them. That's a deliberate,
# narrow scope — a full grammar is what `docs/detection-model.md` lists as
# the size of fix actually needed to close shell analysis generally; this
# closes the two most common command-name evasions without taking on that
# dependency.

# An empty quote pair directly between two word characters concatenates to
# nothing in the shell — `cu''rl` runs `curl`. Bounded to word-adjacent
# quotes specifically so this doesn't touch a normal quoted argument like
# `curl -s "$url"`, where the quotes sit next to whitespace or `$`, not a
# bare word character on both sides.
_EMPTY_QUOTE_SPLIT_RE = re.compile(r"(?<=[A-Za-z0-9_])(['\"])\1(?=[A-Za-z0-9_])")

# A single quote character sitting between two word characters is the other
# half of the same trick — `c'u'r'l` runs `curl` because each quoted single
# character is still just that character to the shell. This one is lossier
# than the empty-pair rule (it will also strip a real apostrophe inside a
# double-quoted string, e.g. "it's" -> "its"), which is why it only ever
# feeds the supplementary de-obfuscated pass below, never the evidence
# quoted for a raw-text match.
_SINGLE_QUOTE_MID_WORD_RE = re.compile(r"(?<=[A-Za-z0-9_])['\"](?=[A-Za-z0-9_])")

# `$IFS`/`${IFS}` is the shell's field-separator variable; unset or default
# it's a space. `$IFS$9` is the same trick with a harmless empty-variable
# suffix appended, seen often enough in the wild to fold in here rather than
# leave as a second silent gap.
_IFS_SEPARATOR_RE = re.compile(r"\$\{?IFS\}?(?:\$\d)?")


def _deobfuscate_shell(text: str) -> str:
    """Collapse quote-splitting and $IFS-as-separator, or return `text`
    unchanged if neither evasion is present.

    Applied as a fixpoint over both quote rules together — collapsing one
    can create the adjacency the other rule needs (`cu''rl` needs only the
    empty-pair rule, but a mixed `c''u'r'l` needs a round of each) — bounded
    at 20 iterations, which is far more than any real command name needs and
    just a hard ceiling against pathological input.

    Never removes a newline, only quote/`$IFS` characters, so a line number
    computed against the returned text with `_line_of` stays correct: the
    count of `\\n` characters before any surviving position is unchanged by
    deleting non-newline characters earlier in the string.
    """
    out = text
    for _ in range(20):
        collapsed = _EMPTY_QUOTE_SPLIT_RE.sub("", out)
        collapsed = _SINGLE_QUOTE_MID_WORD_RE.sub("", collapsed)
        if collapsed == out:
            break
        out = collapsed
    return _IFS_SEPARATOR_RE.sub(" ", out)


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

    deobfuscated = _deobfuscate_shell(text)
    if deobfuscated != text:
        raw_spans = {(f.start_line, f.rule_id) for f in findings}
        recovered_rules: set[str] = set()
        for rid, cap, sev, rx, why in _SHELL_COMPILED:
            for m in rx.finditer(deobfuscated):
                start_line = _line_of(deobfuscated, m.start())
                if (start_line, rid) in raw_spans:
                    continue  # already found on the raw text at this line
                recovered_rules.add(rid)
                findings.append(Finding(
                    rule_id=rid,
                    capability=cap,
                    file=file_path,
                    start_line=start_line,
                    end_line=_line_of(deobfuscated, m.end()),
                    matched_text=m.group(0).strip()[:400],
                    severity=sev,
                    rationale=(
                        f"{why} Only visible after collapsing quote-splitting "
                        "and/or $IFS-as-separator obfuscation in the source "
                        "line — the raw text alone does not spell out this "
                        "command."
                    ),
                    # A notch below the raw-text match on the same rule: this
                    # went through a normalization heuristic rather than
                    # matching the literal source, so it carries slightly
                    # less certainty than seeing the command spelled out
                    # directly.
                    confidence=0.5,
                    provenance=list(provenance or []) + ["shell-deobfuscated"],
                    detector="shell-regex",
                ))
        if recovered_rules:
            findings.append(Finding(
                rule_id="SC-SH12",
                capability=Capability.OBFUSCATION,
                file=file_path,
                start_line=1,
                end_line=1,
                matched_text=f"quote-splitting / $IFS obfuscation constructing: {', '.join(sorted(recovered_rules))}",
                severity=Severity.MEDIUM,
                rationale=(
                    "This file uses quote-splitting (e.g. cu''rl) and/or $IFS "
                    "in place of spaces to construct a shell command — a "
                    "technique whose only purpose is defeating literal "
                    "pattern matching on the command name, since the shell "
                    "runs the exact same command either way."
                ),
                confidence=0.7,
                provenance=list(provenance or []),
                detector="shell-regex",
            ))
    return findings
