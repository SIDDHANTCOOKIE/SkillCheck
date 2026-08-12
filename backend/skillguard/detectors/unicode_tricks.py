"""Zero-width / bidi-override / mixed-script detection. See spec §3.3."""
from __future__ import annotations

import unicodedata

from ..models import Capability, Finding, Severity

ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE / BOM",
    "⁠": "WORD JOINER",
}

BIDI_OVERRIDES = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    return name.split(" ")[0]


def detect_unicode(file_path: str, text: str, provenance: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    provenance = provenance or []

    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH:
            findings.append(Finding(
                rule_id="SG-U1", capability=Capability.OBFUSCATION, file=file_path,
                start_line=_line_of(text, i), end_line=_line_of(text, i),
                matched_text=f"U+{ord(ch):04X} {ZERO_WIDTH[ch]}", severity=Severity.MEDIUM,
                rationale="Zero-width character can hide or split content from human/LLM review.",
                confidence=0.5, provenance=list(provenance), detector="unicode",
            ))
        elif ch in BIDI_OVERRIDES:
            findings.append(Finding(
                rule_id="SG-U2", capability=Capability.OBFUSCATION, file=file_path,
                start_line=_line_of(text, i), end_line=_line_of(text, i),
                matched_text=f"U+{ord(ch):04X} {BIDI_OVERRIDES[ch]}", severity=Severity.HIGH,
                rationale="Bidi control character can visually reorder text to disguise malicious content.",
                confidence=0.7, provenance=list(provenance), detector="unicode",
            ))

    # crude mixed-script identifier check: ascii letters mixed with letters from
    # another alphabetic script inside a single "word" token (homoglyph smell).
    word = []
    word_start = 0
    for i, ch in enumerate(text + " "):
        if ch.isalpha():
            if not word:
                word_start = i
            word.append(ch)
            continue
        if len(word) >= 4:
            scripts = {_script_of(c) for c in word if ord(c) > 127}
            has_ascii = any(ord(c) <= 127 for c in word)
            if scripts and has_ascii:
                findings.append(Finding(
                    rule_id="SG-U3", capability=Capability.OBFUSCATION, file=file_path,
                    start_line=_line_of(text, word_start), end_line=_line_of(text, word_start),
                    matched_text="".join(word)[:80], severity=Severity.MEDIUM,
                    rationale="Mixed-script token (ASCII + non-Latin letters) consistent with homoglyph spoofing.",
                    confidence=0.35, provenance=list(provenance), detector="unicode",
                ))
        word = []
    return findings
