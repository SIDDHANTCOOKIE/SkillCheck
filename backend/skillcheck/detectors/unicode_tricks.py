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
                rule_id="SC-U1", capability=Capability.OBFUSCATION, file=file_path,
                start_line=_line_of(text, i), end_line=_line_of(text, i),
                matched_text=f"U+{ord(ch):04X} {ZERO_WIDTH[ch]}", severity=Severity.MEDIUM,
                rationale="Zero-width character can hide or split content from human/LLM review.",
                confidence=0.5, provenance=list(provenance), detector="unicode",
            ))
        elif ch in BIDI_OVERRIDES:
            findings.append(Finding(
                rule_id="SC-U2", capability=Capability.OBFUSCATION, file=file_path,
                start_line=_line_of(text, i), end_line=_line_of(text, i),
                matched_text=f"U+{ord(ch):04X} {BIDI_OVERRIDES[ch]}", severity=Severity.HIGH,
                rationale="Bidi control character can visually reorder text to disguise malicious content.",
                confidence=0.7, provenance=list(provenance), detector="unicode",
            ))

    # crude mixed-script identifier check: ascii letters mixed with letters from
    # a genuinely different alphabetic script inside a single "word" token
    # (homoglyph smell) — e.g. Cyrillic "а" substituted into an otherwise-Latin
    # word to spoof "admin".
    #
    # `_script_of` correctly names an accented Latin letter's script "LATIN"
    # (unicodedata.name("á") is "LATIN SMALL LETTER A WITH ACUTE"), the exact
    # same bucket as plain ASCII — but the check below used to test only
    # "is there a non-ASCII letter AND an ASCII letter in this word", without
    # ever asking whether the script that was just identified was actually a
    # *different* one. Every accented word in Spanish/French/German/
    # Portuguese prose ("configuración", "está", "über") is non-ASCII Latin
    # next to plain ASCII letters in the same token, so this fired on nearly
    # every word of ordinary multilingual documentation — a false positive on
    # exactly the content prose_intl.py exists to read fairly. A real
    # homoglyph substitution uses a script that isn't Latin at all (Cyrillic,
    # Greek, Armenian, ...), so exempting "LATIN" from the suspicious set
    # keeps genuine cross-script spoofing detected while clearing accented
    # Latin text entirely.
    _NOT_SUSPICIOUS_SCRIPTS = {"LATIN"}
    word = []
    word_start = 0
    for i, ch in enumerate(text + " "):
        if ch.isalpha():
            if not word:
                word_start = i
            word.append(ch)
            continue
        if len(word) >= 4:
            scripts = {_script_of(c) for c in word if ord(c) > 127} - _NOT_SUSPICIOUS_SCRIPTS
            has_ascii = any(ord(c) <= 127 for c in word)
            if scripts and has_ascii:
                findings.append(Finding(
                    rule_id="SC-U3", capability=Capability.OBFUSCATION, file=file_path,
                    start_line=_line_of(text, word_start), end_line=_line_of(text, word_start),
                    matched_text="".join(word)[:80], severity=Severity.MEDIUM,
                    rationale=f"Mixed-script token (ASCII + {'/'.join(sorted(scripts))} letters) "
                              "consistent with homoglyph spoofing.",
                    confidence=0.35, provenance=list(provenance), detector="unicode",
                ))
        word = []
    return findings
