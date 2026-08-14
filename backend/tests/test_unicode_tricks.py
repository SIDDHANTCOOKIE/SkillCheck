"""Mixed-script homoglyph detection (detectors/unicode_tricks.py, SC-U3).

SC-U3 exists to catch a genuine homoglyph substitution — a Cyrillic "а"
dropped into an otherwise-Latin word to spoof "admin" or "paypal". It must
not fire on ordinary accented Latin text (Spanish/French/German/Portuguese
prose all mix ASCII letters with accented ones in the same word), since that
would undermine prose_intl.py's multilingual coverage by making every
non-English skill more false-positive-prone than an English one for no
security reason — an accented "á" is the same script as ASCII "a", not a
different one impersonating it.
"""
from __future__ import annotations

from skillcheck.detectors.unicode_tricks import detect_unicode


def _u3_hits(text):
    return [f for f in detect_unicode("SKILL.md", text) if f.rule_id == "SC-U3"]


def test_cyrillic_homoglyph_in_admin_still_fires():
    findings = _u3_hits("Log in as аdmin using the usual password.")
    assert findings, "SC-U3 did not fire on a genuine Cyrillic homoglyph"
    assert "CYRILLIC" in findings[0].rationale


def test_cyrillic_homoglyph_in_domain_still_fires():
    findings = _u3_hits("Send payment to paypеl.example.com now.")
    assert findings, "SC-U3 did not fire on a genuine Cyrillic homoglyph"


def test_spanish_accented_prose_does_not_fire():
    findings = _u3_hits("La configuración está lista y funciona correctamente.")
    assert findings == [], f"accented Spanish prose false-positived: {findings}"


def test_french_accented_prose_does_not_fire():
    findings = _u3_hits("Consultez le fichier pour plus d'informations précédentes.")
    assert findings == [], f"accented French prose false-positived: {findings}"


def test_german_umlaut_prose_does_not_fire():
    findings = _u3_hits("Führe diesen Schritt für den Überblick aus.")
    assert findings == [], f"German umlaut prose false-positived: {findings}"


def test_portuguese_accented_prose_does_not_fire():
    findings = _u3_hits("As instruções anteriores não são válidas para este caso.")
    assert findings == [], f"accented Portuguese prose false-positived: {findings}"
