"""Recursive decode cascade. See spec §7.2.

Finds base64 / hex / rot13 / zlib / gzip / url-encoded spans inside a text,
decodes them, and re-emits the decoded text as a `DecodedSpan` carrying full
provenance back to the original file/line so downstream detectors can flag
findings from decoded content without losing the evidence trail (I6).

`deobfuscate_text` below is a second, narrower producer for the same idea:
byte-level encodings aren't the only way a payload hides from the prose
detectors — a zero-width character split across "ignore" and "previous", or
a Cyrillic `е` standing in for a Latin one, reads as ordinary text to a human
and as ordinary bytes to `_BASE64_RE`/`_HEX_RE` above, so nothing in this
file's cascade ever touches it. Unlike the spans above, these transforms are
whole-document and (deliberately) preserve every newline, so the resulting
text can be handed straight to the same detectors with no offset bookkeeping
— see the call site in pipeline.py for why that's safe here specifically.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
import unicodedata
import urllib.parse
import zlib
from dataclasses import dataclass, field

MAX_DEPTH = 4
MIN_DECODE_LEN = 16

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){10,}(?![0-9a-fA-F])")
_URLENC_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")


@dataclass
class DecodedSpan:
    text: str
    encoding_chain: list[str]
    origin_start: int  # char offset in the immediate parent text
    origin_end: int
    origin_text: str  # the raw encoded span, for evidence
    depth: int


def _try_base64(s: str) -> str | None:
    try:
        raw = base64.b64decode(s, validate=True)
        decoded = raw.decode("utf-8")
        if decoded.isprintable() or "\n" in decoded:
            return decoded
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return None


def _try_hex(s: str) -> str | None:
    try:
        raw = bytes.fromhex(s)
        decoded = raw.decode("utf-8")
        if decoded.isprintable() or "\n" in decoded:
            return decoded
    except (ValueError, UnicodeDecodeError):
        return None
    return None


def _try_rot13(s: str) -> str | None:
    out = codecs.decode(s, "rot_13")
    return out if out != s else None


def _try_urlenc(s: str) -> str | None:
    try:
        out = urllib.parse.unquote(s)
        return out if out != s else None
    except Exception:
        return None


def _try_zlib_or_gzip(raw_bytes: bytes) -> str | None:
    for fn in (zlib.decompress, lambda b: gzip.decompress(b)):
        try:
            decoded = fn(raw_bytes).decode("utf-8")
            if decoded:
                return decoded
        except Exception:
            continue
    return None


def decode_cascade(text: str, _depth: int = 0, _chain: list[str] | None = None) -> list[DecodedSpan]:
    """Find and recursively decode candidate-encoded spans in `text`."""
    if _depth >= MAX_DEPTH:
        return []
    _chain = _chain or []
    results: list[DecodedSpan] = []

    candidates: list[tuple[re.Match, str, str]] = []
    for m in _BASE64_RE.finditer(text):
        candidates.append((m, "base64", m.group(0)))
    for m in _HEX_RE.finditer(text):
        candidates.append((m, "hex", m.group(0)))
    for m in _URLENC_RE.finditer(text):
        candidates.append((m, "url-encode", m.group(0)))

    for m, kind, raw in candidates:
        if len(raw) < MIN_DECODE_LEN:
            continue
        decoded = None
        if kind == "base64":
            decoded = _try_base64(raw)
            if decoded is None:
                try:
                    b = base64.b64decode(raw, validate=True)
                    z = _try_zlib_or_gzip(b)
                    if z:
                        decoded = z
                        kind = "base64+zlib"
                except Exception:
                    pass
        elif kind == "hex":
            decoded = _try_hex(raw)
        elif kind == "url-encode":
            decoded = _try_urlenc(raw)

        if not decoded:
            continue

        span = DecodedSpan(
            text=decoded,
            encoding_chain=_chain + [kind],
            origin_start=m.start(),
            origin_end=m.end(),
            origin_text=raw,
            depth=_depth + 1,
        )
        results.append(span)
        results.extend(decode_cascade(decoded, _depth + 1, span.encoding_chain))

    # rot13 has no reliable signature; only attempt on the whole text once,
    # and only keep it if it produces plausible ascii words.
    if _depth == 0:
        r = _try_rot13(text)
        if r and re.search(r"\b(curl|bash|import|eval|exec|http)\b", r, re.I):
            span = DecodedSpan(
                text=r, encoding_chain=["rot13"], origin_start=0,
                origin_end=len(text), origin_text=text[:200], depth=1,
            )
            results.append(span)
            results.extend(decode_cascade(r, 1, ["rot13"]))

    return results


# --- character-level de-obfuscation ------------------------------------

# Unicode tag block (U+E0000-U+E007F) spells ASCII by offsetting it +0xE0000
# from the printable range 0x20-0x7E; U+E007F is the CANCEL TAG that closes
# a run. A handful of tag chars is an ordinary emoji subdivision-flag
# sequence (England/Scotland/Wales flags spell a 2-3 letter region code this
# way) — only a run this long is a smuggled sentence rather than a flag.
_TAG_START, _TAG_END, _TAG_CANCEL = 0xE0020, 0xE007E, 0xE007F
_MIN_TAG_RUN = 12

# High-confidence single-glyph confusables: Cyrillic/Greek letters that are
# visually identical to a Latin one in most fonts, restricted to the letters
# actually used this way in the wild (package names, exfil domains) rather
# than a full confusables table — a broad table would fold real Cyrillic/
# Greek prose into mangled Latin and manufacture findings out of it.
HOMOGLYPH_MAP = {
    # Cyrillic -> Latin
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J",
    "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X",
    "У": "Y",
    # Greek -> Latin
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "ο": "o", "ν": "v",
}


def _zero_width_chars() -> frozenset:
    # Imported lazily rather than at module load: detectors/__init__.py pulls
    # in every detector module on import, and while none of them import this
    # file today, loading it lazily here means that stays an accident of the
    # current graph rather than a load-bearing fact this module depends on.
    from .detectors.unicode_tricks import ZERO_WIDTH
    return frozenset(ZERO_WIDTH)


def _strip_zero_width(text: str) -> tuple[str, bool]:
    zw = _zero_width_chars()
    if not any(c in zw for c in text):
        return text, False
    return "".join(c for c in text if c not in zw), True


def _fold_tag_chars(text: str) -> tuple[str, bool]:
    if not any(_TAG_START <= ord(c) <= _TAG_CANCEL for c in text if ord(c) >= _TAG_START):
        return text, False
    out: list[str] = []
    changed = False
    i, n = 0, len(text)
    while i < n:
        cp = ord(text[i])
        if _TAG_START <= cp <= _TAG_END:
            j = i
            spelled: list[str] = []
            while j < n and _TAG_START <= ord(text[j]) <= _TAG_END:
                spelled.append(chr(ord(text[j]) - 0xE0000))
                j += 1
            if j < n and ord(text[j]) == _TAG_CANCEL:
                j += 1
            if len(spelled) >= _MIN_TAG_RUN:
                # Fold to the ASCII it spells — never strip. A tag char
                # carries a letter, so removing it (rather than revealing
                # what it says) is how a tag-smuggled injection reaches
                # every downstream detector as a document the attack has
                # already been deleted from.
                out.append("".join(spelled))
                changed = True
            else:
                out.append(text[i:j])
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out), changed


def _fold_homoglyphs(text: str) -> tuple[str, bool]:
    nfkc = unicodedata.normalize("NFKC", text)
    folded = "".join(HOMOGLYPH_MAP.get(c, c) for c in nfkc)
    return folded, folded != text


def deobfuscate_text(text: str) -> tuple[str, list[str]] | None:
    """Whole-document character-level de-obfuscation: zero-width joins, tag-
    character smuggling, and homoglyph substitution. None of these are byte
    encodings `decode_cascade` above can find — they read as ordinary text
    to a human and as ordinary bytes to `_BASE64_RE`/`_HEX_RE`.

    Order matters and is not arbitrary: zero-width characters carry no
    content, so stripping them *reveals* the word they were splitting; tag
    characters carry a letter each, so they must be *folded* to what they
    spell, doing the strip step first would instead delete the sentence a
    tag run smuggles. NFKC/homoglyph folding runs last so it also normalizes
    whatever the first two steps exposed.

    Every step here preserves the newline count and position of `text`
    exactly (no step ever touches `\\n`), so the returned text can be handed
    straight to the ordinary line-counting detectors with no offset
    remapping — see pipeline.py's call site for why that's load-bearing.

    Returns `(deobfuscated_text, techniques)` naming which steps fired, or
    `None` if the text was unchanged by all three.
    """
    techniques: list[str] = []
    working = text

    stripped, changed = _strip_zero_width(working)
    if changed:
        working = stripped
        techniques.append("zero-width-join")

    folded_tags, changed = _fold_tag_chars(working)
    if changed:
        working = folded_tags
        techniques.append("tag-fold")

    folded_homoglyphs, changed = _fold_homoglyphs(working)
    if changed:
        working = folded_homoglyphs
        techniques.append("nfkc-homoglyph-fold")

    if not techniques:
        return None
    return working, techniques
