"""Recursive decode cascade. See spec §7.2.

Finds base64 / hex / rot13 / zlib / gzip / url-encoded spans inside a text,
decodes them, and re-emits the decoded text as a `DecodedSpan` carrying full
provenance back to the original file/line so downstream detectors can flag
findings from decoded content without losing the evidence trail (I6).
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
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
