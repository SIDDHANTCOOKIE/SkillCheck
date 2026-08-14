"""Regression test for I6 (exact quoted span): for every finding produced by
scanning the red corpus, `matched_text` must actually be found at the line(s)
`start_line`-`end_line` claims, in the real file on disk — not in some
fragment-relative line number that only made sense to the detector that
produced it. This is the direct check the eval-strengthening plan calls for
in Phase 2.1.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from skillcheck.pipeline import scan

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Findings with no single real source line to check against.
SKIP_RULES = {"SC-SCN1", "SC-OSV1"}
# A decoded finding's matched_text is synthetic (it only exists after decoding);
# it is deliberately anchored to the *origin* line (where the encoded blob
# sits), not to a line that would literally contain the decoded string (2.1).
DECODE_TAGS = {"base64", "hex", "rot13", "url-encode", "base64+zlib"}
# A de-obfuscated finding's matched_text is the *de-obfuscated* string (e.g.
# the word a zero-width character was splitting, joined) — it only exists
# after decode.py's deobfuscate_text() runs, so it's exempt from the literal
# window-containment check the same way a decoded finding is, but it needs
# no separate origin-line anchoring: unlike a decode_cascade span, the
# de-obfuscated text keeps every newline of the original file in the exact
# same place (see deobfuscate_text's docstring), so start_line already
# points at the real source line — just not at text you'd find there
# byte-for-byte, since the whole point was that it isn't there byte-for-byte.
DEOBFUSCATION_TAGS = {"zero-width-join", "tag-fold", "nfkc-homoglyph-fold"}


def _targets():
    for base in (FIXTURES / "red", FIXTURES / "benign"):
        for p in sorted(base.iterdir()):
            yield p


@pytest.mark.parametrize("target", list(_targets()), ids=lambda p: p.name)
def test_finding_spans_match_real_source_lines(target: Path):
    result = scan(str(target))
    root = target if target.is_dir() else target.parent

    for f in result.verdict.findings:
        if f.rule_id in SKIP_RULES:
            continue
        source_path = root / f.file
        if not source_path.is_file():
            # e.g. a finding anchored to a file the ingest walk didn't resolve
            # to this exact relative path structure — not what this test checks.
            continue

        raw = source_path.read_text(encoding="utf-8", errors="replace")
        lines = raw.splitlines()
        if not (1 <= f.start_line <= len(lines)):
            pytest.fail(
                f"{f.rule_id} in {f.file}: start_line={f.start_line} is out of range "
                f"for a {len(lines)}-line file"
            )

        window = "\n".join(lines[f.start_line - 1: f.end_line])
        first_line = f.matched_text.split("\n", 1)[0].strip()
        # Some detectors report a synthetic description rather than a literal
        # source excerpt (e.g. unicode codepoint names), and a decoded
        # finding's text only exists post-decode — both are exempt from
        # literal containment but still had their line-range bounds checked above.
        # A structure finding's matched_text is a synthesized description of a
        # structural fact (a hook's event+command, a permission grant, an MCP
        # server's address) rather than a literal excerpt of the file at a
        # specific line — the file is JSON, not prose, and the fact it
        # describes has no single source line to quote (I6 exempts it the
        # same way a unicode codepoint name is exempt below).
        if f.detector in ("unicode", "structure") or (
            f.provenance and any(t in DECODE_TAGS or t in DEOBFUSCATION_TAGS for t in f.provenance)
        ):
            continue

        assert first_line[:60] in window or window.strip() in f.matched_text, (
            f"{f.rule_id} in {f.file}:{f.start_line}-{f.end_line} — matched_text "
            f"{f.matched_text[:80]!r} not found in source window {window[:120]!r}"
        )
