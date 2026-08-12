"""Frontmatter + lightweight markdown structural split.

We don't need a full CommonMark parser — we need to reliably separate a
document into: YAML frontmatter, fenced code blocks (with language), HTML
comments, prose, and link targets, each tagged with line ranges so findings
carry accurate evidence spans (I6).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?\n)---\s*\n", re.DOTALL)
_FENCE_RE = re.compile(r"^```([\w+-]*)\s*\n(.*?)\n```", re.DOTALL | re.MULTILINE)
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
_BARE_URL_RE = re.compile(r"(?<![\(\[])\bhttps?://[^\s)>\]\"']+")


@dataclass
class CodeBlock:
    language: str
    text: str
    start_line: int
    end_line: int


@dataclass
class HtmlComment:
    text: str
    start_line: int
    end_line: int


@dataclass
class LinkTarget:
    label: str
    target: str
    line: int


@dataclass
class ParsedDocument:
    frontmatter: dict
    # frontmatter/fences/comments blanked out but newline-count preserved, so a
    # line number computed by counting "\n" within `prose` is *already* the
    # correct 1-based line number in `raw` — no offset needed at the call site.
    prose: str
    code_blocks: list[CodeBlock]
    html_comments: list[HtmlComment]
    links: list[LinkTarget]
    raw: str


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def parse_document(raw: str) -> ParsedDocument:
    frontmatter: dict = {}
    body = raw
    fm_match = _FRONTMATTER_RE.match(raw)
    if fm_match:
        fm_text = fm_match.group(1)
        if yaml is not None:
            try:
                loaded = yaml.safe_load(fm_text)
                if isinstance(loaded, dict):
                    frontmatter = loaded
            except Exception:
                frontmatter = {"_parse_error": True}
        body = raw[fm_match.end():]
        body_offset = fm_match.end()
    else:
        body_offset = 0

    code_blocks: list[CodeBlock] = []
    for m in _FENCE_RE.finditer(body):
        start = _line_of(raw, body_offset + m.start())
        end = _line_of(raw, body_offset + m.end())
        code_blocks.append(CodeBlock(m.group(1) or "text", m.group(2), start, end))

    html_comments: list[HtmlComment] = []
    for m in _HTML_COMMENT_RE.finditer(body):
        start = _line_of(raw, body_offset + m.start())
        end = _line_of(raw, body_offset + m.end())
        html_comments.append(HtmlComment(m.group(1), start, end))

    links: list[LinkTarget] = []
    for m in _LINK_RE.finditer(body):
        line = _line_of(raw, body_offset + m.start())
        links.append(LinkTarget(m.group(1), m.group(2), line))
    for m in _BARE_URL_RE.finditer(body):
        if any(m.group(0) == l.target for l in links):
            continue
        line = _line_of(raw, body_offset + m.start())
        links.append(LinkTarget(m.group(0), m.group(0), line))

    def _blank(match: re.Match) -> str:
        # Preserve newline count so every remaining line keeps its true line
        # number in `raw` — deleting the span outright (the old behaviour)
        # shifted every subsequent line's offset arbitrarily (I6).
        return "\n" * match.group(0).count("\n")

    prose_body = _FENCE_RE.sub(_blank, body)
    prose_body = _HTML_COMMENT_RE.sub(_blank, prose_body)
    # Re-attach a blanked frontmatter block (if any) so `prose` has the same
    # total line count as `raw` and needs no offset at the call site.
    frontmatter_blank = "\n" * raw[:body_offset].count("\n") if fm_match else ""
    prose = frontmatter_blank + prose_body

    return ParsedDocument(
        frontmatter=frontmatter,
        prose=prose,
        code_blocks=code_blocks,
        html_comments=html_comments,
        links=links,
        raw=raw,
    )
