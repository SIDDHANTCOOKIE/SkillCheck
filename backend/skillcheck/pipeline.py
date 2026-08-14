"""End-to-end orchestration. See spec §7 architecture diagram."""
from __future__ import annotations

import ast
from dataclasses import dataclass

from . import corroboration
from .adjudicator import adjudicate, semantic_scan
from .coverage import build_ledger
from .decode import decode_cascade, deobfuscate_text
from .detectors import ALL_DETECTORS
from .graph import build_capability_chains, build_component_graph, mark_unattended_nodes
from .ingest import IngestResult, cleanup, ingest_path, ingest_text_blob
from .models import CapabilityChain, Capability, Finding, Severity, Verdict
from .osv_client import find_manifests, query_osv
from .parse_markdown import parse_document
from .report import annotate_attack_ids, to_json, to_markdown
from .structure import detect_structure
from .verdict import decide_verdict

MAX_FILE_BYTES = 2_000_000
RULESET_VERSION = "3"  # bump whenever detector/scoring logic changes meaning of a cached report


@dataclass
class ScanResult:
    verdict: Verdict
    adjudicator_mode: str
    markdown: str
    json: str


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _looks_like_python(text: str) -> bool:
    """A decoded payload with no filename to key off — parse it and see (2.2)."""
    stripped = text.strip()
    if not stripped:
        return False
    try:
        ast.parse(stripped)
    except (SyntaxError, ValueError, RecursionError):
        return False
    return True


def _run_detectors(
    rel_path: str,
    text: str,
    provenance: list[str] | None,
    failed_layers: list[str],
    *,
    line_offset: int = 0,
    lang_hint: str | None = None,
) -> list[Finding]:
    """A single detector raising must not take down the other detectors or the
    scan (I1: every byte analysed or explicitly declared unanalysed). Each
    failure is named and surfaces as an SC-SCN1 finding so the verdict never
    reads cleaner than what actually ran.

    `line_offset` corrects a finding's start/end line from "line N within the
    fragment handed to the detector" to "line N in the actual file" (I6) —
    the fragment (prose/code-block/html-comment/decoded span) is rarely the
    whole file. `lang_hint` lets a fenced code block reach the AST detector
    even though its file path ends in `.md`, not `.py`.
    """
    findings: list[Finding] = []
    for name, fn in ALL_DETECTORS:
        try:
            if name == "code" and lang_hint == "python":
                new = fn(rel_path, text, provenance, lang_override="python")
            else:
                new = fn(rel_path, text, provenance)
        except Exception as e:  # noqa: BLE001 - one detector's bug can't sink the scan
            tag = f"{name}:{rel_path}"
            if tag not in failed_layers:
                failed_layers.append(tag)
                findings.append(Finding(
                    rule_id="SC-SCN1",
                    capability=Capability.UNKNOWN,
                    file=rel_path,
                    start_line=1,
                    end_line=1,
                    matched_text=f"<{name} detector raised: {e}>",
                    severity=Severity.MEDIUM,
                    rationale=(
                        f"The '{name}' detection layer raised an exception on this file and produced "
                        "no findings for it. Whatever it would have found is missing from this report, "
                        "not missing from the skill — treat the verdict as a floor, not a complete result."
                    ),
                    confidence=1.0,
                    detector="scan-integrity",
                ))
            continue
        if line_offset:
            for f in new:
                f.start_line += line_offset
                f.end_line += line_offset
        findings.extend(new)
    return findings


def scan(
    source: str | None = None, *, text_blob: tuple[str, str] | None = None,
    llm_override: tuple[str, str] | None = None,
) -> ScanResult:
    """Scan a filesystem path / zip / tar / git URL, or a pasted (name, text) blob.

    `llm_override` is an optional caller-supplied (provider, api_key) — see
    adjudicator._resolve_provider() — for a bring-your-own-key request."""
    result: IngestResult
    if text_blob is not None:
        result = ingest_text_blob(*text_blob)
    else:
        assert source is not None
        result = ingest_path(source)

    try:
        return _scan_ingested(result, llm_override=llm_override)
    finally:
        cleanup(result)


def _scan_stage(name: str, failed_layers: list[str], fn, *args, default=None):
    """Run one pipeline stage; on failure, name it, record it, and return a
    safe default instead of taking the whole scan down with it."""
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001 - a stage's bug can't sink the scan (I1)
        failed_layers.append(f"{name}: {e}")
        return default


def _scan_ingested(result: IngestResult, *, llm_override: tuple[str, str] | None = None) -> ScanResult:
    file_texts: dict[str, str] = {}
    frontmatter_by_file: dict[str, dict] = {}
    analysed_paths: set[str] = set()
    all_findings: list[Finding] = []
    failed_layers: list[str] = []

    for f in result.files:
        if f.is_binary or not f.is_text:
            continue
        if f.size > MAX_FILE_BYTES:
            continue
        try:
            text = f.abs_path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue

        file_texts[f.rel_path] = text
        analysed_paths.add(f.rel_path)

        if f.rel_path.lower().endswith((".md", ".markdown")):
            doc = parse_document(text)
            frontmatter_by_file[f.rel_path] = doc.frontmatter
            if doc.frontmatter_raw:
                # `description:` is the field an agent runtime always loads —
                # previously this text was parsed only into a dict for the
                # scope-mismatch check and handed to no detector at all, so a
                # payload here scored NO_FINDINGS regardless of content.
                all_findings.extend(_run_detectors(
                    f.rel_path, doc.frontmatter_raw, ["frontmatter"], failed_layers,
                    line_offset=doc.frontmatter_line_offset,
                ))
            # prose is blanked-but-newline-preserving (see parse_markdown.py), so
            # its own line numbers already match the raw file — no offset needed.
            all_findings.extend(_run_detectors(f.rel_path, doc.prose, ["prose"], failed_layers))
            for cb in doc.code_blocks:
                # cb.start_line is the line of the opening ``` fence; the fenced
                # content's own line 1 is the line right after it.
                lang = (cb.language or "").lower()
                lang_hint = "python" if lang in ("python", "py", "python3") else None
                all_findings.extend(_run_detectors(
                    f.rel_path, cb.text, [f"code-block:{cb.language or 'text'}"], failed_layers,
                    line_offset=cb.start_line, lang_hint=lang_hint,
                ))
            for hc in doc.html_comments:
                # hc.start_line is the line "<!--" opens on; the comment body's
                # own line 1 begins on that same line.
                all_findings.extend(_run_detectors(
                    f.rel_path, hc.text, ["html-comment"], failed_layers,
                    line_offset=hc.start_line - 1,
                ))
        else:
            lang_hint = "python" if f.rel_path.lower().endswith(".py") else None
            all_findings.extend(_run_detectors(f.rel_path, text, ["file"], failed_layers, lang_hint=lang_hint))

        decoded_spans = _scan_stage("decode", failed_layers, decode_cascade, text, default=[])
        for span in decoded_spans:
            origin_line = _line_of(text, span.origin_start)
            span_lang = "python" if _looks_like_python(span.text) else None
            decoded = _run_detectors(
                f.rel_path, span.text, span.encoding_chain, failed_layers, lang_hint=span_lang,
            )
            # A decoded payload's internal newlines don't correspond to real
            # lines in the file it was extracted from — anchor every finding
            # from it to the line where the encoded blob itself appears (I6),
            # rather than reporting a line number that only exists in the
            # ephemeral decoded text.
            for f_ in decoded:
                f_.start_line = origin_line
                f_.end_line = origin_line
            all_findings.extend(decoded)

        # Character-level de-obfuscation: zero-width joins, tag-character
        # smuggling, homoglyph substitution. Unlike the byte-encoding spans
        # above, this transform touches the whole file and — by construction
        # (decode.py's deobfuscate_text docstring) — never adds or removes a
        # newline, so the result lines up with the original file 1:1 and can
        # go straight through the same line-counting detectors with no
        # offset correction, the same way the plain-file branch above does.
        # The raw text is still scanned everywhere above this — de-obfuscating
        # only ever adds findings the raw pass couldn't see; it never
        # replaces the SC-U1/SC-U2/SC-U3 findings that fire on the hidden
        # characters themselves.
        deobfuscated = _scan_stage("deobfuscate", failed_layers, deobfuscate_text, text, default=None)
        if deobfuscated:
            deob_text, techniques = deobfuscated
            all_findings.extend(_run_detectors(f.rel_path, deob_text, techniques, failed_layers))

    manifests = _scan_stage("dependency", failed_layers, find_manifests, file_texts, default={})
    all_findings.extend(_scan_stage("osv", failed_layers, query_osv, manifests, default=[]) or [])

    graph_result = _scan_stage("component-graph", failed_layers, build_component_graph, result.files, file_texts)
    if graph_result is None:
        from .graph import ComponentGraph
        graph, unresolved_refs = ComponentGraph(nodes={}, root=None), []
    else:
        graph, unresolved_refs = graph_result
    # Config-as-code: hooks, permission grants, bundled MCP servers, subagent
    # definitions, and unreferenced scripts. Package-level rather than a
    # per-fragment detector, so it runs as its own stage once the component
    # graph (needed for SC-ST5's reachability check) exists.
    structure_findings = _scan_stage(
        "structure", failed_layers, detect_structure,
        result.files, file_texts, graph, default=[],
    ) or []
    # A single unparseable manifest surfaces as its own SC-SCN1 finding
    # rather than raising (one bad settings.json shouldn't take down hook/
    # permission/MCP detection for every other file in the bundle) — but
    # that means it never reaches the try/except in _scan_stage, so nothing
    # would otherwise record it in failed_layers. Without this, a skill
    # whose *only* structural fact is "this config didn't parse" scored
    # NO_FINDINGS instead of the UNVERIFIED the rest of the scanner promises
    # for content it couldn't read (I1/I3).
    for f in structure_findings:
        if f.rule_id == "SC-SCN1" and f.detector == "structure":
            tag = f"structure-manifest:{f.file}"
            if tag not in failed_layers:
                failed_layers.append(tag)
    all_findings.extend(structure_findings)
    # A hook/MCP-server/subagent/permission-bypass/install-time-exec finding
    # names a file that runs (or is granted) with nothing deciding — one rung
    # past "immediate" on the load_stage ladder. Must run after structure
    # detection and before anything below reads load_stage.
    mark_unattended_nodes(graph, structure_findings)

    for ref in unresolved_refs:
        origin_line = _line_of(file_texts[ref.file], ref.offset)
        all_findings.append(Finding(
            rule_id="SC-REF1",
            capability=Capability.UNSCANNED_REFERENCE,
            file=ref.file,
            start_line=origin_line,
            end_line=origin_line,
            matched_text=ref.target,
            severity=Severity.MEDIUM,
            rationale=(
                f"This document references '{ref.target}', but no file at that path was "
                "part of this scan. This scan cannot clear content it never saw — resubmit "
                "as the full package (zip or repo URL), not just this one file, for a "
                "verdict that accounts for it."
            ),
            confidence=1.0,
            detector="component-graph",
        ))
    # Independent LLM read of the raw prose, regardless of what the
    # deterministic layer above found — closes the gap where a skill using
    # no literal known-bad keyword scores NO_FINDINGS and adjudicate() below
    # never even runs (it only ranks findings that already exist; given zero
    # it returns immediately). A no-op with zero cost when no LLM provider
    # is configured (semantic_scan() returns [] cleanly) or a request never
    # brought its own key. Skipped once a CRITICAL finding already exists —
    # the verdict is already at its ceiling, so spending the call adds cost
    # without adding information.
    #
    # `heightened=not all_findings`: when every rule/AST/structure layer that
    # ran before this point found literally nothing, this pass is the only
    # review the package gets before a clean verdict — see
    # SEMANTIC_HEIGHTENED_SUFFIX in adjudicator.py.
    if not any(f.severity == Severity.CRITICAL for f in all_findings):
        semantic_findings = _scan_stage(
            "semantic-pass", failed_layers,
            lambda: semantic_scan(file_texts, llm_override, heightened=not all_findings),
            default=[],
        )
        all_findings.extend(semantic_findings or [])

    chains = _scan_stage("capability-graph", failed_layers, build_capability_chains, all_findings, graph, default=[])

    _scan_stage("corroborate-provenance", failed_layers, corroboration.corroborate_provenance, all_findings)
    _scan_stage("corroborate-reputation", failed_layers, corroboration.corroborate_reputation, all_findings, file_texts)
    _scan_stage("corroborate-reachability", failed_layers, corroboration.corroborate_sink_reachability, all_findings, graph)
    _scan_stage("corroborate-chains", failed_layers, corroboration.corroborate_chains, chains, graph)
    scope_mismatch = _scan_stage(
        "corroborate-scope", failed_layers, corroboration.corroborate_scope_mismatch,
        all_findings, frontmatter_by_file, default=False,
    )

    adjudicator_mode = _scan_stage(
        "adjudicator", failed_layers, adjudicate, all_findings, chains, file_texts, llm_override, default="failed",
    )

    ledger, coverage_pct = _scan_stage(
        "coverage", failed_layers, build_ledger, result.files, analysed_paths, graph, file_texts,
        default=([], 0.0),
    )

    if failed_layers:
        names = sorted({layer.split(":")[0] for layer in failed_layers})
        all_findings.append(Finding(
            rule_id="SC-SCN1",
            capability=Capability.UNKNOWN,
            file="<scan>",
            start_line=1,
            end_line=1,
            matched_text=f"failed layers: {', '.join(names)}",
            severity=Severity.MEDIUM,
            rationale=(
                f"{len(failed_layers)} pipeline stage(s) raised and produced nothing: {', '.join(names)}. "
                "Whatever they would have found is missing from this report, not missing from the skill — "
                "treat this verdict as a floor, not a complete result."
            ),
            confidence=1.0,
            detector="scan-integrity",
        ))

    verdict = decide_verdict(all_findings, chains, ledger, coverage_pct, graph, scope_mismatch)
    if failed_layers and verdict.label == "NO_FINDINGS":
        verdict.label = "UNVERIFIED"
        verdict.summary = (
            f"UNVERIFIED — {len(failed_layers)} pipeline stage(s) did not complete, so a clean result "
            f"cannot be claimed. {verdict.summary}"
        )
    verdict.chains = [
        CapabilityChain(
            chain_id=c.chain_id,
            finding_ids=[c.source.rule_id, c.sink.rule_id],
            description=f"{c.source.rule_id} -> {c.sink.rule_id}",
            corroborated=c.same_file or c.connected_via_graph,
        )
        for c in chains
    ]
    annotate_attack_ids(verdict)

    md = to_markdown(verdict, adjudicator_mode, chains)
    js = to_json(verdict, adjudicator_mode, chains)
    return ScanResult(verdict=verdict, adjudicator_mode=adjudicator_mode, markdown=md, json=js)
