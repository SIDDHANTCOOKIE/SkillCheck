"""End-to-end orchestration. See spec §7 architecture diagram."""
from __future__ import annotations

from dataclasses import dataclass

from . import corroboration
from .adjudicator import adjudicate
from .coverage import build_ledger
from .decode import decode_cascade
from .detectors import ALL_DETECTORS
from .graph import build_capability_chains, build_component_graph
from .ingest import IngestResult, cleanup, ingest_path, ingest_text_blob
from .models import CapabilityChain, Capability, Finding, Severity, Verdict
from .osv_client import find_manifests, query_osv
from .parse_markdown import parse_document
from .report import annotate_attack_ids, to_json, to_markdown
from .verdict import decide_verdict

MAX_FILE_BYTES = 2_000_000
RULESET_VERSION = "2"  # bump whenever detector/scoring logic changes meaning of a cached report


@dataclass
class ScanResult:
    verdict: Verdict
    adjudicator_mode: str
    markdown: str
    json: str


def _run_detectors(rel_path: str, text: str, provenance: list[str] | None, failed_layers: list[str]) -> list[Finding]:
    """A single detector raising must not take down the other detectors or the
    scan (I1: every byte analysed or explicitly declared unanalysed). Each
    failure is named and surfaces as an SC-SCN1 finding so the verdict never
    reads cleaner than what actually ran."""
    findings: list[Finding] = []
    for name, fn in ALL_DETECTORS:
        try:
            findings.extend(fn(rel_path, text, provenance))
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
    return findings


def scan(source: str | None = None, *, text_blob: tuple[str, str] | None = None) -> ScanResult:
    """Scan a filesystem path / zip / tar / git URL, or a pasted (name, text) blob."""
    result: IngestResult
    if text_blob is not None:
        result = ingest_text_blob(*text_blob)
    else:
        assert source is not None
        result = ingest_path(source)

    try:
        return _scan_ingested(result)
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


def _scan_ingested(result: IngestResult) -> ScanResult:
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
            all_findings.extend(_run_detectors(f.rel_path, doc.prose, None, failed_layers))
            for cb in doc.code_blocks:
                all_findings.extend(_run_detectors(f.rel_path, cb.text, None, failed_layers))
            for hc in doc.html_comments:
                all_findings.extend(_run_detectors(f.rel_path, hc.text, None, failed_layers))
        else:
            all_findings.extend(_run_detectors(f.rel_path, text, None, failed_layers))

        decoded_spans = _scan_stage("decode", failed_layers, decode_cascade, text, default=[])
        for span in decoded_spans:
            all_findings.extend(_run_detectors(f.rel_path, span.text, span.encoding_chain, failed_layers))

    manifests = _scan_stage("dependency", failed_layers, find_manifests, file_texts, default={})
    all_findings.extend(_scan_stage("osv", failed_layers, query_osv, manifests, default=[]) or [])

    graph = _scan_stage("component-graph", failed_layers, build_component_graph, result.files, file_texts)
    if graph is None:
        from .graph import ComponentGraph
        graph = ComponentGraph(nodes={}, root=None)
    chains = _scan_stage("capability-graph", failed_layers, build_capability_chains, all_findings, graph, default=[])

    _scan_stage("corroborate-reputation", failed_layers, corroboration.corroborate_reputation, all_findings, file_texts)
    _scan_stage("corroborate-reachability", failed_layers, corroboration.corroborate_sink_reachability, all_findings, graph)
    _scan_stage("corroborate-chains", failed_layers, corroboration.corroborate_chains, chains)
    scope_mismatch = _scan_stage(
        "corroborate-scope", failed_layers, corroboration.corroborate_scope_mismatch,
        all_findings, frontmatter_by_file, default=False,
    )

    adjudicator_mode = _scan_stage("adjudicator", failed_layers, adjudicate, all_findings, chains, default="failed")

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
