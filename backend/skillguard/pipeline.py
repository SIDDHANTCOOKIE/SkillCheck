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
from .models import CapabilityChain, Finding, Verdict
from .osv_client import find_manifests, query_osv
from .parse_markdown import parse_document
from .report import annotate_attack_ids, to_json, to_markdown
from .verdict import decide_verdict

MAX_FILE_BYTES = 2_000_000


@dataclass
class ScanResult:
    verdict: Verdict
    adjudicator_mode: str
    markdown: str
    json: str


def _run_detectors(rel_path: str, text: str, provenance: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for _name, fn in ALL_DETECTORS:
        findings.extend(fn(rel_path, text, provenance))
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


def _scan_ingested(result: IngestResult) -> ScanResult:
    file_texts: dict[str, str] = {}
    frontmatter_by_file: dict[str, dict] = {}
    analysed_paths: set[str] = set()
    all_findings: list[Finding] = []

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
            all_findings.extend(_run_detectors(f.rel_path, doc.prose))
            for cb in doc.code_blocks:
                all_findings.extend(_run_detectors(f.rel_path, cb.text))
            for hc in doc.html_comments:
                all_findings.extend(_run_detectors(f.rel_path, hc.text))
        else:
            all_findings.extend(_run_detectors(f.rel_path, text))

        for span in decode_cascade(text):
            all_findings.extend(_run_detectors(f.rel_path, span.text, span.encoding_chain))

    manifests = find_manifests(file_texts)
    all_findings.extend(query_osv(manifests))

    graph = build_component_graph(result.files, file_texts)
    chains = build_capability_chains(all_findings, graph)

    corroboration.corroborate_reputation(all_findings, file_texts)
    corroboration.corroborate_sink_reachability(all_findings, graph)
    corroboration.corroborate_chains(chains)
    scope_mismatch = corroboration.corroborate_scope_mismatch(all_findings, frontmatter_by_file)

    adjudicator_mode = adjudicate(all_findings, chains)

    ledger, coverage_pct = build_ledger(result.files, analysed_paths, graph, file_texts)

    verdict = decide_verdict(all_findings, chains, ledger, coverage_pct, graph, scope_mismatch)
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
