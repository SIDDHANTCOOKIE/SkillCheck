"""Phase 1.4: determinism and scan-integrity checks. Cheap, high-value, and
previously entirely absent — these exercise pipeline machinery (SC-SCN1,
the NO_FINDINGS->UNVERIFIED downgrade, the chain-cap) that existed in code
but had never actually been triggered by a test.
"""
from __future__ import annotations

import time
from pathlib import Path

import skillcheck.detectors as detectors_pkg
from skillcheck.graph import ComponentGraph, ComponentNode, MAX_CHAIN_PAIRS, build_capability_chains
from skillcheck.models import Capability, Finding, Severity, Tier
from skillcheck.pipeline import scan

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_scan_is_idempotent(monkeypatch):
    """Scanning the same target twice, with no LLM key so the adjudicator
    takes its deterministic path, must produce byte-identical JSON. This
    guards against ordering nondeterminism (e.g. a `set` iterated instead of
    membership-tested) leaking into the report."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    target = str(FIXTURES / "red" / "obj6_anti_forensics.sh")
    first = scan(target).json
    second = scan(target).json
    assert first == second


def test_detector_failure_surfaces_as_finding_and_forces_unverified(monkeypatch):
    """A detector that raises must not crash the scan (I1), must be named in
    an SC-SCN1 finding, and must stop a would-be-clean scan from reading as
    NO_FINDINGS — the whole point of the failure-containment code path in
    pipeline.py."""
    def _boom(*_args, **_kwargs):
        raise RuntimeError("synthetic detector failure")

    broken = [(name, _boom if name == "prose" else fn) for name, fn in detectors_pkg.ALL_DETECTORS]
    monkeypatch.setattr("skillcheck.pipeline.ALL_DETECTORS", broken)

    # A benign fixture that would otherwise be NO_FINDINGS.
    result = scan(str(FIXTURES / "benign" / "translation_skill.md"))

    scn_findings = [f for f in result.verdict.findings if f.rule_id == "SC-SCN1"]
    assert scn_findings, "expected an SC-SCN1 finding when a detector raises"
    assert "prose" in scn_findings[0].matched_text or "prose" in scn_findings[0].rationale
    assert result.verdict.label == "UNVERIFIED", (
        f"a scan with a failed detection layer must never read as NO_FINDINGS "
        f"(I1/I3); got {result.verdict.label}"
    )


def test_capability_chain_cross_product_is_bounded():
    """1.4 chain-explosion: a pathological finding count must not make chain
    building unbounded, and must still complete quickly."""
    graph = ComponentGraph(nodes={}, root="SKILL.md")

    def _mk(i: int, cap: Capability, file: str) -> Finding:
        return Finding(
            rule_id=f"SYN-{i}", capability=cap, file=file, start_line=1, end_line=1,
            matched_text="synthetic", severity=Severity.HIGH, rationale="synthetic",
            tier=Tier.POSSIBLE,
        )

    n_sources, n_sinks = 200, 200
    findings = (
        [_mk(i, Capability.CREDENTIAL_ACCESS, f"src{i}.md") for i in range(n_sources)]
        + [_mk(i, Capability.EXFILTRATION, f"sink{i}.md") for i in range(n_sinks)]
    )
    for f in findings:
        graph.nodes[f.file] = ComponentNode(path=f.file, reachable_from_root=True, load_stage="on-demand")

    assert n_sources * n_sinks > MAX_CHAIN_PAIRS, "test setup should actually exceed the cap"

    t0 = time.time()
    chains = build_capability_chains(findings, graph)
    elapsed = time.time() - t0

    assert elapsed < 5.0, f"chain building took {elapsed:.1f}s on a bounded input — cap isn't working"
    assert len(chains) <= MAX_CHAIN_PAIRS
