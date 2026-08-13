"""Verdict policy. See spec §10.

UNVERIFIED outranks NO_FINDINGS: a package we could not read is not a
package we cleared (I1/I3).
"""
from __future__ import annotations

from .graph import Chain, ComponentGraph
from .models import CoverageEntry, Finding, Severity, Tier, Verdict

COVERAGE_THRESHOLD = 90.0


def _has_runtime_fetch(graph: ComponentGraph) -> bool:
    return any(n.load_stage == "runtime" for n in graph.nodes.values())


def _direct_locality(graph: ComponentGraph, a: str, b: str) -> bool:
    """Same file, or a direct link/import edge — deliberately NOT the broader
    common-root reachability used for chain formation (graph.py). Two
    unrelated MEDIUM findings anywhere in a large reachable package
    shouldn't corroborate each other; two in the same file, or one linking
    to the other, should (2.5)."""
    if a == b:
        return True
    na = graph.nodes.get(a)
    nb = graph.nodes.get(b)
    if na and b in na.edges_out:
        return True
    if nb and a in nb.edges_out:
        return True
    return False


def _has_corroborated_medium(findings: list[Finding], graph: ComponentGraph) -> bool:
    mediums = [
        f for f in findings
        if f.severity == Severity.MEDIUM and f.tier != Tier.FALSE_POSITIVE_SUSPECTED
    ]
    for i, a in enumerate(mediums):
        for b in mediums[i + 1:]:
            if a.rule_id != b.rule_id and _direct_locality(graph, a.file, b.file):
                return True
    return False


def _coverage_summary(ledger: list[CoverageEntry], pct: float) -> str:
    analysed = sum(1 for e in ledger if e.status == "analysed")
    partial = sum(1 for e in ledger if e.status == "partial")
    unanalysed = [e for e in ledger if e.status == "unanalysed"]
    total = len(ledger)
    parts = [f"{analysed}/{total} files fully analysed"]
    if partial:
        parts.append(f"{partial} partially analysed")
    if unanalysed:
        reasons = ", ".join(f"1 {e.reason}" for e in unanalysed[:6])
        parts.append(f"{len(unanalysed)} files unanalysed ({reasons})")
    return f"{pct}% coverage — " + "; ".join(parts) + "."


def decide_verdict(
    findings: list[Finding],
    chains: list[Chain],
    ledger: list[CoverageEntry],
    coverage_pct: float,
    graph: ComponentGraph,
    scope_mismatch: bool,
) -> Verdict:
    coverage_note = _coverage_summary(ledger, coverage_pct)

    confirmed_chain = [f for f in findings if f.tier == Tier.CONFIRMED and f.chain_id]
    confirmed_critical = [f for f in findings if f.tier == Tier.CONFIRMED and f.severity == Severity.CRITICAL]

    likely_chain = [f for f in findings if f.tier == Tier.LIKELY and f.chain_id]
    likely_isolated_risk = [
        f for f in findings
        if f.tier in (Tier.LIKELY, Tier.CONFIRMED)
        and f.capability.value in ("anti_forensics", "persistence", "agent_manipulation")
    ]

    # CONFIRMED belongs here too: a HIGH-severity finding the adjudicator
    # called "clear evidence of intent to harm" must be at least as
    # suspicious as an uncorroborated POSSIBLE/LIKELY one of the same
    # severity. Omitting it meant a *more* confident verdict from the judge
    # could land on a *lower* label than a less confident one — being more
    # confident made the label better (P1-7).
    high_possible = [
        f for f in findings
        if f.tier in (Tier.POSSIBLE, Tier.LIKELY, Tier.CONFIRMED)
        and f.severity in (Severity.HIGH, Severity.CRITICAL)
    ]

    # Corroboration carries lower severities across the line: no single MEDIUM
    # finding should be able to convict alone, but two independently-quiet
    # signals *local to each other* (same file, or one linking to the other)
    # are not a clean skill. Locality matters: two unrelated MEDIUM findings
    # scattered anywhere in a large package are much weaker evidence than two
    # in the same file, so this requires proximity, not just quantity (2.5).
    # Recall still matters more than precision here — false positives are
    # tolerable, false negatives are not.
    corroborated_medium = _has_corroborated_medium(findings, graph)

    runtime_fetch = _has_runtime_fetch(graph)

    if confirmed_chain or confirmed_critical:
        label = "MALICIOUS"
        summary = (
            f"MALICIOUS — {len(confirmed_chain) + len(confirmed_critical)} confirmed finding(s) "
            f"with corroborated evidence of intent to harm. {coverage_note}"
        )
    elif likely_chain or likely_isolated_risk:
        label = "DANGEROUS"
        summary = (
            f"DANGEROUS — capability chain or high-risk behaviour present, intent not fully confirmed. "
            f"{coverage_note}"
        )
    elif high_possible or scope_mismatch or corroborated_medium:
        label = "SUSPICIOUS"
        reason = (
            "two or more independent medium-severity findings corroborate each other"
            if corroborated_medium and not (high_possible or scope_mismatch)
            else "uncorroborated high-severity finding(s) or declared-vs-demanded scope mismatch present"
        )
        summary = f"SUSPICIOUS — {reason}. {coverage_note}"
    elif coverage_pct < COVERAGE_THRESHOLD or runtime_fetch:
        label = "UNVERIFIED"
        extra = " Runtime-fetched content is in the reachable set and cannot be statically cleared." if runtime_fetch else ""
        summary = f"UNVERIFIED — coverage below threshold or content only resolvable at runtime.{extra} {coverage_note}"
    else:
        label = "NO_FINDINGS"
        summary = f"NO FINDINGS — {coverage_note}"

    return Verdict(
        label=label,
        coverage_pct=coverage_pct,
        findings=findings,
        ledger=ledger,
        summary=summary,
        chains=[],
    )
