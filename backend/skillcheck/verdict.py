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

    high_possible = [
        f for f in findings
        if f.tier in (Tier.POSSIBLE, Tier.LIKELY)
        and f.severity in (Severity.HIGH, Severity.CRITICAL)
    ]

    # Corroboration carries lower severities across the line: no single MEDIUM
    # finding should be able to convict alone, but a skill with several
    # independently-quiet signals is not a clean skill. Recall matters more
    # than precision here — false positives are tolerable, false negatives
    # are not (a missed multi-signal attack is worse than an extra review).
    distinct_medium_rules = {
        f.rule_id for f in findings
        if f.severity == Severity.MEDIUM and f.tier != Tier.FALSE_POSITIVE_SUSPECTED
    }
    corroborated_medium = len(distinct_medium_rules) >= 2

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
