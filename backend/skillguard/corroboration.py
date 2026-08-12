"""Deterministic corroboration layer. See spec §7, table row "deterministic
corroboration layer (scope mismatch, sink reachability, reputation)".

This layer only ever *raises* confidence and *annotates* rationale; it never
removes a finding (I2). Its output feeds the adjudicator as evidence, not as
a filter.
"""
from __future__ import annotations

import re

from .graph import Chain, ComponentGraph
from .models import Finding

# Known exfiltration / anonymous-hosting sinks — corroborates SG-P8/SG-SH3/SG-SH4.
KNOWN_BAD_DOMAINS = [
    "webhook.site", "pastebin.com", "ngrok.io", "ngrok-free.app", "requestbin.com",
    "discord.com/api/webhooks", "discordapp.com/api/webhooks", "transfer.sh",
    "file.io", "0x0.st", "anonfiles.com", "pipedream.net",
]

_URL_RE = re.compile(r"https?://[^\s)\"'>]+")


def _mentions_known_bad_domain(text: str) -> str | None:
    for dom in KNOWN_BAD_DOMAINS:
        if dom in text:
            return dom
    return None


def corroborate_reputation(findings: list[Finding], full_text_by_file: dict[str, str]) -> None:
    """Bump confidence when a finding's file also references a known-bad domain."""
    for f in findings:
        text = full_text_by_file.get(f.file, "")
        dom = _mentions_known_bad_domain(f.matched_text) or _mentions_known_bad_domain(text)
        if dom and f.capability.value in ("exfiltration", "stage2_fetch"):
            f.confidence = min(1.0, f.confidence + 0.25)
            f.rationale += f" [corroborated: file references known exfil/anon-hosting domain '{dom}']"


def corroborate_scope_mismatch(findings: list[Finding], frontmatter_by_file: dict[str, dict]) -> bool:
    """Flag skills whose declared tools/scope don't cover the capabilities they
    actually demand (declared-vs-demanded mismatch). Returns True if any
    mismatch was found."""
    found_mismatch = False
    for path, fm in frontmatter_by_file.items():
        declared = fm.get("allowed-tools") or fm.get("allowed_tools") or fm.get("tools")
        if declared is None:
            continue
        declared_str = str(declared).lower()
        risky_here = [f for f in findings if f.file == path and f.severity.value in ("high", "critical")]
        for f in risky_here:
            needs_net = f.capability.value in ("exfiltration", "stage2_fetch") and "network" not in declared_str and "web" not in declared_str and "bash" not in declared_str
            needs_exec = f.capability.value == "hidden_execution" and "bash" not in declared_str and "shell" not in declared_str and "exec" not in declared_str
            if needs_net or needs_exec:
                f.confidence = min(1.0, f.confidence + 0.2)
                f.rationale += " [corroborated: capability used is not covered by declared allowed-tools scope]"
                found_mismatch = True
    return found_mismatch


def corroborate_sink_reachability(findings: list[Finding], graph: ComponentGraph) -> None:
    """Findings in files unreachable from SKILL.md are still reported (I1) but
    are annotated — they need a human/LLM judgment on whether they're live."""
    for f in findings:
        node = graph.nodes.get(f.file)
        if node and not node.reachable_from_root and graph.root:
            f.rationale += " [note: file is not statically reachable from SKILL.md — reachability unconfirmed]"


def corroborate_chains(chains: list[Chain]) -> None:
    for c in chains:
        if c.same_file:
            c.source.confidence = min(1.0, c.source.confidence + 0.15)
            c.sink.confidence = min(1.0, c.sink.confidence + 0.15)
        elif c.connected_via_graph:
            c.source.confidence = min(1.0, c.source.confidence + 0.1)
            c.sink.confidence = min(1.0, c.sink.confidence + 0.1)
