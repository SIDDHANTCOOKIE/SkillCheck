"""Evidence report rendering: markdown + JSON. See spec §1, §13 Day 3."""
from __future__ import annotations

import json

from .graph import Chain
from .models import Verdict

ATTACK_TECHNIQUE = {
    "credential_access": "T1552 (Unsecured Credentials)",
    "exfiltration": "T1041 (Exfiltration Over C2 Channel)",
    "hidden_execution": "T1059 (Command and Scripting Interpreter)",
    "stage2_fetch": "T1105 (Ingress Tool Transfer)",
    "persistence": "T1547 (Boot or Logon Autostart Execution)",
    "anti_forensics": "T1070.003 (Clear Command History)",
    "agent_manipulation": "AML.T0051 (LLM Prompt Injection) / OWASP LLM01",
    "task_then_payload": "AML.T0051 (LLM Prompt Injection) / OWASP LLM01",
    "scope_mismatch": "OWASP LLM08 (Excessive Agency)",
    "obfuscation": "T1027 (Obfuscated Files or Information)",
    "ssrf": "T1090 (Proxy) / OWASP LLM-adjacent SSRF",
    "privilege_escalation": "T1548 (Abuse Elevation Control Mechanism)",
    "harmful_content": "OWASP LLM09 (Misinformation) / AML.T0048 (Harmful Content Generation)",
    "anti_refusal": "AML.T0054 (LLM Jailbreak) / OWASP LLM01",
    "agent_snooping": "T1082 (System Information Discovery) / OWASP LLM06",
}


def annotate_attack_ids(verdict: Verdict) -> None:
    for f in verdict.findings:
        if not f.attack_technique:
            f.attack_technique = ATTACK_TECHNIQUE.get(f.capability.value, "unmapped")


def to_json(verdict: Verdict, adjudicator_mode: str, chains: list[Chain]) -> str:
    payload = verdict.to_dict()
    payload["adjudicator_mode"] = adjudicator_mode
    payload["chains"] = [
        {
            "chain_id": c.chain_id,
            "source_rule": c.source.rule_id,
            "sink_rule": c.sink.rule_id,
            "same_file": c.same_file,
            "connected_via_graph": c.connected_via_graph,
        }
        for c in chains
    ]
    return json.dumps(payload, indent=2)


_TIER_ORDER = {"confirmed": 0, "likely": 1, "possible": 2, "insufficient_context": 3, "false_positive_suspected": 4}


def to_markdown(verdict: Verdict, adjudicator_mode: str, chains: list[Chain]) -> str:
    lines = [f"# SkillGuard Report", "", f"**Verdict: {verdict.label}**", "", verdict.summary, "",
              f"_Adjudicator mode: {adjudicator_mode}_", ""]

    if chains:
        lines.append("## Capability chains")
        for c in chains:
            arrow = "->" if c.same_file else "-> (cross-file)"
            lines.append(f"- `{c.chain_id}`: {c.source.rule_id} @ {c.source.file}:{c.source.start_line} {arrow} "
                          f"{c.sink.rule_id} @ {c.sink.file}:{c.sink.start_line}")
        lines.append("")

    if verdict.findings:
        lines.append("## Findings")
        ordered = sorted(verdict.findings, key=lambda f: (_TIER_ORDER.get(f.tier.value, 9), -{"critical": 3, "high": 2, "medium": 1, "low": 0}[f.severity.value]))
        for f in ordered:
            lines.append(f"### {f.rule_id} — {f.capability.value} [{f.tier.value}] ({f.severity.value})")
            lines.append(f"- **File**: `{f.file}:{f.start_line}-{f.end_line}`")
            lines.append(f"- **Evidence**: `{f.matched_text}`")
            lines.append(f"- **Capability**: {f.capability.value}")
            lines.append(f"- **ATT&CK**: {f.attack_technique or 'unmapped'}")
            lines.append(f"- **Why**: {f.rationale}")
            lines.append(f"- **Confidence**: {f.confidence:.2f}")
            if f.chain_id:
                lines.append(f"- **Chain**: {f.chain_id}")
            if f.provenance:
                lines.append(f"- **Provenance**: {' -> '.join(f.provenance)}")
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("None.")
        lines.append("")

    lines.append("## Coverage ledger")
    lines.append("")
    lines.append("| Path | Status | Bytes | Reason |")
    lines.append("|---|---|---|---|")
    for e in verdict.ledger:
        lines.append(f"| `{e.path}` | {e.status} | {e.bytes} | {e.reason or '-'} |")

    return "\n".join(lines)
