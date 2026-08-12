"""Core data model. See project spec §8.

Invariants encoded here:
  I2 - Finding.tier is set by the adjudicator and is never removed from the
       findings list; nothing downstream may drop a Finding.
  I3 - Verdict.label is never "SAFE"; the clean state is NO_FINDINGS with a
       coverage ledger attached.
  I6 - Finding.matched_text is required (exact quoted span).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Optional


class Capability(str, Enum):
    CREDENTIAL_ACCESS = "credential_access"
    EXFILTRATION = "exfiltration"
    HIDDEN_EXECUTION = "hidden_execution"
    STAGE2_FETCH = "stage2_fetch"
    PERSISTENCE = "persistence"
    ANTI_FORENSICS = "anti_forensics"
    AGENT_MANIPULATION = "agent_manipulation"
    TASK_THEN_PAYLOAD = "task_then_payload"
    SCOPE_MISMATCH = "scope_mismatch"
    OBFUSCATION = "obfuscation"
    SSRF = "ssrf"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    HARMFUL_CONTENT = "harmful_content"
    ANTI_REFUSAL = "anti_refusal"
    AGENT_SNOOPING = "agent_snooping"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Tier(str, Enum):
    """Assigned by the adjudicator. Ranks, never filters (I2)."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    INSUFFICIENT_CONTEXT = "insufficient_context"  # I4: escalates, never clears
    FALSE_POSITIVE_SUSPECTED = "false_positive_suspected"


VerdictLabel = Literal[
    "MALICIOUS", "DANGEROUS", "SUSPICIOUS", "UNVERIFIED", "NO_FINDINGS"
]

CoverageStatus = Literal["analysed", "partial", "unanalysed"]


@dataclass
class Finding:
    rule_id: str
    capability: Capability
    file: str
    start_line: int
    end_line: int
    matched_text: str  # exact span, required (I6)
    severity: Severity
    rationale: str
    confidence: float = 0.5
    tier: Tier = Tier.POSSIBLE
    provenance: list[str] = field(default_factory=list)
    attack_technique: Optional[str] = None
    chain_id: Optional[str] = None
    detector: str = ""

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["capability"] = self.capability.value
        d["severity"] = self.severity.value
        d["tier"] = self.tier.value
        return d


@dataclass
class CoverageEntry:
    path: str
    status: CoverageStatus
    bytes: int
    reason: Optional[str] = None  # e.g. "binary", "encrypted", "remote-fetch"

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class CapabilityChain:
    chain_id: str
    finding_ids: list[str]
    description: str
    corroborated: bool = False


@dataclass
class Verdict:
    label: VerdictLabel
    coverage_pct: float
    findings: list[Finding]
    ledger: list[CoverageEntry]
    summary: str
    chains: list[CapabilityChain] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "coverage_pct": self.coverage_pct,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "ledger": [c.to_dict() for c in self.ledger],
            "chains": [c.__dict__ for c in self.chains],
        }
