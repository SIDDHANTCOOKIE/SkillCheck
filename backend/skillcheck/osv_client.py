"""OSV.dev dependency vulnerability lookup. See spec §9.

Parses requirements.txt / package.json manifests bundled in the skill,
batches them to the OSV.dev API (no key required), and emits a Finding per
vulnerable pinned version. Network failure degrades gracefully — it never
raises into the pipeline, and the coverage ledger already accounts for the
manifest file itself being analysed regardless of whether OSV was reachable.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from .models import Capability, Finding, Severity

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT = 6


def _parse_requirements_txt(text: str) -> list[tuple[str, str]]:
    deps = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
        if m:
            deps.append((m.group(1), m.group(2)))
    return deps


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    deps = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            v = re.sub(r"^[\^~>=<\s]+", "", str(version))
            if re.match(r"^\d", v):
                deps.append((name, v))
    return deps


def find_manifests(file_texts: dict[str, str]) -> dict[str, list[tuple[str, str]]]:
    """Returns {file_path: [(package_name, version), ...]}."""
    out: dict[str, list[tuple[str, str]]] = {}
    for path, text in file_texts.items():
        base = path.rsplit("/", 1)[-1]
        if base == "requirements.txt":
            deps = _parse_requirements_txt(text)
            if deps:
                out[path] = deps
        elif base == "package.json":
            deps = _parse_package_json(text)
            if deps:
                out[path] = deps
    return out


def _ecosystem_for(path: str) -> str:
    return "PyPI" if path.endswith("requirements.txt") else "npm"


def query_osv(manifests: dict[str, list[tuple[str, str]]]) -> list[Finding]:
    """Batch-queries OSV.dev for each (name, version) pair found. Returns
    Findings for anything with vulnerabilities. Never raises."""
    if not manifests:
        return []

    queries = []
    lookup: list[tuple[str, str, str]] = []  # (file, name, version)
    for path, deps in manifests.items():
        eco = _ecosystem_for(path)
        for name, version in deps:
            queries.append({"package": {"name": name, "ecosystem": eco}, "version": version})
            lookup.append((path, name, version))

    if not queries:
        return []

    findings: list[Finding] = []
    try:
        req = urllib.request.Request(
            OSV_BATCH_URL,
            data=json.dumps({"queries": queries}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return []

    results = body.get("results", [])
    for (path, name, version), result in zip(lookup, results):
        vulns = result.get("vulns") or []
        if not vulns:
            continue
        ids = ", ".join(v.get("id", "?") for v in vulns[:5])
        findings.append(Finding(
            rule_id="SC-OSV1",
            capability=Capability.UNKNOWN,
            file=path,
            start_line=1,
            end_line=1,
            matched_text=f"{name}=={version}",
            severity=Severity.HIGH if len(vulns) > 1 else Severity.MEDIUM,
            rationale=f"Pinned dependency {name}=={version} has known vulnerabilities per OSV.dev: {ids}.",
            confidence=0.9,
            detector="osv",
            attack_technique=None,
        ))
    return findings
