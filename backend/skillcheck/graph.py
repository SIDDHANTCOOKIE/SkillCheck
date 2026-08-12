"""Component graph (reachability) and capability graph (chain detection).

Component graph: spec §7.1. Root is SKILL.md. Edges come from markdown links,
`references/` mentions, and local imports in code files. Every node is
tagged reachable_from_root + load_stage so progressive-disclosure abuse
(§3.3 bullet 8) is visible instead of silently trusted.

Capability graph: spec §7.3 / I5. Findings are capability events; a chain is
a source event (credential access) reaching a sink event (exfiltration /
stage2 fetch / hidden execution) either in the same file or in a different
file connected by the component graph. This is a heuristic approximation of
real dataflow analysis, appropriate for a 12-hour build — it is deliberately
conservative about calling something "corroborated".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ingest import IngestedFile
from .models import Capability, Finding
from .parse_markdown import parse_document

SOURCE_CAPS = {Capability.CREDENTIAL_ACCESS}
SINK_CAPS = {Capability.EXFILTRATION, Capability.STAGE2_FETCH, Capability.HIDDEN_EXECUTION,
             Capability.PERSISTENCE, Capability.PRIVILEGE_ESCALATION, Capability.SSRF}


@dataclass
class ComponentNode:
    path: str
    reachable_from_root: bool = False
    load_stage: str = "unreachable"  # immediate | on-demand | runtime | unreachable
    edges_out: list[str] = field(default_factory=list)


@dataclass
class ComponentGraph:
    nodes: dict[str, ComponentNode]
    root: str | None


def _find_root(files: list[IngestedFile]) -> str | None:
    candidates = [f for f in files if f.rel_path.lower() in ("skill.md", "skill.yaml", "skill.yml")]
    if candidates:
        return sorted(candidates, key=lambda f: len(f.rel_path))[0].rel_path
    top_level_md = [f for f in files if f.rel_path.lower().endswith(".md") and "/" not in f.rel_path]
    if top_level_md:
        return sorted(top_level_md, key=lambda f: len(f.rel_path))[0].rel_path
    return None


def _resolve_target(target: str, all_paths: list[str], from_path: str) -> str | None:
    target = target.split("#")[0].strip()
    if not target or target.startswith(("http://", "https://", "mailto:")):
        return None
    from_dir = "/".join(from_path.split("/")[:-1])
    candidate = f"{from_dir}/{target}" if from_dir else target
    candidate = candidate.replace("./", "")
    for p in all_paths:
        if p == candidate or p.endswith("/" + target) or p == target:
            return p
    return None


def build_component_graph(files: list[IngestedFile], file_texts: dict[str, str]) -> ComponentGraph:
    all_paths = [f.rel_path for f in files]
    nodes = {p: ComponentNode(path=p) for p in all_paths}
    root = _find_root(files)

    for path, text in file_texts.items():
        edges: list[str] = []
        if path.lower().endswith((".md", ".markdown")):
            doc = parse_document(text)
            for link in doc.links:
                resolved = _resolve_target(link.target, all_paths, path)
                if resolved:
                    edges.append(resolved)
            for m in re.finditer(r"\breferences?/[\w./-]+", text):
                resolved = _resolve_target(m.group(0), all_paths, path)
                if resolved:
                    edges.append(resolved)
            for m in re.finditer(r"\bscripts?/[\w./-]+", text):
                resolved = _resolve_target(m.group(0), all_paths, path)
                if resolved:
                    edges.append(resolved)
        elif path.endswith(".py"):
            for m in re.finditer(r"^\s*(?:import|from)\s+([\w.]+)", text, re.MULTILINE):
                mod = m.group(1).replace(".", "/")
                for cand in (f"{mod}.py", f"{mod}/__init__.py"):
                    if cand in all_paths:
                        edges.append(cand)
        nodes[path].edges_out = sorted(set(edges))

    if root:
        nodes[root].reachable_from_root = True
        nodes[root].load_stage = "immediate"
        seen = {root}
        frontier = [root]
        while frontier:
            nxt = []
            for p in frontier:
                for e in nodes[p].edges_out:
                    if e not in seen:
                        seen.add(e)
                        nodes[e].reachable_from_root = True
                        nodes[e].load_stage = "on-demand" if p == root else nodes[p].load_stage
                        nxt.append(e)
            frontier = nxt

    return ComponentGraph(nodes=nodes, root=root)


# --- capability graph --------------------------------------------------------

@dataclass
class Chain:
    chain_id: str
    source: Finding
    sink: Finding
    same_file: bool
    connected_via_graph: bool


def build_capability_chains(findings: list[Finding], graph: ComponentGraph) -> list[Chain]:
    sources = [f for f in findings if f.capability in SOURCE_CAPS]
    sinks = [f for f in findings if f.capability in SINK_CAPS]
    chains: list[Chain] = []
    idx = 0

    def connected(a: str, b: str) -> bool:
        if a == b:
            return True
        na = graph.nodes.get(a)
        if na and b in na.edges_out:
            return True
        nb = graph.nodes.get(b)
        if nb and a in nb.edges_out:
            return True
        return False

    for src in sources:
        for sink in sinks:
            if src is sink:
                continue
            same_file = src.file == sink.file
            via_graph = connected(src.file, sink.file)
            if same_file or via_graph:
                idx += 1
                cid = f"CHAIN-{idx}"
                chains.append(Chain(cid, src, sink, same_file, via_graph))
                src.chain_id = src.chain_id or cid
                sink.chain_id = sink.chain_id or cid
    return chains
