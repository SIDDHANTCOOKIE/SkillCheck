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
    load_stage: str = "unreachable"  # unattended | immediate | on-demand | runtime | unreachable
    edges_out: list[str] = field(default_factory=list)


# structure.py rule ids whose finding names a file that runs, or is granted,
# with nothing deciding: no model turn, no confirmation, and for a couple of
# these not even the skill being invoked. A hook fires on an event; an
# in-tree PEP 517 backend or an npm postinstall script runs at install time;
# a bypassPermissions/unscoped-tool grant switches off the approval step
# itself; an MCP server's and a subagent's content load into context before
# the skill is ever invoked. Not imported from structure.py — graph.py is a
# dependency of structure.py (ComponentGraph), so the relationship only goes
# one way; these ids are the contract between the two, not a re-detection of
# what structure.py already found.
UNATTENDED_STRUCTURE_RULES = frozenset({"SC-ST1", "SC-ST2", "SC-ST3", "SC-ST4", "SC-ST8"})


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
    # Docs commonly invoke a script by its bare name — `scripts/build` for
    # `scripts/build.sh` — omitting the extension. Only try a stem match when
    # the target itself has none, so a target that already names a real
    # extension (and simply doesn't exist) still correctly fails to resolve.
    if "." not in target.rsplit("/", 1)[-1]:
        for p in all_paths:
            stem = p.rsplit(".", 1)[0] if "." in p.rsplit("/", 1)[-1] else p
            if stem == candidate or stem.endswith("/" + target) or stem == target:
                return p
    return None


def _is_plausible_file_reference(text: str, target: str, start: int, end: int) -> bool:
    """Gate for treating a `scripts/X` / `references/X` regex match as an
    actual file reference rather than ordinary prose that happens to contain
    a slash between two words (e.g. "better scripts/tools that produced").

    A target with a file extension (`scripts/build.sh`, `references/advanced.md`)
    is accepted on its own — that's the ordinary, unadorned way real skills
    write an invocation, extension included. An extensionless target
    (`scripts/check_fillable_fields`) is accepted only when set off as inline
    code or inside a fenced block, since without an extension the same shape
    also matches plain prose ("better scripts/tools that produced ..."), and
    that ambiguity needs the extra signal to resolve (verified against real
    skills — see the pdf/skill-creator cases in the session that added this)."""
    if "." in target.rsplit("/", 1)[-1]:
        return True
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]
    rel_start = start - line_start
    for m in re.finditer(r"`[^`\n]*`", line):
        if m.start() <= rel_start < m.end():
            return True
    return False


@dataclass
class UnresolvedReference:
    """A `scripts/...` or `references/...` mention that names a file not present
    in this scan (paste-only submission, partial zip, etc.) — content the skill
    declares it will load that this scan never got to see. Surfaced as a
    finding rather than silently dropped, so a lone pasted SKILL.md that
    promises an external payload can't score NO_FINDINGS just because the
    payload wasn't submitted alongside it."""
    file: str
    target: str
    offset: int  # char offset of the match within `file`'s text, for line lookup


def build_component_graph(
    files: list[IngestedFile], file_texts: dict[str, str]
) -> tuple[ComponentGraph, list[UnresolvedReference]]:
    all_paths = [f.rel_path for f in files]
    nodes = {p: ComponentNode(path=p) for p in all_paths}
    root = _find_root(files)
    unresolved: list[UnresolvedReference] = []

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
                elif _is_plausible_file_reference(text, m.group(0), m.start(), m.end()):
                    unresolved.append(UnresolvedReference(path, m.group(0), m.start()))
            for m in re.finditer(r"\bscripts?/[\w./-]+", text):
                resolved = _resolve_target(m.group(0), all_paths, path)
                if resolved:
                    edges.append(resolved)
                elif _is_plausible_file_reference(text, m.group(0), m.start(), m.end()):
                    unresolved.append(UnresolvedReference(path, m.group(0), m.start()))
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

    return ComponentGraph(nodes=nodes, root=root), unresolved


def mark_unattended_nodes(graph: ComponentGraph, structure_findings: list[Finding]) -> None:
    """Promote a node to load_stage 'unattended' wherever structure.py found
    one of UNATTENDED_STRUCTURE_RULES on it. Called after detect_structure()
    runs and before anything downstream reads load_stage (capability-chain
    building, corroborate_sink_reachability, verdict.py's corroborated-medium
    check) — 'immediate' already meant "SKILL.md itself"; this is the one
    file/setting away from that, one rung up, for the files whose content
    doesn't wait on the skill being invoked at all."""
    for f in structure_findings:
        if f.rule_id not in UNATTENDED_STRUCTURE_RULES:
            continue
        node = graph.nodes.get(f.file)
        if node is not None:
            node.load_stage = "unattended"


# --- capability graph --------------------------------------------------------

@dataclass
class Chain:
    chain_id: str
    source: Finding
    sink: Finding
    same_file: bool
    connected_via_graph: bool
    direct: bool  # same_file or a direct link/import edge — NOT merely "both reachable from root"


def _direct_edge(graph: ComponentGraph, a: str, b: str) -> bool:
    na = graph.nodes.get(a)
    nb = graph.nodes.get(b)
    if na and b in na.edges_out:
        return True
    if nb and a in nb.edges_out:
        return True
    return False


def _common_root_connected(graph: ComponentGraph, a: str, b: str) -> bool:
    na = graph.nodes.get(a)
    nb = graph.nodes.get(b)
    # The canonical split-across-files attack (§3.3): SKILL.md fans out to
    # several references/*.md that never link to *each other* — only a
    # direct-edge check would never see them as connected, which is exactly
    # the evasion. Two files that are both part of the same reachable
    # package (i.e. share the root as a common ancestor) are treated as
    # connected too, just with a lighter corroboration weight (see
    # corroborate_chains) — `direct` on the resulting Chain stays False so
    # callers that need tighter proximity (e.g. corroborated_medium) can
    # still tell the two apart.
    return bool(na and nb and na.reachable_from_root and nb.reachable_from_root and graph.root)


MAX_CHAIN_PAIRS = 20_000  # bounds the source x sink cross product (1.4: chain-explosion)


def build_capability_chains(findings: list[Finding], graph: ComponentGraph) -> list[Chain]:
    sources = [f for f in findings if f.capability in SOURCE_CAPS]
    sinks = [f for f in findings if f.capability in SINK_CAPS]
    chains: list[Chain] = []
    idx = 0

    if len(sources) * len(sinks) > MAX_CHAIN_PAIRS:
        # A pathological skill with hundreds of source/sink findings would
        # otherwise make this a full unbounded cross product. Cap it rather
        # than let one oversized package hang the scan for everyone else.
        sources = sources[: max(1, MAX_CHAIN_PAIRS // max(1, len(sinks)))]

    for src in sources:
        for sink in sinks:
            if src is sink:
                continue
            same_file = src.file == sink.file
            direct = same_file or _direct_edge(graph, src.file, sink.file)
            via_graph = direct or _common_root_connected(graph, src.file, sink.file)
            if via_graph:
                idx += 1
                cid = f"CHAIN-{idx}"
                chains.append(Chain(cid, src, sink, same_file, via_graph, direct))
                src.chain_id = src.chain_id or cid
                sink.chain_id = sink.chain_id or cid
                src.chain_ids.append(cid)
                sink.chain_ids.append(cid)
    return chains
