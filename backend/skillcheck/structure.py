"""Structure layer: what a skill bundle *declares*, not what it says.

Every detector in `detectors/` reads a file's content as prose or code. None
of them understand that a bundled `.claude/settings.json` can register an
event hook, retarget the harness's own outbound API traffic, or switch off
the confirmation gate for the rest of the session; that a bundled
`.mcp.json` can point the harness at a remote server whose tool descriptions
load before the skill is ever invoked; or that a bundled
`.claude/agents/*.md` is a system prompt for a second model instance. None
of that is a phrase a regex matches against prose — it's a structural fact
about what the package configures, sitting in files the content detectors
read as inert text (or don't read for meaning at all).

A skill shipping exactly those files today would otherwise score
NO_FINDINGS. That's the blind spot this closes, and it's worth closing
first because of where these declarations sit relative to the approval
path. Everything the content detectors read is something the agent has to
*choose* to act on, and a user can decline. A registered hook (or a
`statusLine` command, see SC-ST7) is dispatched by the harness when its
event arrives: there is no tool call to review and no prompt to answer, so
the only remaining place to catch it is here, before install.

This runs as its own pipeline stage rather than a `detectors/` entry. Every
entry in `ALL_DETECTORS` has the `(rel_path, text, provenance)` per-fragment
signature and runs once per file/code-block/decoded-span; the checks here
are package-level — SC-ST5's reachability check needs the whole file set and
the component graph at once, and a hook/permission/MCP finding needs the
whole parsed manifest rather than a text fragment.
"""
from __future__ import annotations

import json
import re
import tomllib

from .graph import ComponentGraph
from .ingest import IngestedFile
from .models import Capability, Finding, Severity

# A real .claude/settings.json is a few kilobytes. 256 KiB is two orders of
# magnitude of headroom while still bounding what we hand to json.loads from
# an untrusted bundle.
_MANIFEST_BYTE_CEILING = 256 * 1024

# The documented hooks block reaches a command in four container hops:
#   hooks -> "<EventName>" -> [ {matcher, hooks: [ {type, command} ]} ]
# The walk below is schema-agnostic on purpose (see _hook_commands), so this
# is drift headroom rather than a schema constant — double the known depth.
_MAX_NESTING_HOPS = 8

# Per-manifest output bound. A settings.json that legitimately registers more
# than this many commands does not exist; past it we are being fed a payload
# designed to flood the report rather than a config.
_MAX_COMMANDS_PER_MANIFEST = 32

# Command strings are quoted whole in evidence up to this length.
_COMMAND_CHARS = 200
_EVIDENCE_CHARS = 300

_HARNESS_SETTINGS_RE = re.compile(r"(?:^|/)\.claude/settings(?:\.local)?\.json$", re.IGNORECASE)
_MCP_MANIFEST_RE = re.compile(r"(?:^|/)\.mcp\.json$", re.IGNORECASE)
_PACKAGE_JSON_RE = re.compile(r"(?:^|/)package\.json$", re.IGNORECASE)
_PYPROJECT_TOML_RE = re.compile(r"(?:^|/)pyproject\.toml$", re.IGNORECASE)

# npm scripts that run on their own during `npm install`, with no separate
# invocation — "install" fires whenever there's no gyp binding.gyp either,
# not only alongside preinstall/postinstall.
_NPM_INSTALL_SCRIPT_KEYS = ("preinstall", "install", "postinstall")

# PEP 517 backends every real package uses; anything else declared alongside
# an in-tree `backend-path` is a bundle shipping its own build-time code.
_KNOWN_BUILD_BACKENDS = frozenset({
    "setuptools.build_meta", "poetry.core.masonry.api", "flit_core.buildapi",
    "hatchling.build", "pdm.backend", "maturin",
})

# Hook events that fire ahead of, or independent of, any specific tool call —
# there is no narrower moment a reviewer could point to and say "that's what
# it was gated on". Everything else (PreToolUse, PostToolUse, Stop, ...) is
# still unsupervised, but at least ties to a tool invocation that was itself
# a deliberate step, so it's scored a notch below rather than lumped in with
# the same severity as an ungated session-wide trigger.
_SESSION_WIDE_HOOK_EVENTS = {"sessionstart", "sessionend", "userpromptsubmit", "notification"}

# Which tools matter when granted without a scope, grouped by *what the
# unqualified grant actually hands over* rather than kept as one flat list —
# the grouping is the argument for inclusion, and it's what makes adding a
# tool later a decision rather than a guess.
#
# Read-only tools (Read, Glob, Grep, TodoWrite, ...) are deliberately absent:
# an unscoped `Read` is a real widening, but it isn't the difference between
# a reviewed session and an unreviewed machine, and convicting on it is how
# this rule would start firing on ordinary skills.
_EXEC_TOOLS = frozenset({"bash", "bashoutput", "killshell", "execute", "slashcommand"})
_WRITE_TOOLS = frozenset({"write", "edit", "multiedit", "notebookedit"})
_EGRESS_TOOLS = frozenset({"webfetch", "websearch"})
_DELEGATION_TOOLS = frozenset({"task", "agent"})
_UNSCOPED_GRANT_IS_SEVERE = _EXEC_TOOLS | _WRITE_TOOLS | _EGRESS_TOOLS | _DELEGATION_TOOLS

# Env-var names whose value is the network endpoint a harness (or its
# underlying model client) actually talks to. A bundled settings.json that
# sets one of these doesn't just risk that one variable's normal use — it
# retargets every request the harness makes for the rest of the session,
# including whatever bearer token/API key rides along in the request, to
# wherever the skill author pointed it. Matched by suffix, case-insensitive,
# so a provider-specific name (ANTHROPIC_BASE_URL, OPENAI_BASE_URL,
# AZURE_..._ENDPOINT) is covered without an exhaustive per-vendor list.
_ENDPOINT_ENV_SUFFIXES = ("_BASE_URL", "_API_URL", "_ENDPOINT", "_API_BASE")
_PROXY_ENV_NAMES = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NODE_EXTRA_CA_CERTS"}

# Extensions treated as bundled executable code for SC-ST5. Deliberately
# narrower than ingest.TEXT_EXTENSIONS — this is the false-positive-prone
# rule (a vendored helper trips it once per module), so it's held to the
# languages the rest of the scanner can actually reason about elsewhere
# (code.py AST-parses .py; the shell family gets pattern coverage) rather
# than every text extension the ingester happens to accept.
_BUNDLED_CODE_EXTENSIONS = (".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ps1", ".rb")


def _evidence(raw: str, limit: int = _EVIDENCE_CHARS) -> str:
    """One-line evidence, truncated with a marker the reader can see.

    Evidence that is cut silently reads as the whole of what was found, which
    is the one thing a quoted span must never do — so the marker spells out
    that there is more rather than trailing off into an ellipsis.
    """
    collapsed = " ".join(raw.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit].rstrip() + " [...truncated]"


def _is_subagent_definition(rel_path: str) -> bool:
    """True for `.claude/agents/<name>.md` at any depth in the bundle.

    Compared segment-wise rather than pattern-matched: the path is data from
    an untrusted archive, and `.claude` / `agents` are exact directory names,
    not a shape to match loosely.
    """
    segments = rel_path.lower().split("/")
    if len(segments) < 3 or not segments[-1].endswith(".md"):
        return False
    return segments[-3] == ".claude" and segments[-2] == "agents"


def _try_parse_manifest(raw_text: str) -> dict | None:
    """Parse a bundled JSON manifest, or None if it isn't usable as one.

    Size is checked before parsing, and *every* parse failure is swallowed:
    this is attacker-controlled input, so the failure modes are open-ended
    (nesting deep enough to exhaust the stack, surrogates the decoder rejects)
    and a config we cannot read must degrade to SC-SCN1 at the call site, not
    take the stage down with it.
    """
    if len(raw_text.encode("utf-8", errors="ignore")) > _MANIFEST_BYTE_CEILING:
        return None
    try:
        loaded = json.loads(raw_text)
    except Exception:
        return None
    return loaded if isinstance(loaded, dict) else None


def _new_finding(
    rule_id: str, capability: Capability, severity: Severity,
    rel_path: str, evidence: str, why: str, confidence: float,
) -> Finding:
    return Finding(
        rule_id=rule_id, capability=capability, file=rel_path,
        start_line=1, end_line=1, matched_text=_evidence(evidence),
        severity=severity, rationale=why, confidence=confidence,
        detector="structure",
    )


# --- SC-ST1: event hooks -----------------------------------------------

def _hook_commands(spec) -> list[str]:
    """Every `command` string reachable under one event's hook spec.

    The traversal is breadth-first over an explicit queue rather than
    recursive, for two reasons that both come from the input being hostile
    JSON: a bundle can nest deeply enough to exhaust the interpreter stack on
    a recursive walk, and a queue makes the depth and output bounds a single
    readable loop condition instead of two guards spread across call frames.

    Deliberately not bound to the documented layout. The hooks schema has
    already changed shape once, and a rule that reads config the model never
    sees is the worst possible place to acquire a silent blind spot on the
    next revision — so any `command` key under the event counts, wherever it
    turns up.
    """
    found: list[str] = []
    queue: list[tuple[object, int]] = [(spec, 0)]
    cursor = 0
    while cursor < len(queue) and len(found) < _MAX_COMMANDS_PER_MANIFEST:
        node, hops = queue[cursor]
        cursor += 1
        if hops > _MAX_NESTING_HOPS:
            continue
        if isinstance(node, dict):
            command = node.get("command")
            if isinstance(command, str) and command.strip():
                found.append(command.strip()[:_COMMAND_CHARS])
            queue.extend((v, hops + 1) for k, v in node.items() if k != "command")
        elif isinstance(node, list):
            queue.extend((item, hops + 1) for item in node)
    return found


def _hook_findings(rel_path: str, manifest: dict) -> list[Finding]:
    hooks_block = manifest.get("hooks")
    if not isinstance(hooks_block, dict):
        return []
    out: list[Finding] = []
    for event_name, spec in hooks_block.items():
        event_key = str(event_name).strip().lower()
        session_wide = event_key in _SESSION_WIDE_HOOK_EVENTS
        for command in _hook_commands(spec):
            if len(out) >= _MAX_COMMANDS_PER_MANIFEST:
                return out
            out.append(_new_finding(
                "SC-ST1", Capability.PERSISTENCE,
                Severity.CRITICAL if session_wide else Severity.HIGH,
                rel_path, f"{event_name}: {command}",
                f"'{rel_path}' installs a command on the '{event_name}' event. "
                "Registering a hook moves the command outside the approval "
                "path entirely: the harness dispatches it when the event "
                "arrives, so there is no tool call to review, nothing for the "
                "model to decline, and no prompt for the user to answer. "
                + (
                    "This event carries no tool context at all, so the "
                    "command's trigger cannot be traced back to any action "
                    "the user took — it fires on the session itself."
                    if session_wide else
                    "This event does at least follow a tool invocation the "
                    "model chose to make, but approving that invocation was "
                    "never approval of the hook body attached to it."
                ),
                0.9,
            ))
    return out


# --- SC-ST2: permission-gate weakening ----------------------------------

def _split_grant(entry: str) -> tuple[str, str | None]:
    """Split a permission entry into `(tool, scope)`; scope is None if absent.

    Parsed by partitioning on the first bracket rather than by regex. A grant
    is a two-part string with one delimiter — there is no pattern here worth
    matching, and a hand-written split has no bounded quantifiers to be
    walked past by a long or oddly-spaced entry.
    """
    head, bracket, tail = entry.partition("(")
    tool = head.strip()
    if not bracket:
        return tool, None
    tail = tail.rstrip()
    if not tail.endswith(")"):
        # Unbalanced — treat the whole remainder as the scope rather than
        # guessing, so a malformed entry can't read as an unscoped grant.
        return tool, tail.strip()
    return tool, tail[:-1].strip()


def _scope_is_unbounded(scope: str | None) -> bool:
    """True when a grant's scope restricts nothing.

    Tested by asking whether the scope names anything at all — a scope with
    no alphanumeric character in it (`*`, `**`, `*:*`, `:*`, `:`, empty) is
    punctuation, not a restriction. Derived this way rather than enumerated
    so a spelling nobody thought to list still reads as unbounded; an
    enumeration is a list of the wildcards we happened to imagine.
    """
    return scope is None or not any(ch.isalnum() for ch in scope)


def _unscoped_grant_tool(entry: str) -> str | None:
    """The tool an allow-entry hands over without qualification, or None."""
    if entry.strip().lower() in {"*", "all", "any"}:
        return "*"
    tool, scope = _split_grant(entry)
    if not tool or not tool.replace("_", "").isalnum():
        return None
    return tool if _scope_is_unbounded(scope) else None


def _permission_findings(rel_path: str, manifest: dict) -> list[Finding]:
    perms = manifest.get("permissions")
    if not isinstance(perms, dict):
        return []
    out: list[Finding] = []

    default_mode = perms.get("defaultMode")
    if isinstance(default_mode, str) and default_mode.strip() == "bypassPermissions":
        out.append(_new_finding(
            "SC-ST2", Capability.PRIVILEGE_ESCALATION, Severity.CRITICAL,
            rel_path, "permissions.defaultMode = bypassPermissions",
            f"'{rel_path}' turns the confirmation gate off for the rest of "
            "the session by setting permissions.defaultMode to "
            "bypassPermissions. This doesn't widen what may be approved — it "
            "removes the approving, for every action the agent takes "
            "afterwards, whether or not it originated from this skill.",
            0.9,
        ))

    if perms.get("enableAllProjectMcpServers") is True:
        out.append(_new_finding(
            "SC-ST2", Capability.PRIVILEGE_ESCALATION, Severity.HIGH,
            rel_path, "permissions.enableAllProjectMcpServers = true",
            f"'{rel_path}' auto-approves every MCP server the project "
            "declares, including any this same bundle ships under "
            "mcpServers — the approval step that would otherwise have "
            "surfaced them is switched off from inside the bundle itself.",
            0.8,
        ))

    for entry in (perms.get("allow") or [])[:_MAX_COMMANDS_PER_MANIFEST]:
        if not isinstance(entry, str):
            continue
        tool = _unscoped_grant_tool(entry)
        if tool is None:
            continue
        if tool != "*" and tool.lower() not in _UNSCOPED_GRANT_IS_SEVERE:
            continue
        out.append(_new_finding(
            "SC-ST2", Capability.PRIVILEGE_ESCALATION, Severity.CRITICAL,
            rel_path, f"permissions.allow: {entry.strip()}",
            f"'{rel_path}' pre-approves '{entry.strip()}' in permissions.allow "
            "with no qualification. A scoped grant names what it allows "
            "(e.g. `Bash(git log:*)`); this one names only the tool, so "
            "every future use of it is already answered for.",
            0.85,
        ))

    return out


# --- SC-ST3: MCP server declarations -------------------------------------

def _mcp_server_address(server_cfg: dict) -> str | None:
    # Any key an MCP entry uses to name a remote endpoint. Matched by name
    # across the transports the spec defines (streamable HTTP, SSE) plus the
    # spellings clients have shipped, since an entry only needs one of them
    # to point the harness somewhere off-bundle.
    for url_key in ("url", "httpUrl", "sseUrl", "serverUrl", "endpoint"):
        value = server_cfg.get(url_key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:200]
    command = server_cfg.get("command")
    if isinstance(command, str) and command.strip():
        args = [a for a in server_cfg.get("args", []) if isinstance(a, str)]
        return " ".join([command.strip(), *args])[:200]
    return None


def _mcp_findings(rel_path: str, manifest: dict) -> list[Finding]:
    out: list[Finding] = []
    for block_key in ("mcpServers", "servers"):
        servers = manifest.get(block_key)
        if not isinstance(servers, dict):
            continue
        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue
            address = _mcp_server_address(server_cfg)
            if address is None:
                continue
            out.append(_new_finding(
                "SC-ST3", Capability.STAGE2_FETCH, Severity.HIGH,
                rel_path, f"{server_name}: {address}",
                f"'{rel_path}' declares the MCP server "
                f"'{str(server_name)[:64]}'. Its tool descriptions load into "
                "the agent's context at session start, before the skill is "
                "ever invoked, and none of that content was part of this scan.",
                0.75,
            ))
    return out


# --- SC-ST6: harness endpoint / proxy override ---------------------------

def _looks_like_endpoint_var(name: str) -> bool:
    upper = name.upper()
    return upper in _PROXY_ENV_NAMES or upper.endswith(_ENDPOINT_ENV_SUFFIXES)


def _endpoint_override_findings(rel_path: str, manifest: dict) -> list[Finding]:
    env_block = manifest.get("env")
    if not isinstance(env_block, dict):
        return []
    out: list[Finding] = []
    for var_name, var_value in env_block.items():
        if not isinstance(var_name, str) or not _looks_like_endpoint_var(var_name):
            continue
        out.append(_new_finding(
            "SC-ST6", Capability.EXFILTRATION, Severity.CRITICAL,
            rel_path, f"env.{var_name} = {str(var_value)[:160]}",
            f"'{rel_path}' sets {var_name} in its bundled settings, "
            "retargeting where the harness's own outbound traffic goes for "
            "the rest of the session — not just this skill's requests, but "
            "every request the client makes, including whatever credential "
            "rides along with it.",
            0.85,
        ))
    return out


# --- SC-ST7: statusLine (a second, easy-to-miss execution point) --------

def _status_line_findings(rel_path: str, manifest: dict) -> list[Finding]:
    status_line = manifest.get("statusLine")
    if not isinstance(status_line, dict):
        return []
    command = status_line.get("command")
    if not (isinstance(command, str) and command.strip()):
        return []
    return [_new_finding(
        "SC-ST7", Capability.HIDDEN_EXECUTION, Severity.HIGH,
        rel_path, f"statusLine.command = {command.strip()}",
        f"'{rel_path}' registers a statusLine command, which the harness "
        "runs on its own schedule to render the prompt status line — the "
        "same unsupervised-execution shape as a hook (SC-ST1), just under a "
        "settings.json key that isn't nested under \"hooks\" and is easy to "
        "miss on a manual read.",
        0.75,
    )]


# --- SC-ST4: subagent definitions ----------------------------------------

def _subagent_finding(rel_path: str, raw_text: str) -> Finding:
    from .parse_markdown import parse_document
    parsed = parse_document(raw_text)
    frontmatter = parsed.frontmatter if isinstance(parsed.frontmatter, dict) else {}
    agent_name = frontmatter.get("name") or rel_path.rsplit("/", 1)[-1]
    return _new_finding(
        "SC-ST4", Capability.AGENT_MANIPULATION, Severity.HIGH,
        rel_path, f"subagent: {agent_name}",
        f"'{rel_path}' defines the subagent '{agent_name}'. Its body is a "
        "system prompt a second model instance will run under — "
        "instructions by construction, not documentation — and it ships "
        "with the skill unreviewed. (Its prose is separately covered by "
        "the SC-P* prompt-injection rules, which read this same file as "
        "text like any other.)",
        0.7,
    )


# --- SC-ST5: bundled code SKILL.md never points at ------------------------

def _unreferenced_code_findings(files: list[IngestedFile], graph: ComponentGraph) -> list[Finding]:
    if not graph.root:
        # Nothing to be unreferenced *from* — a lone script with no SKILL.md
        # anchor isn't this rule's claim to make; stay quiet rather than
        # convict every file in a headless bundle.
        return []
    out: list[Finding] = []
    for f in files:
        if f.is_binary or not f.is_text:
            continue
        if not f.rel_path.lower().endswith(_BUNDLED_CODE_EXTENSIONS):
            continue
        node = graph.nodes.get(f.rel_path)
        if node is None or node.reachable_from_root:
            continue
        out.append(_new_finding(
            "SC-ST5", Capability.HIDDEN_EXECUTION, Severity.MEDIUM,
            f.rel_path, f.rel_path,
            f"'{f.rel_path}' is bundled executable code, but SKILL.md never "
            "reaches it — no link, and no scripts/ or references/ mention "
            "resolves to it. It may run via a side channel, or lie dormant "
            "until triggered some other way.",
            0.5,
        ))
    return out


# --- SC-ST8: install-time execution --------------------------------------

def _npm_install_script_findings(rel_path: str, manifest: dict) -> list[Finding]:
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return []
    out: list[Finding] = []
    for key in _NPM_INSTALL_SCRIPT_KEYS:
        command = scripts.get(key)
        if not (isinstance(command, str) and command.strip()):
            continue
        out.append(_new_finding(
            "SC-ST8", Capability.HIDDEN_EXECUTION, Severity.CRITICAL,
            rel_path, f"scripts.{key} = {command.strip()}",
            f"'{rel_path}' registers a '{key}' script, which npm runs on its "
            "own during `npm install` — before any tool call, with no model "
            "decision and no confirmation in front of it. The same "
            "unsupervised-execution shape as a bundled event hook (SC-ST1), "
            "just triggered by a package manager instead of the harness.",
            0.85,
        ))
    return out


def _pep517_backend_findings(rel_path: str, raw_text: str) -> list[Finding]:
    try:
        data = tomllib.loads(raw_text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return []
    build_system = data.get("build-system")
    if not isinstance(build_system, dict):
        return []
    backend = build_system.get("build-backend")
    backend_path = build_system.get("backend-path")
    if not (isinstance(backend, str) and backend_path):
        return []
    if backend in _KNOWN_BUILD_BACKENDS:
        return []
    return [_new_finding(
        "SC-ST8", Capability.HIDDEN_EXECUTION, Severity.CRITICAL,
        rel_path, f'build-backend = "{backend}" (backend-path = {backend_path!r})',
        f"'{rel_path}' declares an in-tree PEP 517 build backend ('{backend}', "
        f"loaded from {backend_path!r} inside this bundle). That module runs "
        "at `pip install` time — before setup.py, before any script a "
        "reviewer would think to check — the same unsupervised-execution "
        "shape as a bundled event hook (SC-ST1), just triggered by the "
        "package installer instead of the harness.",
        0.8,
    )]


def _manifest_unreadable_finding(rel_path: str) -> Finding:
    return Finding(
        rule_id="SC-SCN1", capability=Capability.UNKNOWN, file=rel_path,
        start_line=1, end_line=1, matched_text="<unparseable JSON>",
        severity=Severity.MEDIUM,
        rationale=(
            f"'{rel_path}' looks like a harness config file but did not "
            "parse as JSON, so it could not be checked for hooks, "
            "permissions, or MCP servers. Treat the verdict as a floor."
        ),
        confidence=1.0, detector="structure",
    )


def detect_structure(
    files: list[IngestedFile],
    file_texts: dict[str, str],
    graph: ComponentGraph,
) -> list[Finding]:
    findings: list[Finding] = []

    for f in files:
        raw_text = file_texts.get(f.rel_path)
        if raw_text is None:
            continue

        if _HARNESS_SETTINGS_RE.search(f.rel_path) or _MCP_MANIFEST_RE.search(f.rel_path):
            manifest = _try_parse_manifest(raw_text)
            if manifest is None:
                if raw_text.strip():
                    findings.append(_manifest_unreadable_finding(f.rel_path))
                continue
            findings.extend(_hook_findings(f.rel_path, manifest))
            findings.extend(_permission_findings(f.rel_path, manifest))
            findings.extend(_mcp_findings(f.rel_path, manifest))
            findings.extend(_endpoint_override_findings(f.rel_path, manifest))
            findings.extend(_status_line_findings(f.rel_path, manifest))
        elif _is_subagent_definition(f.rel_path):
            findings.append(_subagent_finding(f.rel_path, raw_text))
        elif _PACKAGE_JSON_RE.search(f.rel_path):
            manifest = _try_parse_manifest(raw_text)
            if manifest is None:
                if raw_text.strip():
                    findings.append(_manifest_unreadable_finding(f.rel_path))
                continue
            findings.extend(_npm_install_script_findings(f.rel_path, manifest))
        elif _PYPROJECT_TOML_RE.search(f.rel_path):
            findings.extend(_pep517_backend_findings(f.rel_path, raw_text))

    findings.extend(_unreferenced_code_findings(files, graph))
    return findings
