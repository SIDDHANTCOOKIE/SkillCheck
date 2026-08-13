"""Coverage ledger. See spec I1/I3 — first-class from the first commit."""
from __future__ import annotations

from .graph import ComponentGraph
from .ingest import IngestedFile
from .models import CoverageEntry

MINIFIED_LINE_LEN = 2000

# Executable-ish languages that only get regex/pattern coverage (code.py's
# shell pack) — no AST/structural analysis exists for them, unlike .py.
# Reporting these as plain "analysed" overstated what actually ran (2.5).
NO_AST_CODE_EXTENSIONS = {".sh", ".bash", ".zsh", ".rb", ".ps1", ".js", ".ts", ".php", ".pl", ".cjs", ".mjs"}


def _reason_for_unanalysed(f: IngestedFile) -> str:
    if f.is_binary:
        return "binary"
    return "unreadable"


def build_ledger(
    files: list[IngestedFile],
    analysed_paths: set[str],
    graph: ComponentGraph,
    file_texts: dict[str, str],
) -> tuple[list[CoverageEntry], float]:
    ledger: list[CoverageEntry] = []
    analysed_bytes = 0
    total_bytes = 0

    for f in files:
        if f.rel_path not in analysed_paths and _reason_for_unanalysed(f) == "binary":
            # A font/image/PDF asset that was correctly classified as binary
            # is not a scan failure — counting its bytes against the ratio
            # made a legitimate skill that ships design assets (e.g. a
            # font-heavy canvas/theme skill) read as low-coverage UNVERIFIED
            # for shipping exactly the kind of file it's supposed to ship.
            # Still listed in the ledger below so it's visible, just excluded
            # from the pct this drives.
            ledger.append(CoverageEntry(f.rel_path, "unanalysed", f.size, "binary"))
            continue
        total_bytes += f.size
        if f.rel_path in analysed_paths:
            text = file_texts.get(f.rel_path, "")
            longest_line = max((len(l) for l in text.splitlines()), default=0)
            ext = "." + f.rel_path.rsplit(".", 1)[-1].lower() if "." in f.rel_path else ""
            if longest_line > MINIFIED_LINE_LEN:
                ledger.append(CoverageEntry(f.rel_path, "partial", f.size, "minified/very-long-line, pattern coverage reduced"))
                analysed_bytes += f.size // 2
            elif ext in NO_AST_CODE_EXTENSIONS:
                ledger.append(CoverageEntry(f.rel_path, "partial", f.size, "regex/pattern coverage only, no AST analysis for this language"))
                analysed_bytes += f.size
            else:
                ledger.append(CoverageEntry(f.rel_path, "analysed", f.size, None))
                analysed_bytes += f.size
        else:
            ledger.append(CoverageEntry(f.rel_path, "unanalysed", f.size, _reason_for_unanalysed(f)))

    if total_bytes == 0:
        return ledger, 100.0
    pct = round(100.0 * analysed_bytes / total_bytes, 1)
    return ledger, pct
