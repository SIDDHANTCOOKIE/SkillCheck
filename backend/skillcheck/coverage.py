"""Coverage ledger. See spec I1/I3 — first-class from the first commit."""
from __future__ import annotations

from .graph import ComponentGraph
from .ingest import IngestedFile
from .models import CoverageEntry

MINIFIED_LINE_LEN = 2000


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
        total_bytes += f.size
        if f.rel_path in analysed_paths:
            text = file_texts.get(f.rel_path, "")
            longest_line = max((len(l) for l in text.splitlines()), default=0)
            if longest_line > MINIFIED_LINE_LEN:
                ledger.append(CoverageEntry(f.rel_path, "partial", f.size, "minified/very-long-line, pattern coverage reduced"))
                analysed_bytes += f.size // 2
            else:
                ledger.append(CoverageEntry(f.rel_path, "analysed", f.size, None))
                analysed_bytes += f.size
        else:
            ledger.append(CoverageEntry(f.rel_path, "unanalysed", f.size, _reason_for_unanalysed(f)))

    if total_bytes == 0:
        return ledger, 100.0
    pct = round(100.0 * analysed_bytes / total_bytes, 1)
    return ledger, pct
