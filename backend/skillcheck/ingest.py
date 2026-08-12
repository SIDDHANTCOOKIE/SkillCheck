"""Ingestion: turn a path/zip/tar/git-url/raw-text into a flat file set.

Everything downstream operates on `IngestedFile` objects. Binary detection
happens here so the coverage ledger (I1/I3) has an entry for every byte from
the first stage.
"""
from __future__ import annotations

import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

TEXT_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".ts",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env", ".rb", ".ps1",
    ".xml", ".html", ".htm", ".cjs", ".mjs",
}

BINARY_MAGIC = {
    b"\x89PNG": "png",
    b"\xff\xd8\xff": "jpeg",
    b"GIF8": "gif",
    b"%PDF": "pdf",
    b"PK\x03\x04": "zip",
    b"\x7fELF": "elf",
    b"MZ": "pe-exe",
}


@dataclass
class IngestedFile:
    rel_path: str
    abs_path: Path
    size: int
    is_binary: bool
    is_text: bool


@dataclass
class IngestResult:
    root: Path
    files: list[IngestedFile]
    tmpdir: tempfile.TemporaryDirectory | None = None


def _sniff_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return True
    for magic in BINARY_MAGIC:
        if head.startswith(magic):
            return True
    if b"\x00" in head:
        return True
    return False


def _walk(root: Path) -> list[IngestedFile]:
    files: list[IngestedFile] = []
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        if ".git" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        size = p.stat().st_size
        is_bin = _sniff_binary(p)
        is_text = (not is_bin) or (p.suffix.lower() in TEXT_EXTENSIONS)
        files.append(IngestedFile(rel, p, size, is_bin, is_text and not is_bin))
    return files


def ingest_path(source: str) -> IngestResult:
    """Ingest a directory, .zip, .tar[.gz], a git URL, or a raw text blob path."""
    src = Path(source)

    if src.is_dir():
        return IngestResult(root=src, files=_walk(src))

    if src.is_file() and zipfile.is_zipfile(src):
        tmp = tempfile.TemporaryDirectory(prefix="skillguard_")
        out = Path(tmp.name)
        with zipfile.ZipFile(src) as zf:
            zf.extractall(out)
        return IngestResult(root=out, files=_walk(out), tmpdir=tmp)

    if src.is_file() and tarfile.is_tarfile(src):
        tmp = tempfile.TemporaryDirectory(prefix="skillguard_")
        out = Path(tmp.name)
        with tarfile.open(src) as tf:
            tf.extractall(out)  # noqa: S202 - trusted local eval harness input
        return IngestResult(root=out, files=_walk(out), tmpdir=tmp)

    if source.startswith(("http://", "https://")) and source.endswith(".git"):
        tmp = tempfile.TemporaryDirectory(prefix="skillguard_")
        out = Path(tmp.name)
        subprocess.run(
            ["git", "clone", "--depth", "1", source, str(out)],
            check=True, capture_output=True, timeout=120,
        )
        return IngestResult(root=out, files=_walk(out), tmpdir=tmp)

    if src.is_file():
        # A bare file is scanned as itself, not its containing directory —
        # scanning the parent silently pulled in sibling files (e.g. every
        # other fixture in the same eval corpus directory) and made every
        # loose-file scan report findings that didn't belong to it.
        size = src.stat().st_size
        is_bin = _sniff_binary(src)
        is_text = (not is_bin) or (src.suffix.lower() in TEXT_EXTENSIONS)
        f = IngestedFile(src.name, src, size, is_bin, is_text and not is_bin)
        return IngestResult(root=src.parent, files=[f])

    raise ValueError(f"Cannot ingest source: {source!r}")


def ingest_text_blob(name: str, text: str) -> IngestResult:
    """Ingest a single pasted document (e.g. a SKILL.md paste) as a one-file set."""
    tmp = tempfile.TemporaryDirectory(prefix="skillguard_")
    out = Path(tmp.name)
    target = out / name
    target.write_text(text, encoding="utf-8")
    return IngestResult(root=out, files=_walk(out), tmpdir=tmp)


def cleanup(result: IngestResult) -> None:
    if result.tmpdir is not None:
        result.tmpdir.cleanup()
