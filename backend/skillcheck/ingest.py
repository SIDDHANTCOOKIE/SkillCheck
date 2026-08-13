"""Ingestion: turn a path/zip/tar/git-url/raw-text into a flat file set.

Everything downstream operates on `IngestedFile` objects. Binary detection
happens here so the coverage ledger (I1/I3) has an entry for every byte from
the first stage.

This module is the untrusted-input boundary: `source` and the archive bytes
it points at are attacker-controlled (uploaded by an anonymous HTTP caller in
api/main.py). Every extraction path below is written under that assumption —
see the audit plan's P0-1/P0-2/P0-4/P1-5 items for the concrete bugs this
replaced (arbitrary file write via an absolute blob name, unfiltered tar
extraction permitting traversal/symlink escape, no bound on decompressed
size, and cross-file reachability silently breaking on any real zip because
of its top-level folder).
"""
from __future__ import annotations

import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

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

# Bounds on what a single archive is allowed to expand to. api/main.py caps
# the *compressed* upload at 25 MB; these bound the decompressed result, so a
# small crafted archive can't fill the disk or exhaust inodes (P0-4).
MAX_EXTRACTED_BYTES = 200 * 1024 * 1024
MAX_EXTRACTED_FILES = 5000

_IGNORED_TOP_LEVEL = {"__MACOSX"}  # cosmetic zip artifact, not a real package layout


class IngestError(ValueError):
    """A problem with the submitted archive/path itself, not a scanner bug."""


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


def _make_ingested_file(rel: str, p: Path) -> IngestedFile:
    size = p.stat().st_size
    sniffed_binary = _sniff_binary(p)
    # A known text extension overrides the binary sniff — the previous
    # `is_text and not is_bin` formulation made this branch unreachable
    # (whenever is_bin was True, `not is_bin` was already False, so the
    # extension check never fired), meaning a .md file starting with a
    # stray NUL byte was silently dropped from scanning entirely with no
    # accurate reason recorded. TEXT_EXTENSIONS now actually does something.
    is_known_text = p.suffix.lower() in TEXT_EXTENSIONS
    is_binary = sniffed_binary and not is_known_text
    return IngestedFile(rel, p, size, is_binary, not is_binary)


def _walk(root: Path) -> list[IngestedFile]:
    files: list[IngestedFile] = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            # Never follow a symlink for scanning purposes — a link target
            # outside the extraction root is exactly the file-disclosure
            # primitive this ingestion boundary exists to prevent.
            continue
        if p.is_dir():
            continue
        if ".git" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        files.append(_make_ingested_file(rel, p))
    return files


def _effective_root(out: Path) -> Path:
    """A submitted zip/tar almost always wraps its contents in one top-level
    folder (`my-skill/SKILL.md`, not `SKILL.md`) — real archive tooling does
    this by default. `_find_root` in graph.py only recognises SKILL.md at the
    scan root, so without unwrapping, every real upload silently loses
    reachability and therefore every cross-file capability chain (P1-5).
    Descend through single-child wrapper directories, stopping as soon as the
    level has more than one meaningful entry (i.e. looks like the real
    package root) or a real file."""
    root = out
    while True:
        try:
            entries = [e for e in root.iterdir() if e.name not in _IGNORED_TOP_LEVEL]
        except OSError:
            break
        if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
            root = entries[0]
            continue
        break
    return root


def _reject_unsafe_member_names(names: list[str], kind: str) -> None:
    """Defence in depth ahead of extraction, independent of whatever
    protection the archive library itself provides. An absolute path or a
    `..` path segment must never be allowed to write outside the extraction
    directory (P0-2)."""
    for name in names:
        norm = name.replace("\\", "/")
        if norm.startswith("/"):
            raise IngestError(f"{kind} member has an unsafe absolute path: {name!r}")
        first = norm.split("/", 1)[0]
        if len(first) == 2 and first[1] == ":":  # Windows drive letter, e.g. "C:"
            raise IngestError(f"{kind} member has an unsafe absolute path: {name!r}")
        if ".." in norm.split("/"):
            raise IngestError(f"{kind} member attempts path traversal: {name!r}")


def _extract_zip_bounded(src: Path, out: Path) -> None:
    with zipfile.ZipFile(src) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        _reject_unsafe_member_names([i.filename for i in infos], "zip")
        if len(infos) > MAX_EXTRACTED_FILES:
            raise IngestError(f"zip contains more than {MAX_EXTRACTED_FILES} files")
        total = sum(i.file_size for i in infos)
        if total > MAX_EXTRACTED_BYTES:
            raise IngestError(f"zip would extract to more than {MAX_EXTRACTED_BYTES} bytes")
        zf.extractall(out)


def _extract_tar_bounded(src: Path, out: Path) -> None:
    with tarfile.open(src) as tf:
        members = tf.getmembers()
        regular = [m for m in members if m.isreg()]
        _reject_unsafe_member_names([m.name for m in members], "tar")
        if len(regular) > MAX_EXTRACTED_FILES:
            raise IngestError(f"tar contains more than {MAX_EXTRACTED_FILES} files")
        total = sum(m.size for m in regular)
        if total > MAX_EXTRACTED_BYTES:
            raise IngestError(f"tar would extract to more than {MAX_EXTRACTED_BYTES} bytes")
        # filter="data" (PEP 706) refuses device/special files and refuses to
        # resolve a symlink/hardlink target outside `out` — this is the fix
        # for the unfiltered-extractall traversal/symlink-escape bug. It is
        # available as an explicit opt-in on this Python version; do not
        # silently fall back to the unfiltered extractor if it's missing.
        tf.extractall(out, filter="data")


def ingest_path(source: str) -> IngestResult:
    """Ingest a directory, .zip, .tar[.gz], a git URL, or a raw text blob path."""
    src = Path(source)

    if src.is_dir():
        return IngestResult(root=src, files=_walk(src))

    if src.is_file() and zipfile.is_zipfile(src):
        tmp = tempfile.TemporaryDirectory(prefix="skillcheck_")
        out = Path(tmp.name)
        try:
            _extract_zip_bounded(src, out)
        except IngestError:
            tmp.cleanup()
            raise
        except (zipfile.BadZipFile, OSError) as e:
            tmp.cleanup()
            raise IngestError(f"could not extract zip: {e}") from e
        root = _effective_root(out)
        return IngestResult(root=root, files=_walk(root), tmpdir=tmp)

    if src.is_file() and tarfile.is_tarfile(src):
        tmp = tempfile.TemporaryDirectory(prefix="skillcheck_")
        out = Path(tmp.name)
        try:
            _extract_tar_bounded(src, out)
        except IngestError:
            tmp.cleanup()
            raise
        except (tarfile.TarError, OSError) as e:
            # Includes tarfile's own filter="data" rejections (absolute/outside
            # symlinks, device files, unsafe permissions) — normalized to the
            # same error type as our own pre-checks so callers only need to
            # handle one exception class from this module.
            tmp.cleanup()
            raise IngestError(f"could not extract tar: {e}") from e
        root = _effective_root(out)
        return IngestResult(root=root, files=_walk(root), tmpdir=tmp)

    if source.startswith(("http://", "https://")) and source.endswith(".git"):
        tmp = tempfile.TemporaryDirectory(prefix="skillcheck_")
        out = Path(tmp.name)
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", source, str(out)],
                check=True, capture_output=True, timeout=120,
            )
        except Exception as e:
            tmp.cleanup()
            raise IngestError(f"could not clone repository: {e}") from e
        root = _effective_root(out)
        return IngestResult(root=root, files=_walk(root), tmpdir=tmp)

    if src.is_file():
        # A bare file is scanned as itself, not its containing directory —
        # scanning the parent silently pulled in sibling files (e.g. every
        # other fixture in the same eval corpus directory) and made every
        # loose-file scan report findings that didn't belong to it.
        return IngestResult(root=src.parent, files=[_make_ingested_file(src.name, src)])

    raise IngestError(f"Cannot ingest source: {source!r}")


def safe_blob_name(name: str) -> str:
    """Reduce a caller-supplied filename to a single safe path component.

    `req.name` on POST /api/scan/text is fully attacker-controlled. Before
    this existed, `ingest_text_blob` did `out / name` directly — `pathlib`
    discards the left operand when the right one is absolute
    (`Path("/tmp/x") / "/etc/passwd" == Path("/etc/passwd")`), and normal
    `../` segments escape just as easily either way — turning a "paste a
    skill" endpoint into an unauthenticated arbitrary file write (P0-1).
    """
    raw = (name or "").strip().replace("\\", "/")
    candidate = PurePosixPath(raw).name  # last component only; drops any directory part
    if not candidate or candidate in (".", ".."):
        candidate = "SKILL.md"
    return candidate


def ingest_text_blob(name: str, text: str) -> IngestResult:
    """Ingest a single pasted document (e.g. a SKILL.md paste) as a one-file set."""
    tmp = tempfile.TemporaryDirectory(prefix="skillcheck_")
    out = Path(tmp.name)
    safe_name = safe_blob_name(name)
    target = out / safe_name
    # Belt and suspenders: confirm the resolved target is still inside `out`
    # even after basename reduction, in case of a platform path quirk.
    if target.resolve().parent != out.resolve():
        tmp.cleanup()
        raise IngestError(f"unsafe blob name: {name!r}")
    try:
        target.write_text(text, encoding="utf-8")
    except OSError as e:
        # e.g. a character illegal in a filename on this OS (Windows rejects
        # `<>:"|?*`) — a submitted name we haven't otherwise rejected but
        # still can't write. Report it as the caller's bad input, not a
        # server error.
        tmp.cleanup()
        raise IngestError(f"could not write blob with name {name!r}: {e}") from e
    return IngestResult(root=out, files=_walk(out), tmpdir=tmp)


def cleanup(result: IngestResult) -> None:
    if result.tmpdir is not None:
        result.tmpdir.cleanup()
