"""FastAPI backend: paste a skill or upload a package, get an evidence report.

Thin endpoints over skillcheck.pipeline.scan(), plus a content-addressed
report store (skillcheck.store) so a scan result is shareable via a permalink
and a repeat scan of identical bytes is served from SQLite instead of
re-running the pipeline. The frontend stays a client-rendered SPA — it just
fetches by report id instead of always re-scanning, so "client-side" and
"stored/shareable" aren't in tension. See skillcheck/store.py for the
freshness caveat around OSV data in a cached report.
"""
from __future__ import annotations

import re
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from skillcheck import store
from skillcheck.ingest import IngestError
from skillcheck.pipeline import RULESET_VERSION, scan

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
UPLOAD_CHUNK_SIZE = 1024 * 1024

app = FastAPI(title="SkillCheck API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Every response — including the CPU-bound scan endpoints — gets a CSP as
# defence in depth alongside the frontend's move away from innerHTML for
# report data. This is a same-origin, script-free page, so a strict policy
# costs nothing functionally.
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in _SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


# Minimal in-process rate limit on the two scan endpoints, which are the only
# CPU/LLM-cost-bearing routes and are otherwise reachable by any anonymous
# caller (CORS "*", no auth). Sliding window per client IP; this is a single-
# worker mitigation, not a substitute for a real gateway-level limiter in a
# multi-worker deployment.
_RATE_LIMIT_MAX = 20
_RATE_LIMIT_WINDOW_S = 60.0
_rate_buckets: dict[str, deque] = defaultdict(deque)


def _enforce_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket = _rate_buckets[client_ip]
    while bucket and now - bucket[0] > _RATE_LIMIT_WINDOW_S:
        bucket.popleft()
    if len(bucket) >= _RATE_LIMIT_MAX:
        raise HTTPException(429, "too many scan requests, slow down")
    bucket.append(now)


_LLM_PROVIDERS = ("anthropic", "openrouter", "gemini")


class TextScanRequest(BaseModel):
    name: str = "SKILL.md"
    text: str
    force: bool = False
    llm_provider: str | None = None
    llm_api_key: str | None = None


class RepoScanRequest(BaseModel):
    url: str
    force: bool = False
    llm_provider: str | None = None
    llm_api_key: str | None = None


def _llm_override(provider: str | None, api_key: str | None) -> tuple[str, str] | None:
    """A caller-supplied (provider, key) for a bring-your-own-key scan — lets
    a public deployment run with no operator-funded LLM key at all while
    still letting a visitor who brings their own trigger real adjudication.
    The key is used for exactly this one adjudicate() call and nowhere else:
    never logged, never included in the stored/cached report (verdict.to_dict()
    has no such field), and the caller below skips both cache read and write
    for a BYOK request so it can never (a) get served someone else's cached
    non-adjudicated result when it explicitly asked for a fresh judge, or
    (b) let a stranger's scan piggyback for free on this visitor's paid key
    via the shared content-addressed cache."""
    if not api_key:
        return None
    if provider not in _LLM_PROVIDERS:
        raise HTTPException(400, f"llm_provider must be one of {_LLM_PROVIDERS}")
    return provider, api_key


# Owner/repo path segments, GitHub's own allowed charset (alnum, `.`, `-`,
# `_`), first char alnum. Anything failing this never reaches `git clone`'s
# argument list.
_GITHUB_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def _normalize_github_url(raw: str) -> str:
    """Reduce an attacker-supplied string to a `github.com/<owner>/<repo>`
    clone URL, or reject it. The clone URL handed to `git clone` (ingest.py)
    is always rebuilt from the validated owner/repo segments below, never
    from the raw input — so a lookalike host (`github.com.evil.com`),
    embedded credentials (`user:pass@github.com`), an `@`-authority trick
    (`github.com@evil.com`), a non-https scheme, or a path-traversal segment
    never reaches the subprocess, regardless of what slipped past any single
    check below.
    """
    try:
        parts = urlsplit(raw.strip())
    except ValueError as e:
        raise HTTPException(400, f"invalid URL: {e}") from e
    if parts.scheme != "https":
        raise HTTPException(400, "only https:// GitHub URLs are accepted")
    if parts.username or parts.password:
        raise HTTPException(400, "URL must not contain embedded credentials")
    if parts.hostname != "github.com":
        raise HTTPException(400, "only github.com URLs are accepted")
    if parts.port not in (None, 443):
        raise HTTPException(400, "unexpected port in URL")
    segments = [s for s in parts.path.strip("/").split("/") if s]
    if len(segments) < 2:
        raise HTTPException(400, "URL must point at a github.com/<owner>/<repo>")
    owner, repo = segments[0], segments[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _GITHUB_SEGMENT_RE.match(owner) or not _GITHUB_SEGMENT_RE.match(repo):
        raise HTTPException(400, "owner/repo contains unexpected characters")
    return f"https://github.com/{owner}/{repo}.git"


def _respond(content_bytes: bytes, force: bool, run_scan, *, skip_cache: bool = False) -> JSONResponse:
    rid = store.report_id(content_bytes, RULESET_VERSION)
    if not force and not skip_cache:
        cached = store.get(rid)
        if cached is not None:
            return JSONResponse(content=cached, headers={"Cache-Control": "no-store"})

    try:
        result = run_scan()
    except IngestError as e:
        # A malformed/oversized/traversal-attempting archive is a 400, not a
        # 500 — the scanner doing exactly what it should with hostile input.
        raise HTTPException(400, str(e)) from e

    payload = result.verdict.to_dict()
    if skip_cache:
        # A bring-your-own-key scan is never persisted to the shared,
        # unauthenticated report store — see _llm_override()'s docstring for
        # why (no permalink either, for the same reason: nothing to point at).
        scanned_at = time.time()
        report_id = None
    else:
        report_id = rid
        scanned_at = store.put(rid, RULESET_VERSION, payload, result.adjudicator_mode)
    payload = payload | {
        "adjudicator_mode": result.adjudicator_mode,
        "report_id": report_id,
        "scanned_at": scanned_at,
        "cached": False,
    }
    return JSONResponse(content=payload, headers={"Cache-Control": "no-store"})


# Both endpoints below are plain `def`, not `async def` — this pipeline is
# CPU-bound (extraction, regex over megabytes, an O(n^2) corroboration pass,
# a synchronous-under-the-hood LLM HTTP call) and previously ran inline on
# the event loop from an `async def` handler, so one slow scan froze every
# other request including /api/health. A sync def is dispatched to FastAPI's
# threadpool automatically.

@app.post("/api/scan/text")
def scan_text(req: TextScanRequest, request: Request):
    _enforce_rate_limit(request)
    if not req.text.strip():
        raise HTTPException(400, "text is empty")
    name = req.name.strip() or "SKILL.md"
    override = _llm_override(req.llm_provider, req.llm_api_key)
    return _respond(
        req.text.encode("utf-8"), req.force,
        lambda: scan(text_blob=(name, req.text), llm_override=override),
        skip_cache=override is not None,
    )


@app.post("/api/scan/upload")
def scan_upload(
    request: Request, file: UploadFile = File(...), force: bool = False,
    llm_provider: str | None = None, llm_api_key: str | None = None,
):
    _enforce_rate_limit(request)
    override = _llm_override(llm_provider, llm_api_key)

    # Stream the upload and enforce the size cap as we go, rather than
    # buffering the whole body first and checking afterward — the latter
    # lets an arbitrarily large POST body sit in memory before ever being
    # rejected. `.file` is the underlying (Spooled)TemporaryFile; reading it
    # synchronously is the documented pattern for a sync UploadFile handler.
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = file.file.read(UPLOAD_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "file too large")
        chunks.append(chunk)
    contents = b"".join(chunks)

    suffix = Path(file.filename or "upload.zip").suffix or ".zip"

    def run():
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name
        try:
            return scan(tmp_path, llm_override=override)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    return _respond(contents, force, run, skip_cache=override is not None)


@app.post("/api/scan/repo")
def scan_repo(req: RepoScanRequest, request: Request):
    _enforce_rate_limit(request)
    clone_url = _normalize_github_url(req.url)
    override = _llm_override(req.llm_provider, req.llm_api_key)
    # Cache key is the normalized clone URL, not a commit SHA — ingest.py's
    # `git clone --depth 1` doesn't resolve one back to the caller. Same
    # caveat as OSV data in a cached report (see module docstring): a repeat
    # scan of the same URL serves the first scan's result until `force=true`
    # bypasses it, even if the repo has since changed.
    return _respond(
        clone_url.encode("utf-8"), req.force, lambda: scan(clone_url, llm_override=override),
        skip_cache=override is not None,
    )


@app.get("/api/report/{report_id}")
def get_report(report_id: str):
    cached = store.get(report_id)
    if cached is None:
        raise HTTPException(404, "no report with that id")
    return JSONResponse(content=cached, headers={"Cache-Control": "no-store"})


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(404, "frontend not built")
    return FileResponse(index_path)


@app.get("/app.js")
def app_js():
    # Served same-origin so the strict `script-src 'self'` CSP (no
    # 'unsafe-inline') allows it — the app logic used to be an inline
    # <script> block, which a real script-src policy blocks outright.
    js_path = FRONTEND_DIR / "app.js"
    if not js_path.exists():
        raise HTTPException(404, "frontend not built")
    return FileResponse(js_path, media_type="application/javascript")


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
