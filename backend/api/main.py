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

import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path

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


class TextScanRequest(BaseModel):
    name: str = "SKILL.md"
    text: str
    force: bool = False


def _respond(content_bytes: bytes, force: bool, run_scan) -> JSONResponse:
    rid = store.report_id(content_bytes, RULESET_VERSION)
    if not force:
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
    scanned_at = store.put(rid, RULESET_VERSION, payload, result.adjudicator_mode)
    payload = payload | {
        "adjudicator_mode": result.adjudicator_mode,
        "report_id": rid,
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
    return _respond(req.text.encode("utf-8"), req.force, lambda: scan(text_blob=(name, req.text)))


@app.post("/api/scan/upload")
def scan_upload(request: Request, file: UploadFile = File(...), force: bool = False):
    _enforce_rate_limit(request)

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
            return scan(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    return _respond(contents, force, run)


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
