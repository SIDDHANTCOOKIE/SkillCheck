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
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from skillcheck import store
from skillcheck.pipeline import RULESET_VERSION, scan

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

app = FastAPI(title="SkillCheck API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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

    result = run_scan()
    payload = result.verdict.to_dict()
    scanned_at = store.put(rid, RULESET_VERSION, payload, result.adjudicator_mode)
    payload = payload | {
        "adjudicator_mode": result.adjudicator_mode,
        "report_id": rid,
        "scanned_at": scanned_at,
        "cached": False,
    }
    return JSONResponse(content=payload, headers={"Cache-Control": "no-store"})


@app.post("/api/scan/text")
def scan_text(req: TextScanRequest):
    if not req.text.strip():
        raise HTTPException(400, "text is empty")
    name = req.name.strip() or "SKILL.md"
    return _respond(req.text.encode("utf-8"), req.force, lambda: scan(text_blob=(name, req.text)))


@app.post("/api/scan/upload")
async def scan_upload(file: UploadFile = File(...), force: bool = False):
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large")
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


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
