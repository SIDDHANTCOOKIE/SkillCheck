"""FastAPI backend: paste a skill or upload a package, get an evidence report.

Two thin endpoints over skillguard.pipeline.scan(). No auth, no persistence —
this is a 12-hour build, scoped per project spec §12 to shipping the engine
plus a minimal callable surface.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from skillguard.pipeline import scan

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

app = FastAPI(title="SkillGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class TextScanRequest(BaseModel):
    name: str = "SKILL.md"
    text: str


@app.post("/api/scan/text")
def scan_text(req: TextScanRequest):
    if not req.text.strip():
        raise HTTPException(400, "text is empty")
    name = req.name.strip() or "SKILL.md"
    result = scan(text_blob=(name, req.text))
    return JSONResponse(content=result.verdict.to_dict() | {"adjudicator_mode": result.adjudicator_mode})


@app.post("/api/scan/upload")
async def scan_upload(file: UploadFile = File(...)):
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large")
    suffix = Path(file.filename or "upload.zip").suffix or ".zip"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name
    try:
        result = scan(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return JSONResponse(content=result.verdict.to_dict() | {"adjudicator_mode": result.adjudicator_mode})


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
