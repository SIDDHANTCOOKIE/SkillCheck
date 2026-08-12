"""Content-addressed report store, so a scan result is shareable and repeat
scans of the same bytes are ~free — without giving up "client-side" rendering.

The id is sha256(RULESET_VERSION + input bytes). A hit means the exact same
bytes were already scanned against the exact same detector/scoring logic —
bump pipeline.RULESET_VERSION whenever that logic changes meaning, and old
cache entries stop being served as if they still reflect current rules.

This is a deliberate scope note, not an oversight: OSV.dev findings are part
of the cached blob, so a stored report can go stale relative to a freshly
published advisory. The API layer surfaces `cached` + `scanned_at` so a
client can offer "rescan for the latest OSV data" rather than silently
presenting a week-old external-data result as current.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "skillcheck_reports.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            ruleset_version TEXT NOT NULL,
            verdict_json TEXT NOT NULL,
            adjudicator_mode TEXT NOT NULL,
            scanned_at REAL NOT NULL
        )"""
    )
    return conn


def report_id(content: bytes, ruleset_version: str) -> str:
    return hashlib.sha256(ruleset_version.encode("utf-8") + b"\x00" + content).hexdigest()[:20]


def get(rid: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT verdict_json, adjudicator_mode, scanned_at FROM reports WHERE id = ?", (rid,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    verdict_json, adjudicator_mode, scanned_at = row
    payload = json.loads(verdict_json)
    payload["adjudicator_mode"] = adjudicator_mode
    payload["report_id"] = rid
    payload["scanned_at"] = scanned_at
    payload["cached"] = True
    return payload


def put(rid: str, ruleset_version: str, verdict_dict: dict, adjudicator_mode: str) -> float:
    scanned_at = time.time()
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO reports (id, ruleset_version, verdict_json, adjudicator_mode, scanned_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (rid, ruleset_version, json.dumps(verdict_dict), adjudicator_mode, scanned_at),
        )
        conn.commit()
    finally:
        conn.close()
    return scanned_at
