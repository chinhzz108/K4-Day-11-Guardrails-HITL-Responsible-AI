"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None) -> str:
        """Store input + start timestamp keyed by request_id/user_id."""
        req_id = request_id or f"req-{len(self.logs) + len(self._open) + 1}"
        self._open[req_id] = {
            "start_time": time.time(),
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "input": text,
        }
        return req_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ) -> dict:
        """Store output, layer decision, latency; append to self.logs."""
        req_id = request_id or f"req-{len(self.logs) + 1}"
        open_data = self._open.pop(req_id, None)
        now = time.time()
        latency_ms = round((now - open_data["start_time"]) * 1000, 2) if open_data else 0.0
        input_text = open_data["input"] if open_data else ""
        timestamp = open_data["timestamp"] if open_data else utc_now_iso()

        entry = {
            "request_id": req_id,
            "timestamp": timestamp,
            "user_id": user_id,
            "input": input_text,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str = "outputs/audit_log.json") -> Path:
        """Write logs to disk (JSON array)."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
