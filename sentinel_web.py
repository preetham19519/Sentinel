#!/usr/bin/env python3
"""Local browser interface for the bounded Sentinel investigator."""
from __future__ import annotations

import json
import re
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from dataclasses import asdict
from urllib.parse import urlparse

from sentinel import investigate

ROOT = Path(__file__).resolve().parent
SCENARIOS = ROOT / "scenarios"
WEB = ROOT / "web"
JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
MAX_BODY = 16_384
MODEL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")


def scenario_catalog() -> list[dict[str, str]]:
    items = []
    for path in sorted(SCENARIOS.glob("*/incident.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            items.append({"key": path.parent.name, "scenario_id": data.get("scenario_id", path.parent.name),
                          "service": data.get("service", "Unknown service"),
                          "summary": data.get("incident", "Incident scenario")})
        except (OSError, json.JSONDecodeError):
            continue
    return items


def add_event(job_id: str, event: dict[str, Any]) -> None:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is not None:
            job["events"].append({"at": datetime.now(timezone.utc).isoformat(), **event})


def run_job(job_id: str, scenario_key: str, max_steps: int, use_llm: bool, model: str) -> None:
    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
    add_event(job_id, {"phase": "starting", "message": "Investigation started."})
    try:
        report = investigate(SCENARIOS / scenario_key / "incident.json", max_steps=max_steps,
                             planner_endpoint="http://localhost:11434/v1" if use_llm else None,
                             model=model, progress_callback=lambda event: add_event(job_id, event))
        with JOBS_LOCK:
            JOBS[job_id]["report"] = asdict(report)
            JOBS[job_id]["status"] = "complete"
    except Exception as exc:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = f"{type(exc).__name__}: {exc}"


class Handler(BaseHTTPRequestHandler):
    server_version = "SentinelLocal/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print("[Sentinel UI] " + fmt % args)

    def send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            try:
                body = (WEB / "index.html").read_bytes()
            except OSError:
                self.send_error(500, "web/index.html is missing")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/scenarios":
            self.send_json({"scenarios": scenario_catalog()})
        elif path.startswith("/api/investigations/"):
            job_id = path.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                snapshot = json.loads(json.dumps(job)) if job is not None else None
            self.send_json(snapshot or {"error": "Investigation not found"}, 200 if snapshot else 404)
        else:
            self.send_error(404, "Not found")

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/investigations":
            self.send_error(404, "Not found")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                self.send_json({"error": "Request body must be between 1 and 16384 bytes."}, 400)
                return
            request = json.loads(self.rfile.read(length))
            if not isinstance(request, dict):
                raise ValueError("Expected a JSON object.")
            key = request.get("scenario")
            allowed = {item["key"] for item in scenario_catalog()}
            if key not in allowed:
                self.send_json({"error": "Choose a scenario from the available list."}, 400)
                return
            max_steps = request.get("max_steps", 3)
            if isinstance(max_steps, bool) or not isinstance(max_steps, int) or not 1 <= max_steps <= 3:
                self.send_json({"error": "max_steps must be from 1 to 3."}, 400)
                return
            use_llm = request.get("use_llm", False) is True
            model = request.get("model", "qwen3:4b")
            if not isinstance(model, str) or not MODEL_RE.fullmatch(model):
                self.send_json({"error": "Model name contains unsupported characters."}, 400)
                return
            job_id = uuid.uuid4().hex
            with JOBS_LOCK:
                JOBS[job_id] = {"id": job_id, "status": "queued", "events": [], "report": None, "error": None}
            threading.Thread(target=run_job, args=(job_id, key, max_steps, use_llm, model), daemon=True).start()
            self.send_json({"id": job_id, "status": "queued"}, 202)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": f"Invalid request: {exc}"}, 400)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("Sentinel Incident Lab is running at http://127.0.0.1:8765")
    print("Keep this terminal open while using the browser interface. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Sentinel Incident Lab.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
