"""Global and per-agent manifest tracking (SHA256, counts, timings)."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


class ManifestEntry:
    def __init__(self, agent: str, artifact_name: str, path: Path):
        self.agent = agent
        self.artifact_name = artifact_name
        self.path = str(path)
        self.size_bytes = path.stat().st_size if path.exists() else 0
        self.sha256 = sha256(path) if path.exists() else ""


class GlobalManifest:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        self._agent_timings: Dict[str, Dict[str, float]] = {}
        self._started_at = time.time()

    def add_artifact(self, entry: ManifestEntry) -> None:
        with self._lock:
            self._entries.append({
                "agent": entry.agent,
                "artifact": entry.artifact_name,
                "path": entry.path,
                "size_bytes": entry.size_bytes,
                "sha256": entry.sha256,
            })

    def record_timing(self, agent: str, stage: str, elapsed: float) -> None:
        with self._lock:
            if agent not in self._agent_timings:
                self._agent_timings[agent] = {}
            self._agent_timings[agent][stage] = round(elapsed, 2)

    def save(self, output_dir: Path, ctx_dict: dict, tool_versions: Optional[dict] = None) -> Path:
        data = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_elapsed_seconds": round(time.time() - self._started_at, 1),
            "case": ctx_dict,
            "tool_versions": tool_versions or {},
            "agent_timings": self._agent_timings,
            "artifacts": self._entries,
        }
        path = output_dir / "manifest.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return path
