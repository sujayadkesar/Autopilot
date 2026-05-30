r"""
Recycle Bin Agent — $Recycle.Bin $I metadata parser.

Every file sent to the Recycle Bin produces a paired $I<id> (metadata) and
$R<id> (contents) file under \$Recycle.Bin\<SID>\. The $I file is a small binary
record we parse in pure Python (no external tool needed):

  Vista–Win8 (version 1):
    0x00  int64  header (0x01)
    0x08  int64  original file size
    0x10  int64  deletion time (Windows FILETIME, UTC)
    0x18  520B   original path, fixed 260 UTF-16LE chars

  Win10+ (version 2):
    0x00  int64  header (0x02)
    0x08  int64  original file size
    0x10  int64  deletion time (FILETIME, UTC)
    0x18  int32  path length in chars (incl. null)
    0x1C  ...    original path, UTF-16LE
"""

from __future__ import annotations

import csv
import shutil
import struct
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

_REPO_ROOT = Path(__file__).parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.base_agent import BaseAgent, ExtractResult, ParseResult
from core.case_context import CaseContext
from core.fsutil import safe_exists, safe_glob, safe_iterdir, safe_is_dir
from core.progress_bus import ProgressBus

_RECYCLE_DIRS = ["$Recycle.Bin", "$RECYCLE.BIN", "RECYCLER"]


def _filetime_to_iso(ft: int) -> str:
    """Convert a Windows FILETIME (100-ns since 1601) to ISO-8601 UTC."""
    if ft <= 0:
        return ""
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc)
                + timedelta(microseconds=ft / 10)).strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return ""


def parse_i_file(data: bytes) -> Optional[dict]:
    """Parse $I metadata bytes → {size, deleted, original_path}."""
    if len(data) < 24:
        return None
    try:
        header, size, ft = struct.unpack_from("<qqq", data, 0)
        if header == 2:
            (path_len,) = struct.unpack_from("<i", data, 24)
            raw = data[28:28 + path_len * 2]
        else:  # version 1 (fixed 260 chars)
            raw = data[24:24 + 520]
        path = raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        return {"size": size, "deleted": _filetime_to_iso(ft), "original_path": path}
    except Exception:
        return None


class Agent(BaseAgent):
    name = "recyclebin"
    display_name = "Recycle Bin ($I metadata)"
    description = "Deleted-file original paths, sizes, and deletion timestamps per user SID"
    version = "1.0"
    artifact_subdirs = ["."]

    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        progress.stage_started(self.name, "extract")
        t0 = time.time()
        root = ctx.mount_point
        copied: List[Path] = []
        errors: List[str] = []
        dest = ctx.agent_artifacts_dir(self.name)
        dest.mkdir(parents=True, exist_ok=True)

        rec_root = None
        for d in _RECYCLE_DIRS:
            cand = root / d
            if safe_exists(cand):
                rec_root = cand
                break
        if rec_root is None:
            progress.stage_done(self.name, "extract")
            return ExtractResult(agent=self.name, success=False,
                                 error="$Recycle.Bin not found", elapsed=time.time() - t0)

        for sid_dir in safe_iterdir(rec_root):
            if not safe_is_dir(sid_dir):
                continue
            sid = sid_dir.name
            for i_file in safe_glob(sid_dir, "$I*"):
                try:
                    dst = dest / f"{sid}__{i_file.name}"
                    shutil.copy2(str(i_file), str(dst))
                    copied.append(dst)
                except OSError as e:
                    errors.append(f"{i_file.name}: {e}")

        progress.log("INFO", self.name, f"Copied {len(copied)} $I metadata file(s)")
        progress.stage_done(self.name, "extract")
        return ExtractResult(agent=self.name, success=len(copied) > 0, artifacts=copied,
                             elapsed=time.time() - t0, error="; ".join(errors[:5]),
                             metadata={"i_count": len(copied)})

    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        progress.stage_started(self.name, "parse")
        t0 = time.time()
        parsed_dir = ctx.agent_parsed_dir(self.name)
        parsed_dir.mkdir(parents=True, exist_ok=True)
        out_csv = parsed_dir / "recyclebin.csv"
        rows = []

        for i_file in sorted(ctx.agent_artifacts_dir(self.name).glob("*$I*")):
            try:
                meta = parse_i_file(i_file.read_bytes())
            except Exception:
                meta = None
            if not meta:
                continue
            sid = i_file.name.split("__", 1)[0]
            rows.append({"SID": sid, "OriginalPath": meta["original_path"],
                         "SizeBytes": meta["size"], "DeletedUTC": meta["deleted"],
                         "Marker": i_file.name})

        if rows:
            with open(out_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["SID", "OriginalPath", "SizeBytes",
                                                  "DeletedUTC", "Marker"])
                w.writeheader()
                w.writerows(rows)

        progress.log("INFO", self.name, f"Parsed {len(rows)} recycle-bin record(s)")
        progress.stage_done(self.name, "parse")
        return ParseResult(agent=self.name, success=bool(rows),
                           output_files=[out_csv] if rows else [],
                           elapsed=time.time() - t0,
                           metadata={"record_count": len(rows)})
