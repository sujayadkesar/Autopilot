"""
Pure-Python agent for high-value artefacts that need NO external tool.

Each sub-module produces a CSV that downstream analysis consumes.

Sub-modules:
  pca/                — Program Compatibility Assistant (Win 11 program-launch DB)
  scheduled_tasks/    — On-disk task XML definitions (persistence)
  wer/                — Windows Error Reporting (crash telemetry → execution proof)
  jumplists/          — Jump Lists (App ID + recent files via OLE compound docs)

Why these four together?
  None of them need an EZ Tool or PyInstaller bundle. All four are simple
  text/XML/binary parses that fit Python's stdlib. Bundling them in one agent
  keeps the agent count manageable while still giving each artefact its own
  output folder and CSV.
"""

from __future__ import annotations

import csv
import logging
import shutil
import struct
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.base_agent import BaseAgent, ExtractResult, ParseResult
from core.case_context import CaseContext
from core.fsutil import safe_exists, safe_glob, safe_iterdir, safe_is_dir
from core.progress_bus import ProgressBus

log = logging.getLogger("dfir.pjw")

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_iso(ft: int) -> str:
    """Convert a Windows FILETIME (100-ns ticks since 1601) to ISO string."""
    if not ft:
        return ""
    try:
        return (_FILETIME_EPOCH + timedelta(microseconds=ft / 10)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, ValueError):
        return ""


# ────────────────────────────────────────────────────────────────────────────
# 1. PCA — Program Compatibility Assistant (Windows 11 22H2+)
# ────────────────────────────────────────────────────────────────────────────

PCA_FILES = [
    r"Windows\appcompat\pca\PcaAppLaunchDic.txt",   # path|UTC_timestamp pairs
    r"Windows\appcompat\pca\PcaGeneralDb0.txt",     # general events
    r"Windows\appcompat\pca\PcaGeneralDb1.txt",
]


def _parse_pca_appdic(src: Path, out_csv: Path) -> int:
    """Parse PcaAppLaunchDic.txt — pipe-delimited path|timestamp."""
    n = 0
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    try:
        text = src.read_text(encoding="utf-16", errors="replace")
    except Exception:
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return 0
    with open(out_csv, "w", encoding="utf-8", newline="") as fout:
        w = csv.writer(fout)
        w.writerow(["executable_path", "launch_time_utc", "source_file"])
        for line in text.splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|", 1)
            if len(parts) != 2:
                continue
            w.writerow([parts[0], parts[1], src.name])
            n += 1
    return n


def _parse_pca_general(src: Path, out_csv: Path) -> int:
    """Parse PcaGeneralDb0/1.txt — pipe-delimited general events."""
    n = 0
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    try:
        text = src.read_text(encoding="utf-16", errors="replace")
    except Exception:
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return 0
    rows: List[List[str]] = []
    headers: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Format observed: <ts>|<event_kind>|<exe_path>|<vendor>|<product>|<version>|<extra>
        parts = line.split("|")
        if len(parts) < 3:
            continue
        if not headers:
            headers = ["timestamp", "event", "executable_path", "vendor", "product",
                       "version", "extra1", "extra2"]
        # pad to 8 columns
        while len(parts) < 8:
            parts.append("")
        rows.append(parts[:8])
        n += 1
    if not headers:
        return 0
    with open(out_csv, "w", encoding="utf-8", newline="") as fout:
        w = csv.writer(fout)
        w.writerow(headers + ["source_file"])
        for r in rows:
            w.writerow(r + [src.name])
    return n


# ────────────────────────────────────────────────────────────────────────────
# 2. Scheduled Tasks XML
# ────────────────────────────────────────────────────────────────────────────

TASKS_DIR = r"Windows\System32\Tasks"


def _parse_task_xml(xml_path: Path, root_dir: Path) -> Optional[Dict[str, str]]:
    """Read a single task XML and produce a flat dict of forensically-relevant fields."""
    try:
        # Strip XML namespace to make findall easier
        text = xml_path.read_text(encoding="utf-16", errors="replace")
        if not text.lstrip().startswith("<"):
            text = xml_path.read_text(encoding="utf-8", errors="replace")
        # Remove default namespace declaration to simplify XPath
        text = text.replace('xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"', "")
        root = ET.fromstring(text)
    except Exception as e:
        log.debug("Task XML parse failed for %s: %s", xml_path, e)
        return None

    try:
        rel = xml_path.relative_to(root_dir)
        task_path = "\\" + str(rel)
    except ValueError:
        task_path = xml_path.name

    def _find_text(tag: str) -> str:
        el = root.find(f".//{tag}")
        return (el.text or "").strip() if el is not None else ""

    actions_cmd = ""
    actions_args = ""
    actions_user = ""
    exec_el = root.find(".//Exec")
    if exec_el is not None:
        cmd_el = exec_el.find("Command")
        arg_el = exec_el.find("Arguments")
        if cmd_el is not None and cmd_el.text:
            actions_cmd = cmd_el.text.strip()
        if arg_el is not None and arg_el.text:
            actions_args = arg_el.text.strip()

    principal = root.find(".//Principal")
    if principal is not None:
        uid_el = principal.find("UserId")
        if uid_el is not None and uid_el.text:
            actions_user = uid_el.text.strip()

    return {
        "task_path":   task_path,
        "command":     actions_cmd,
        "arguments":   actions_args,
        "user_id":     actions_user,
        "author":      _find_text("Author"),
        "description": _find_text("Description"),
        "date":        _find_text("Date"),
        "uri":         _find_text("URI"),
        "triggers":    ", ".join(t.tag for t in (root.find(".//Triggers") or [])),
    }


# ────────────────────────────────────────────────────────────────────────────
# 3. WER — Windows Error Reporting
# ────────────────────────────────────────────────────────────────────────────

WER_DIRS = [
    r"ProgramData\Microsoft\Windows\WER\ReportArchive",
    r"ProgramData\Microsoft\Windows\WER\ReportQueue",
]
WER_USER_REL = r"AppData\Local\Microsoft\Windows\WER"


def _parse_wer_file(src: Path) -> Optional[Dict[str, str]]:
    """Parse a single .wer file (key=value text format, often UTF-16)."""
    try:
        text = src.read_text(encoding="utf-16", errors="replace")
        if not text.strip().startswith("Version="):
            text = src.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    fields: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        fields[k.strip()] = v.strip()
    if not fields:
        return None
    return {
        "report_id":        fields.get("ReportIdentifier", ""),
        "event_type":       fields.get("EventType", ""),
        "event_time":       fields.get("EventTime", ""),
        "app_name":         fields.get("AppName", ""),
        "app_path":         fields.get("AppPath", ""),
        "app_version":      fields.get("AppVersion", ""),
        "exception_code":   fields.get("Sig[1].Value", ""),
        "module_name":      fields.get("Sig[2].Value", ""),
        "machine_state":    fields.get("Response.BucketTable", ""),
        "source_file":      str(src),
    }


# ────────────────────────────────────────────────────────────────────────────
# 4. Jump Lists (AutomaticDestinations)
# ────────────────────────────────────────────────────────────────────────────
# Jump Lists are OLE Compound Document files. Full parsing requires reading the
# OLE structured storage and the embedded LNK streams (DestList stream lists
# entries with timestamps + LNK numbers). Without external libraries this is
# non-trivial, so we extract the FILE-level metadata: the App ID embedded in
# the filename, the file mtime, and rough entry count via raw byte scan.
# This is "low-fidelity but no-tool" coverage — for full parsing, JLECmd.exe
# from Eric Zimmerman's tools is the gold standard and is supported by the
# tool registry if present.

# AppID → human label (truncated; the full 1500+ list lives in JLECmd's resources)
KNOWN_APPIDS = {
    "1b4dd67f29cb1962": "Internet Explorer",
    "9839aac8efeed583": "Microsoft Edge",
    "9b9cdc69c1c24e2b": "Notepad",
    "f01b4d95cf55d32a": "Windows Explorer",
    "271e609288c95405": "Windows Photo Viewer",
    "47e2c79ac8c89c01": "Adobe Acrobat Reader",
    "fc8a1b0427bb6c69": "WordPad",
    "00a1d6e786c0aaac": "Microsoft Office Word",
    "012ddc7ce6a8f1d3": "Microsoft Office Excel",
    "23646679aaccfae0": "7-Zip",
    "23ab02f8e58d24c4": "WinRAR",
    "5c450709f7ae4396": "VLC media player",
    "9e58be43be0eaa42": "Mozilla Firefox",
    "30f421d949aa2305": "Notepad++",
}


def _scan_jumplist(src: Path) -> Dict[str, Any]:
    """Lightweight scan — file metadata + AppID lookup."""
    info: Dict[str, Any] = {
        "file": src.name,
        "size": 0,
        "mtime": "",
        "app_id": "",
        "app_label": "",
    }
    try:
        st = src.stat()
        info["size"] = st.st_size
        info["mtime"] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        pass
    # AppID is the lower-cased hex string at the start of the filename
    name = src.name.split(".")[0].lower()
    info["app_id"] = name
    info["app_label"] = KNOWN_APPIDS.get(name, "Unknown app")
    return info


# ────────────────────────────────────────────────────────────────────────────
# Agent
# ────────────────────────────────────────────────────────────────────────────


class Agent(BaseAgent):
    name = "pca_jumplists_wer"
    display_name = "PCA / JumpLists / Tasks / WER"
    description = "Pure-Python parsers for PCA, Scheduled Tasks XML, WER, Jump Lists"
    version = "1.0"
    artifact_subdirs = ["pca", "scheduled_tasks", "wer", "jumplists"]

    # ── extract ──────────────────────────────────────────────────────────

    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        progress.stage_started(self.name, "extract")
        t0 = time.time()
        root = ctx.mount_point
        copied: List[Path] = []
        errors: List[str] = []
        metadata: Dict[str, Any] = {}

        # 1. PCA files
        pca_dest = ctx.agent_artifacts_dir(self.name) / "pca"
        pca_dest.mkdir(parents=True, exist_ok=True)
        pca_count = 0
        for rel in PCA_FILES:
            src = root / rel
            if safe_exists(src):
                try:
                    dst = pca_dest / src.name
                    shutil.copy2(str(src), str(dst))
                    copied.append(dst)
                    pca_count += 1
                except OSError as e:
                    errors.append(f"PCA {src.name}: {e}")
        metadata["pca_count"] = pca_count
        progress.log("INFO", self.name, f"PCA: {pca_count} file(s) copied")

        # 2. Scheduled task XMLs (recursive)
        tasks_src = root / TASKS_DIR
        tasks_dest = ctx.agent_artifacts_dir(self.name) / "scheduled_tasks"
        tasks_count = 0
        if safe_exists(tasks_src):
            tasks_dest.mkdir(parents=True, exist_ok=True)
            metadata["tasks_root_src"] = str(tasks_src)
            metadata["tasks_root_dst"] = str(tasks_dest)
            self._copy_tree(tasks_src, tasks_dest, copied, errors, max_files=2000)
            tasks_count = len(list(tasks_dest.rglob("*"))) - len(list(tasks_dest.rglob("*"))[len(list(tasks_dest.rglob('*'))):])
            tasks_count = sum(1 for _ in tasks_dest.rglob("*") if _.is_file())
        metadata["tasks_count"] = tasks_count
        progress.log("INFO", self.name, f"Scheduled Tasks: {tasks_count} XML file(s) copied")

        # 3. WER reports
        wer_dest = ctx.agent_artifacts_dir(self.name) / "wer"
        wer_dest.mkdir(parents=True, exist_ok=True)
        wer_count = 0
        for rel in WER_DIRS:
            src = root / rel
            if not safe_exists(src):
                continue
            for f in src.rglob("*.wer"):
                try:
                    if f.is_file():
                        dst = wer_dest / f.name
                        shutil.copy2(str(f), str(dst))
                        copied.append(dst)
                        wer_count += 1
                        if wer_count >= 1000:
                            break
                except OSError as e:
                    errors.append(f"WER {f.name}: {e}")
            if wer_count >= 1000:
                break
        # Per-user WER
        users_dir = root / "Users"
        if safe_exists(users_dir) and wer_count < 1000:
            for udir in safe_iterdir(users_dir):
                if not safe_is_dir(udir):
                    continue
                user_wer = udir / WER_USER_REL
                if not safe_exists(user_wer):
                    continue
                for f in user_wer.rglob("*.wer"):
                    try:
                        if f.is_file():
                            dst = wer_dest / f"{udir.name}_{f.name}"
                            shutil.copy2(str(f), str(dst))
                            copied.append(dst)
                            wer_count += 1
                            if wer_count >= 1000:
                                break
                    except OSError:
                        continue
                if wer_count >= 1000:
                    break
        metadata["wer_count"] = wer_count
        progress.log("INFO", self.name, f"WER: {wer_count} crash report(s) copied")

        # 4. Jump Lists (per user)
        jl_dest = ctx.agent_artifacts_dir(self.name) / "jumplists"
        jl_dest.mkdir(parents=True, exist_ok=True)
        jl_count = 0
        if safe_exists(users_dir):
            for udir in safe_iterdir(users_dir):
                if not safe_is_dir(udir):
                    continue
                for kind in ("AutomaticDestinations", "CustomDestinations"):
                    src = udir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / kind
                    if not safe_exists(src):
                        continue
                    user_jl_dest = jl_dest / udir.name / kind.lower()
                    user_jl_dest.mkdir(parents=True, exist_ok=True)
                    for f in safe_iterdir(src):
                        try:
                            if f.is_file():
                                dst = user_jl_dest / f.name
                                shutil.copy2(str(f), str(dst))
                                copied.append(dst)
                                jl_count += 1
                        except OSError:
                            continue
        metadata["jl_count"] = jl_count
        progress.log("INFO", self.name, f"Jump Lists: {jl_count} file(s) copied")

        progress.stage_done(self.name, "extract")
        return ExtractResult(
            agent=self.name,
            success=(pca_count + tasks_count + wer_count + jl_count) > 0,
            artifacts=copied,
            elapsed=time.time() - t0,
            error="; ".join(errors[:5]) + (f" (+{len(errors)-5} more)" if len(errors) > 5 else ""),
            metadata=metadata,
        )

    def _copy_tree(self, src_dir: Path, dst_dir: Path, copied: List[Path],
                   errors: List[str], max_files: int = 2000) -> None:
        """Recursively copy small files preserving directory structure."""
        count = 0
        for src in src_dir.rglob("*"):
            if count >= max_files:
                break
            try:
                if not src.is_file():
                    continue
                rel = src.relative_to(src_dir)
                dst = dst_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dst))
                copied.append(dst)
                count += 1
            except OSError as e:
                errors.append(f"{src.name}: {e}")

    # ── parse ─────────────────────────────────────────────────────────────

    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        progress.stage_started(self.name, "parse")
        t0 = time.time()
        parsed_dir = ctx.agent_parsed_dir(self.name)
        output_files: List[Path] = []
        errors: List[str] = []
        meta = extract_result.metadata

        # 1. PCA
        progress.stage_progress(self.name, "parse", 25, "PCA app-launch dictionary")
        pca_src_dir = ctx.agent_artifacts_dir(self.name) / "pca"
        pca_out_dir = parsed_dir / "pca"
        pca_out_dir.mkdir(parents=True, exist_ok=True)

        for src in pca_src_dir.glob("*.txt"):
            if src.name == "PcaAppLaunchDic.txt":
                out_csv = pca_out_dir / "pca_app_launches.csv"
                n = _parse_pca_appdic(src, out_csv)
                if n > 0:
                    output_files.append(out_csv)
                    progress.log("INFO", self.name, f"PCA: {n} program-launch event(s)")
            elif src.name.startswith("PcaGeneralDb"):
                out_csv = pca_out_dir / f"pca_general_{src.stem.lower()}.csv"
                n = _parse_pca_general(src, out_csv)
                if n > 0:
                    output_files.append(out_csv)
                    progress.log("INFO", self.name, f"PCA general: {n} event(s)")

        # 2. Scheduled Tasks XML
        progress.stage_progress(self.name, "parse", 50, "Scheduled task XML definitions")
        tasks_src_dir = ctx.agent_artifacts_dir(self.name) / "scheduled_tasks"
        tasks_out_csv = parsed_dir / "scheduled_tasks" / "tasks.csv"
        tasks_out_csv.parent.mkdir(parents=True, exist_ok=True)
        rows: List[Dict[str, str]] = []
        for xml_path in tasks_src_dir.rglob("*"):
            if not xml_path.is_file():
                continue
            row = _parse_task_xml(xml_path, tasks_src_dir)
            if row:
                rows.append(row)
        if rows:
            with open(tasks_out_csv, "w", encoding="utf-8", newline="") as f:
                headers = ["task_path", "command", "arguments", "user_id",
                           "author", "description", "date", "uri", "triggers"]
                w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
                w.writeheader()
                for r in rows:
                    w.writerow(r)
            output_files.append(tasks_out_csv)
            progress.log("INFO", self.name, f"Scheduled Tasks: {len(rows)} task(s) parsed")

        # 3. WER
        progress.stage_progress(self.name, "parse", 75, "Windows Error Reporting")
        wer_src_dir = ctx.agent_artifacts_dir(self.name) / "wer"
        wer_out_csv = parsed_dir / "wer" / "wer_reports.csv"
        wer_out_csv.parent.mkdir(parents=True, exist_ok=True)
        wer_rows: List[Dict[str, str]] = []
        for wer_file in wer_src_dir.glob("*.wer"):
            row = _parse_wer_file(wer_file)
            if row:
                wer_rows.append(row)
        if wer_rows:
            with open(wer_out_csv, "w", encoding="utf-8", newline="") as f:
                headers = ["event_time", "event_type", "app_name", "app_path",
                           "app_version", "exception_code", "module_name",
                           "report_id", "machine_state", "source_file"]
                w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
                w.writeheader()
                for r in wer_rows:
                    w.writerow(r)
            output_files.append(wer_out_csv)
            progress.log("INFO", self.name, f"WER: {len(wer_rows)} crash report(s) parsed")

        # 4. Jump Lists (file-level metadata only without external tool)
        progress.stage_progress(self.name, "parse", 95, "Jump Lists summary")
        jl_src_dir = ctx.agent_artifacts_dir(self.name) / "jumplists"
        jl_out_csv = parsed_dir / "jumplists" / "jumplists_summary.csv"
        jl_out_csv.parent.mkdir(parents=True, exist_ok=True)
        jl_rows: List[Dict[str, Any]] = []
        for jl in jl_src_dir.rglob("*"):
            if not jl.is_file():
                continue
            try:
                rel = jl.relative_to(jl_src_dir)
                user = rel.parts[0] if len(rel.parts) > 1 else ""
                kind = rel.parts[1] if len(rel.parts) > 2 else ""
                info = _scan_jumplist(jl)
                info["user"] = user
                info["kind"] = kind
                jl_rows.append(info)
            except Exception:
                continue
        if jl_rows:
            with open(jl_out_csv, "w", encoding="utf-8", newline="") as f:
                headers = ["user", "kind", "app_id", "app_label",
                           "file", "size", "mtime"]
                w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
                w.writeheader()
                for r in jl_rows:
                    w.writerow(r)
            output_files.append(jl_out_csv)
            progress.log("INFO", self.name, f"Jump Lists: {len(jl_rows)} entry(ies) summarised")

        progress.stage_done(self.name, "parse")
        return ParseResult(
            agent=self.name,
            success=len(output_files) > 0,
            output_files=output_files,
            elapsed=time.time() - t0,
            error="; ".join(errors[:5]),
            metadata={"parsed_count": len(output_files)},
        )
