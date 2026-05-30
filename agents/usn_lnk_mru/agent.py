"""
USN Journal / LNK / MRU / Browsers Agent.
Wraps forensic_usn-lnk-mru_FIXED.py logic into BaseAgent.

Critical note: RECmd v2.1.0 does NOT support the -q flag.
Passing -q causes RECmd to print usage and exit RC=0 without producing output.
LECmd supports -q; RECmd does not. This bug is documented and fixed here.
"""

from __future__ import annotations

import glob
import shutil
import sys
import time
from pathlib import Path
from typing import List, Optional

_REPO_ROOT = Path(__file__).parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.base_agent import BaseAgent, ExtractResult, ParseResult
from core.case_context import CaseContext
from core.fsutil import safe_exists, safe_iterdir, safe_glob, safe_is_dir
from core.progress_bus import ProgressBus
from core.tool_runner import ExecutionError, ToolNotFoundError, ToolRunner

BROWSER_PROFILES = {
    "Chrome": r"AppData\Local\Google\Chrome\User Data",
    "Edge": r"AppData\Local\Microsoft\Edge\User Data",
}

USN_J_CANDIDATES = [
    r"$Extend\$UsnJrnl:$J:$DATA",
    r"$Extend\$J",
]


class Agent(BaseAgent):
    name = "usn_lnk_mru"
    display_name = "USN Journal / LNK / MRU / Browsers"
    description = "MRU via RECmd, USN Journal via MFTECmd, LNK via LECmd, browser history via Hindsight"
    version = "2.1"
    artifact_subdirs = ["mru", "usn_journal", "lnk", "browsers"]

    # ── extract ──────────────────────────────────────────────────────────

    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        progress.stage_started(self.name, "extract")
        t0 = time.time()
        root = ctx.mount_point
        copied: List[Path] = []
        errors: List[str] = []
        metadata: dict = {}

        # MRU hives (NTUSER.DAT, UsrClass.dat) — use safe_glob/safe_exists throughout
        mru_hives: List[Path] = []
        users_dir = root / "Users"
        if safe_exists(users_dir):
            for pat in [r"Users\*\NTUSER.DAT", r"Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat"]:
                mru_hives.extend(safe_glob(root, pat))
        metadata["mru_hive_paths"] = [str(p) for p in mru_hives]
        progress.log("INFO", self.name, f"Found {len(mru_hives)} MRU hive(s)")

        # USN Journal $J and $MFT are locked NTFS system files.
        # Python's Path.exists() returns False even as admin because the OS hides them
        # from regular file APIs. MFTECmd uses raw volume access and reads them directly.
        # Store the candidate paths unconditionally — MFTECmd will fail gracefully if absent.
        usn_j_path: Optional[Path] = None
        for cand in USN_J_CANDIDATES:
            p = root / cand
            if safe_exists(p):
                usn_j_path = p
                break
        if usn_j_path is None:
            usn_j_path = root / USN_J_CANDIDATES[0]  # try first candidate via raw access
        metadata["usn_j_path"] = str(usn_j_path)

        # $MFT — always store path; MFTECmd reads it natively even when Python can't
        mft_path = root / "$MFT"
        metadata["mft_path"] = str(mft_path)

        # LNK files (Recent)
        lnk_paths: List[Path] = []
        if safe_exists(users_dir):
            for pat in [r"Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk"]:
                lnk_paths.extend(safe_glob(root, pat))
        metadata["lnk_dirs"] = list({str(p.parent) for p in lnk_paths})
        progress.log("INFO", self.name, f"Found {len(lnk_paths)} LNK files in Recent dirs")

        # Browser profiles — find specific profile subdirs (Default, Profile 1, …)
        PROFILE_MARKERS = ("History", "Cookies", "Web Data")
        browser_profiles: dict = {}
        if safe_exists(users_dir):
            for user_dir in safe_iterdir(users_dir):
                if not safe_is_dir(user_dir):
                    continue
                username = user_dir.name
                for browser, rel in BROWSER_PROFILES.items():
                    user_data = user_dir / rel
                    if not safe_exists(user_data):
                        continue
                    for subdir in safe_iterdir(user_data):
                        if not safe_is_dir(subdir):
                            continue
                        if any(safe_exists(subdir / m) for m in PROFILE_MARKERS):
                            browser_profiles.setdefault(browser, []).append({
                                "username": username,
                                "profile_path": str(subdir),
                                "profile_name": subdir.name,
                            })
        metadata["browser_profiles"] = browser_profiles
        metadata["browser_dirs"] = {b: [p["profile_path"] for p in ps] for b, ps in browser_profiles.items()}
        progress.log("INFO", self.name, f"Browser profiles found: {list(browser_profiles.keys())}")

        progress.stage_done(self.name, "extract")
        return ExtractResult(
            agent=self.name,
            success=True,
            artifacts=mru_hives + ([usn_j_path] if usn_j_path else []) + ([mft_path] if safe_exists(mft_path) else []),
            elapsed=time.time() - t0,
            metadata=metadata,
        )

    # ── parse ─────────────────────────────────────────────────────────────

    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        progress.stage_started(self.name, "parse")
        t0 = time.time()
        runner = ToolRunner(ctx.tools_dir)
        parsed_dir = ctx.agent_parsed_dir(self.name)
        output_files: List[Path] = []
        errors: List[str] = []
        meta = extract_result.metadata

        # MRU via RECmd
        progress.stage_progress(self.name, "parse", 10, "Parsing MRU with RECmd")
        mru_files = self._parse_mru(runner, meta, parsed_dir, errors, progress)
        output_files.extend(mru_files)

        # USN Journal via MFTECmd
        progress.stage_progress(self.name, "parse", 35, "Parsing USN Journal")
        usn_files = self._parse_usn(runner, meta, parsed_dir, errors, progress)
        output_files.extend(usn_files)

        # LNK via LECmd
        progress.stage_progress(self.name, "parse", 60, "Parsing LNK files with LECmd")
        lnk_files = self._parse_lnk(runner, ctx.mount_point, meta, parsed_dir, errors, progress)
        output_files.extend(lnk_files)

        # Browser history via Hindsight
        progress.stage_progress(self.name, "parse", 80, "Parsing browser history")
        browser_files = self._parse_browsers(runner, meta, parsed_dir, errors, progress)
        output_files.extend(browser_files)

        progress.stage_done(self.name, "parse")
        return ParseResult(
            agent=self.name,
            success=len(output_files) > 0,
            output_files=output_files,
            elapsed=time.time() - t0,
            error="; ".join(errors),
            metadata={"parsed_count": len(output_files)},
        )

    def _parse_mru(self, runner, meta, parsed_dir, errors, progress):
        hive_paths = [Path(p) for p in meta.get("mru_hive_paths", []) if Path(p).exists()]
        if not hive_paths:
            return []

        try:
            batch = runner.resolve_recmd_batch()
        except ToolNotFoundError as e:
            errors.append(f"RECmd batch: {e}")
            progress.log("WARNING", self.name, f"RECmd batch not found: {e}")
            return []

        try:
            exe = runner.resolve("recmd")
        except ToolNotFoundError as e:
            errors.append(f"RECmd: {e}")
            return []

        out_dir = parsed_dir / "mru"
        out_dir.mkdir(parents=True, exist_ok=True)
        produced: List[Path] = []

        for hive in hive_paths:
            # Derive unique CSV name from username
            parts = hive.parts
            try:
                users_idx = next(i for i, p in enumerate(parts) if p.lower() == "users")
                username = parts[users_idx + 1]
            except (StopIteration, IndexError):
                username = hive.parent.parent.name
            csv_name = f"MRU_{hive.stem}_{username}.csv"
            # NOTE: no -q flag — RECmd v2.1.0 does NOT support it
            cmd = [str(exe), "-f", str(hive), "--bn", str(batch),
                   "--nl", "true", "--csv", str(out_dir), "--csvf", csv_name]
            try:
                runner.run(cmd, f"MRU_{username}", timeout=300)
                out_csv = out_dir / csv_name
                if out_csv.exists():
                    produced.append(out_csv)
            except ExecutionError as e:
                errors.append(f"MRU {username}: {e}")
                progress.log("WARNING", self.name, f"MRU parse error for {username}: {e}")
        return produced

    def _parse_usn(self, runner, meta, parsed_dir, errors, progress):
        usn_j = meta.get("usn_j_path")
        mft = meta.get("mft_path")
        if not usn_j:
            progress.log("INFO", self.name, "No USN $J path — skipping USN parsing")
            return []

        try:
            exe = runner.resolve("mftecmd")
        except ToolNotFoundError as e:
            errors.append(f"MFTECmd: {e}")
            progress.log("WARNING", self.name, f"MFTECmd not found — USN parsing skipped: {e}")
            return []

        out_dir = parsed_dir / "usn_journal"
        out_dir.mkdir(parents=True, exist_ok=True)
        csv_name = "usnjrnl.csv"
        # MFTECmd uses raw volume access; don't pre-check the path with Python.
        # Try each USN candidate in order — the first one that produces output wins.
        candidates = [usn_j]
        # Add fallback candidates relative to the parent of $MFT (mount root)
        if mft:
            mount_parent = Path(mft).parent
            for cand in USN_J_CANDIDATES:
                cand_path = str(mount_parent / cand)
                if cand_path not in candidates:
                    candidates.append(cand_path)

        # MFTECmd's flag for the $MFT companion when parsing $J was renamed across versions.
        # Old (1.x): --mft   |   New (2.x): -m
        # Try the modern flag first, fall back to the old flag if MFTECmd reports
        # "Unrecognized command or argument".
        mft_flag_variants = (["-m"], ["--mft"])

        for i, candidate in enumerate(candidates):
            attempt_label = f"{i+1}/{len(candidates)}"
            for flag in mft_flag_variants:
                cmd = [str(exe), "-f", candidate]
                if mft:
                    cmd += flag + [mft]
                cmd += ["--csv", str(out_dir), "--csvf", csv_name]
                progress.log("INFO", self.name,
                             f"USN attempt {attempt_label} [flag={flag[0]}]: {candidate}")
                try:
                    rc, stdout, stderr = runner.run(
                        cmd, f"USNJournal_{i+1}_{flag[0]}", timeout=900, retries=1,
                    )
                    out_csv = out_dir / csv_name
                    if out_csv.exists() and out_csv.stat().st_size > 0:
                        progress.log("INFO", self.name,
                                     f"USN parsed → {out_csv.name} "
                                     f"({out_csv.stat().st_size:,} bytes) using flag {flag[0]}")
                        return [out_csv]
                    if "Unrecognized command or argument" in (stderr or ""):
                        progress.log("INFO", self.name,
                                     f"USN: MFTECmd doesn't recognise '{flag[0]}', "
                                     f"trying alternate flag…")
                        continue  # try the other flag
                    progress.log("WARNING", self.name,
                                 f"USN attempt {attempt_label}: RC={rc} but no output. "
                                 f"stderr: {(stderr or '')[:200]}")
                    break  # don't retry with other flag if this is a different error
                except ExecutionError as e:
                    err_short = str(e).splitlines()[0][:200]
                    if "Unrecognized" in err_short:
                        continue  # try other flag
                    progress.log("WARNING", self.name,
                                 f"USN attempt {attempt_label} failed: {err_short}")
                    break

        errors.append("USN: all candidates failed (try running MFTECmd manually to verify)")
        progress.log("WARNING", self.name,
                     "USN: no candidate produced output. $J may be inaccessible on this image. "
                     "Try: MFTECmd.exe -f F:\\$Extend\\$J -m F:\\$MFT --csv ./out manually.")
        return []

    def _parse_lnk(self, runner, root, meta, parsed_dir, errors, progress):
        lnk_dirs = list({Path(d) for d in meta.get("lnk_dirs", []) if Path(d).exists()})
        if not lnk_dirs:
            return []

        try:
            exe = runner.resolve("lecmd")
        except ToolNotFoundError as e:
            errors.append(f"LECmd: {e}")
            return []

        out_dir = parsed_dir / "lnk"
        out_dir.mkdir(parents=True, exist_ok=True)
        produced: List[Path] = []

        for lnk_dir in lnk_dirs:
            # Derive username
            parts = lnk_dir.parts
            try:
                users_idx = next(i for i, p in enumerate(parts) if p.lower() == "users")
                username = parts[users_idx + 1]
            except (StopIteration, IndexError):
                username = lnk_dir.parent.parent.name
            csv_name = f"lnk_{username}.csv"
            cmd = [str(exe), "-d", str(lnk_dir), "--csv", str(out_dir), "--csvf", csv_name, "-q"]
            try:
                runner.run(cmd, f"LNK_{username}", timeout=300)
                out_csv = out_dir / csv_name
                if out_csv.exists():
                    produced.append(out_csv)
            except ExecutionError as e:
                errors.append(f"LNK {username}: {e}")
                progress.log("WARNING", self.name, f"LNK error: {e}")
        return produced

    def _parse_browsers(self, runner, meta, parsed_dir, errors, progress):
        """Parse Chrome/Edge history using NATIVE Python sqlite3 (not Hindsight).

        Hindsight is a PyInstaller bundle that crashes in its bundled Rich library
        whenever stdout is a pipe — every workaround we tried (NO_COLOR, chcp 65001,
        DEVNULL) failed. The native parser is faster, more reliable, and produces
        clean CSVs that downstream analysis can consume directly.
        """
        browser_profiles = meta.get("browser_profiles", {})
        if not browser_profiles:
            for browser, paths in meta.get("browser_dirs", {}).items():
                for p in paths:
                    browser_profiles.setdefault(browser, []).append({
                        "username": "unknown",
                        "profile_path": p,
                        "profile_name": Path(p).name,
                    })
        if not browser_profiles:
            return []

        from core.parsers.browser_history import parse_browser_profile

        out_dir = parsed_dir / "browsers"
        out_dir.mkdir(parents=True, exist_ok=True)
        produced: List[Path] = []
        total_profiles = sum(len(v) for v in browser_profiles.values())
        done = 0

        for browser, profiles in browser_profiles.items():
            for profile in profiles:
                done += 1
                profile_path = Path(profile["profile_path"])
                if not profile_path.exists():
                    continue
                username = profile.get("username", "unknown")
                profile_name = profile.get("profile_name", profile_path.name)
                safe_name = f"{username}_{profile_name}".replace(" ", "_")
                profile_out = out_dir / browser.lower() / safe_name

                progress.stage_progress(
                    self.name, "parse",
                    80 + (done / max(total_profiles, 1)) * 15,
                    f"Browser {browser} {username}/{profile_name}",
                )
                try:
                    result = parse_browser_profile(profile_path, profile_out)
                    produced.extend(result.csvs)
                    counts_str = ", ".join(f"{k}={v}" for k, v in result.counts.items() if v)
                    progress.log("INFO", self.name,
                                 f"Browser {browser} {username}/{profile_name}: {counts_str or 'empty'}")
                    if result.errors:
                        for err in result.errors:
                            errors.append(f"Browser {browser} {username}/{profile_name}: {err}")
                except Exception as e:
                    errors.append(f"Browser {browser} {username}/{profile_name}: {e}")
                    progress.log("WARNING", self.name,
                                 f"Browser native parse failed for {browser}/{profile_name}: {e}")
        return produced
