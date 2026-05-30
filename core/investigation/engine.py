"""
Deterministic Forensic Investigation Engine.

Reads parsed artifacts (CSVs, JSONLs, registry artifacts.json), correlates them
against curated indicator lists and the user's investigation prompt, and emits
evidence-based findings WITHOUT relying on the LLM.

Design principles:
  * Everything reproducible: same input → same output.
  * Every finding cites at least one concrete piece of evidence (CSV row, regkey).
  * The investigation prompt is keyword-mapped to focus areas; only those modules run.
  * No false positives from "AI hallucination" because there is no AI here.

Design layout:
  InvestigationEngine
    ├── _scan_usb_activity()        — registry USBSTOR + LNK files on removable
    ├── _scan_cloud_uploads()       — browser history vs cloud / fileshare domains
    ├── _scan_credential_theft()    — process / file path / event log indicators
    ├── _scan_persistence()         — registry persistence + scheduled tasks + svc
    ├── _scan_lateral_movement()    — RDP / SMB / PsExec event signatures
    ├── _scan_log_tampering()       — Event ID 1102, security log gaps
    ├── _scan_anti_forensic()       — privacy tools, log clearing, browser private
    ├── _scan_hacktools()           — known tool names in prefetch / amcache / mft
    └── analyse()                   — orchestrates above based on prompt focus
"""

from __future__ import annotations

import csv
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..case_context import CaseContext
from .indicators import (
    KNOWN_ARCHIVERS,
    KNOWN_CLOUD_DOMAINS,
    KNOWN_FILESHARING_DOMAINS,
    KNOWN_HACKTOOLS,
    KNOWN_PERSONAL_EMAIL,
    KNOWN_PRIVACY_TOOLS,
    PROMPT_FOCUS_KEYWORDS,
)

log = logging.getLogger("dfir.investigator")


@dataclass
class EvidenceSnippet:
    """A small piece of evidence that supports a finding — always renderable as HTML."""
    title: str
    source: str            # e.g. "registry/USBSTOR" or "browsers/chrome/Default"
    headers: List[str]
    rows: List[List[str]]
    highlight: Set[str] = field(default_factory=set)  # column names to highlight
    # Path (relative to reports/) of a rasterized "exhibit screenshot", set by the
    # render layer when Playwright is available. None → fall back to the HTML table.
    image_path: Optional[str] = None


@dataclass
class InvestigationFinding:
    """A single deterministic finding with concrete evidence."""
    category: str          # focus area key (usb_exfil, cloud_upload, ...)
    title: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    summary: str           # 1-2 sentence factual statement
    detail: str            # paragraph of facts (no speculation)
    evidence: List[EvidenceSnippet] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    timeline: List[Tuple[Optional[datetime], str]] = field(default_factory=list)
    # MITRE ATT&CK technique IDs (e.g. ["T1059.001", "T1003"]) for report tags + Navigator export
    attack: List[str] = field(default_factory=list)


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _safe_open_csv(path: Path) -> Optional[csv.DictReader]:
    try:
        f = open(path, encoding="utf-8-sig", errors="replace", newline="")
        return csv.DictReader(f)
    except Exception as e:
        log.warning("Cannot read %s: %s", path, e)
        return None


def _row_to_list(row: Dict[str, str], headers: List[str], maxlen: int = 80) -> List[str]:
    out = []
    for h in headers:
        v = row.get(h, "")
        if v is None:
            v = ""
        v = str(v)
        if len(v) > maxlen:
            v = v[:maxlen - 1] + "…"
        out.append(v)
    return out


def _parse_ts(s: str) -> Optional[datetime]:
    if not s or not isinstance(s, str):
        return None
    s = s.strip().rstrip("Z")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(s[:26], fmt)
        except ValueError:
            continue
    return None


def _domain_from_url(url: str) -> str:
    """Extract the lowercase host from a URL."""
    if not url:
        return ""
    m = re.match(r"^https?://([^/?#]+)", url, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    # bare domain
    return url.split("/")[0].lower() if "." in url.split("/")[0] else ""


# ────────────────────────────────────────────────────────────────────────────
# Engine
# ────────────────────────────────────────────────────────────────────────────

class InvestigationEngine:
    """
    Deterministic, automation-only forensic analyzer.
    Run after parsing completes; no LLM needed.
    """

    def __init__(self, ctx: CaseContext, profile_key: Optional[str] = None,
                 user_keywords: Optional[Dict[str, str]] = None):
        """
        Args:
          profile_key: case-profile key (dlp, malware, phishing, …). Determines focus areas.
          user_keywords: dict {field_key: multiline_text} from profile prompts.
                         All values are merged and used as keyword search terms.
        """
        self.ctx = ctx
        self.parsed = ctx.parsed_dir
        self.prompt = (ctx.investigation_prompt or "").lower()
        self.profile_key = profile_key or "generic"

        from .profiles import get_profile
        self.profile = get_profile(self.profile_key)
        if self.profile is not None:
            self.focus = set(self.profile.focus_areas)
        else:
            self.focus = self._derive_focus(self.prompt)

        # Always layer prompt-based keywords on top of profile focus
        prompt_focus = self._derive_focus(self.prompt)
        self.focus.update(prompt_focus)

        # Normalize user keywords (each prompt field's text becomes a list of terms)
        from .keyword_search import _normalize_keywords
        self.user_keywords: List[str] = []
        if user_keywords:
            for _key, raw_text in user_keywords.items():
                self.user_keywords.extend(_normalize_keywords(raw_text or ""))
            # dedupe while preserving order
            seen = set()
            self.user_keywords = [k for k in self.user_keywords
                                  if not (k in seen or seen.add(k))]

    # ── prompt-driven focus selection ─────────────────────────────────────

    @staticmethod
    def _derive_focus(prompt_lower: str) -> Set[str]:
        focus: Set[str] = set()
        if not prompt_lower:
            # No prompt → run everything that's safe and high-signal
            return {"usb_exfil", "cloud_upload", "fileshare_upload",
                    "credential_theft", "persistence", "hacktools",
                    "log_tampering", "anti_forensic"}
        for area, kws in PROMPT_FOCUS_KEYWORDS.items():
            if any(kw in prompt_lower for kw in kws):
                focus.add(area)
        # Always run baseline checks regardless of prompt
        focus.update({"persistence", "hacktools", "log_tampering"})
        return focus

    # ── public entry point ────────────────────────────────────────────────

    def analyse(self) -> List[InvestigationFinding]:
        findings: List[InvestigationFinding] = []
        log.info("Investigation profile=%s focus=%s keywords=%d",
                 self.profile_key, sorted(self.focus), len(self.user_keywords))

        # ── Profile-driven detection modules ────────────────────────────────
        if "usb_exfil" in self.focus:
            findings.extend(self._scan_usb_activity())
        if "cloud_upload" in self.focus or "fileshare_upload" in self.focus \
                or "personal_email" in self.focus:
            findings.extend(self._scan_browser_uploads())
        if "credential_theft" in self.focus:
            findings.extend(self._scan_credential_theft())
        if "persistence" in self.focus:
            findings.extend(self._scan_persistence())
        if "lateral_movement" in self.focus:
            findings.extend(self._scan_lateral_movement())
        if "log_tampering" in self.focus or "anti_forensic" in self.focus:
            findings.extend(self._scan_log_tampering())
        if "anti_forensic" in self.focus or "tor_anonymizer" in self.focus:
            findings.extend(self._scan_anti_forensic())
        if "hacktools" in self.focus:
            findings.extend(self._scan_hacktools())

        # ── Always-on additions (no extra cost when artefacts are absent) ──
        from ._extra_scans import (
            scan_srum_exfil, scan_hayabusa_detections,
            scan_pca_executions, scan_scheduled_task_xml,
            scan_anti_forensic_gaps,
        )
        findings.extend(scan_srum_exfil(self.parsed))
        findings.extend(scan_hayabusa_detections(self.parsed))
        findings.extend(scan_pca_executions(self.parsed))
        findings.extend(scan_scheduled_task_xml(self.parsed))
        findings.extend(scan_anti_forensic_gaps(self.parsed))

        # ── EventHawk-style deep event-log analysis (deterministic) ────────
        # PowerShell scriptblock reassembly/deobfuscation, process-ancestry
        # chains, logon-session anomalies, and IOC extraction.
        try:
            from ..eventlog import scan_event_logs
            el_findings = scan_event_logs(self.parsed)
            if el_findings:
                log.info("Event-log layer produced %d finding(s)", len(el_findings))
                findings.extend(el_findings)
        except Exception as e:
            log.warning("Event-log analysis layer failed: %s", e)

        # ── Additional artifact scans (Recycle Bin, Shellbags, WMI, ADS, ───
        #    BAM, Windows Timeline) — deterministic, no-op when absent.
        try:
            from ._artifact_scans import run_all as _run_artifact_scans
            art_findings = _run_artifact_scans(self.parsed)
            if art_findings:
                log.info("Artifact scans produced %d finding(s)", len(art_findings))
                findings.extend(art_findings)
        except Exception as e:
            log.warning("Artifact scans failed: %s", e)

        # ── Malware sample analysis (capa + YARA) ──────────────────────────
        # Runs for the malware profile, or whenever malware IOCs / sample dirs
        # are supplied. Locates suspect binaries, then capa/YARA-analyzes them.
        pk = getattr(self.ctx, "profile_keywords", {}) or {}
        mo = getattr(self.ctx, "malware_opts", {}) or {}
        malware_inputs = any(pk.get(k) for k in
                             ("malicious_hashes", "malicious_filenames",
                              "malware_family_names")) or bool(mo.get("sample_dirs"))
        if self.profile_key == "malware" or malware_inputs:
            try:
                from ..malware import scan_malware_samples
                mal_findings = scan_malware_samples(self.ctx, pk, mo)
                if mal_findings:
                    log.info("Malware analysis produced %d finding(s)", len(mal_findings))
                    findings.extend(mal_findings)
            except Exception as e:
                log.warning("Malware sample analysis failed: %s", e)

        # ── User-keyword search (case-specific filenames/IPs/hashes/etc.) ───
        if self.user_keywords:
            from .keyword_search import search_keywords, hits_to_findings
            log.info("Running user-keyword search: %d term(s)", len(self.user_keywords))
            hits = search_keywords(self.parsed, self.user_keywords,
                                   label="User-supplied keywords",
                                   severity="HIGH")
            kw_findings = hits_to_findings(hits, category="user_keywords")
            log.info("Keyword search produced %d finding(s) from %d hit(s)",
                     len(kw_findings), len(hits))
            findings.extend(kw_findings)

        # ── TIMELINE CORRELATION — chain events that occur within 2 minutes ─
        try:
            from .timeline import correlate
            chain_findings = correlate(findings, window_seconds=120, min_chain_size=3)
            if chain_findings:
                log.info("Timeline correlator produced %d chain finding(s)", len(chain_findings))
                findings.extend(chain_findings)
        except Exception as e:
            log.warning("Timeline correlation failed: %s", e)

        return findings

    # ── module: USB / removable-media activity ─────────────────────────────

    def _scan_usb_activity(self) -> List[InvestigationFinding]:
        out: List[InvestigationFinding] = []
        artifacts_json = self.parsed / "registry" / "artifacts.json"
        if not artifacts_json.exists():
            return out
        try:
            data = json.loads(artifacts_json.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            log.warning("USB scan: cannot read artifacts.json: %s", e)
            return out
        artifacts = data.get("artifacts", {})

        # The registry agent typically stores USB info under keys like "usb_devices" / "usbstor"
        usb_keys = [k for k in artifacts.keys() if "usb" in k.lower()]
        if not usb_keys:
            return out

        all_usb_entries: List[Dict[str, Any]] = []
        for key in usb_keys:
            payload = artifacts.get(key, {})
            if isinstance(payload, dict) and "data" in payload:
                payload = payload["data"]
            if isinstance(payload, list):
                all_usb_entries.extend([e for e in payload if isinstance(e, dict)])
            elif isinstance(payload, dict):
                # nested {"DeviceID": {...}, ...}
                for k, v in payload.items():
                    if isinstance(v, dict):
                        v.setdefault("device_id", k)
                        all_usb_entries.append(v)

        if not all_usb_entries:
            return out

        # Build evidence snippet (top 30 devices by most-recent activity)
        cols_priority = ["device_id", "DeviceID", "FriendlyName", "friendly_name",
                         "Manufacturer", "vendor", "Serial", "serial", "SerialNumber",
                         "first_connected", "last_connected", "FirstConnect", "LastConnect"]
        seen_cols: List[str] = []
        for row in all_usb_entries[:30]:
            for k in row.keys():
                if k not in seen_cols and k in cols_priority:
                    seen_cols.append(k)
        if not seen_cols:
            seen_cols = sorted({k for row in all_usb_entries[:30] for k in row.keys()})[:6]

        rows = []
        for entry in all_usb_entries[:30]:
            rows.append(_row_to_list({k: entry.get(k, "") for k in seen_cols}, seen_cols))

        sev = "HIGH" if len(all_usb_entries) > 1 else "MEDIUM"
        out.append(InvestigationFinding(
            category="usb_exfil",
            title=f"{len(all_usb_entries)} USB device connection(s) detected",
            severity=sev,
            summary=(
                f"The Windows registry records {len(all_usb_entries)} unique USB device(s) "
                f"having been connected to this system."
            ),
            detail=(
                "The USBSTOR/USB registry keys (SYSTEM hive) preserve every USB mass-storage "
                "device that has been connected to the host. Each entry below includes the "
                "device identifier and (where Windows recorded it) the friendly name, vendor, "
                "and first/last connection timestamps. Cross-reference these device IDs and "
                "serial numbers against any USB devices found at the scene to corroborate or "
                "refute physical-handling assertions."
            ),
            evidence=[EvidenceSnippet(
                title="USB Devices recorded in registry",
                source="registry/USBSTOR",
                headers=seen_cols,
                rows=rows,
                highlight={"Serial", "serial", "SerialNumber", "device_id"} & set(seen_cols),
            )],
            iocs=[str(e.get("Serial") or e.get("serial") or e.get("SerialNumber") or
                       e.get("device_id") or e.get("DeviceID") or "") for e in all_usb_entries
                  if any(e.get(k) for k in ("Serial","serial","SerialNumber","device_id","DeviceID"))],
        ))

        # LNK files pointing at removable drive letters (D-Z)
        lnk_dir = self.parsed / "usn_lnk_mru" / "lnk"
        removable_lnks = []
        if lnk_dir.exists():
            for lnk_csv in lnk_dir.glob("*.csv"):
                rdr = _safe_open_csv(lnk_csv)
                if not rdr:
                    continue
                for row in rdr:
                    target = (row.get("LocalPath") or row.get("TargetIDListString")
                              or row.get("Drive Letter") or "")
                    if not target:
                        continue
                    # Drive letters D-Z that aren't C: are likely removable
                    m = re.match(r"^([D-Zd-z]):", target.strip())
                    if m:
                        removable_lnks.append({
                            "user_csv": lnk_csv.name,
                            "target": target,
                            "modified": row.get("TargetModified") or row.get("LastAccessed") or "",
                            "args": row.get("Arguments", ""),
                        })

        if removable_lnks:
            headers = ["target", "modified", "user_csv"]
            rows = [_row_to_list(r, headers, maxlen=120) for r in removable_lnks[:25]]
            out.append(InvestigationFinding(
                category="usb_exfil",
                title=f"{len(removable_lnks)} LNK shortcut(s) pointing to removable drives",
                severity="HIGH",
                summary=(
                    f"User shortcut history references {len(removable_lnks)} file(s) on "
                    f"non-system drive letters (D:-Z:), strongly suggesting interaction with "
                    f"removable storage."
                ),
                detail=(
                    "Windows automatically creates .lnk shortcut files in "
                    "%APPDATA%\\Microsoft\\Windows\\Recent for files the user has opened. "
                    "Shortcuts whose target path begins with a drive letter other than C: "
                    "indicate the file lived on an external/removable volume at the time of access. "
                    "These artifacts persist even after the removable device is disconnected."
                ),
                evidence=[EvidenceSnippet(
                    title="Recent shortcuts to non-C: drive letters",
                    source="usn_lnk_mru/lnk",
                    headers=headers,
                    rows=rows,
                    highlight={"target"},
                )],
                iocs=[r["target"] for r in removable_lnks[:25]],
            ))

        return out

    # ── module: Browser / cloud / fileshare uploads ───────────────────────

    def _scan_browser_uploads(self) -> List[InvestigationFinding]:
        out: List[InvestigationFinding] = []
        browsers_dir = self.parsed / "usn_lnk_mru" / "browsers"
        url_hits: List[Dict[str, Any]] = []

        # Native parser produces urls.csv / visits.csv / downloads.csv / searches.csv
        if browsers_dir.exists():
            for csv_path in browsers_dir.rglob("urls.csv"):
                rdr = _safe_open_csv(csv_path)
                if not rdr:
                    continue
                rel_source = str(csv_path.relative_to(browsers_dir))
                for row in rdr:
                    url = row.get("url", "")
                    line = f"{row.get('last_visit_time','')} {url}"
                    self._match_url_line(line, rel_source, url_hits)
            for csv_path in browsers_dir.rglob("downloads.csv"):
                rdr = _safe_open_csv(csv_path)
                if not rdr:
                    continue
                rel_source = str(csv_path.relative_to(browsers_dir))
                for row in rdr:
                    url = row.get("tab_url", "")
                    line = f"{row.get('start_time','')} {url}"
                    self._match_url_line(line, rel_source + " (download)", url_hits)

        if not url_hits:
            # Last-resort: read History SQLite files directly from mount point
            log.info("No URL hits in browser CSVs; running fallback raw-SQLite scan")
            url_hits.extend(self._fallback_scan_browser_history())

        if not url_hits:
            return out

        # Bucket by category
        cloud_hits = [h for h in url_hits if h["category"] == "cloud"]
        fileshare_hits = [h for h in url_hits if h["category"] == "fileshare"]
        email_hits = [h for h in url_hits if h["category"] == "personal_email"]
        privacy_hits = [h for h in url_hits if h["category"] == "privacy"]

        for category, hits, sev, label, why in [
            ("fileshare_upload", fileshare_hits, "CRITICAL", "File-Sharing Service Visits",
             "Anonymous file-sharing services are heavily abused for data exfiltration. "
             "Each visit below is a potential exfil channel and warrants individual review."),
            ("cloud_upload", cloud_hits, "HIGH", "Cloud Storage Service Visits",
             "Visits to personal cloud storage. While these can be legitimate, in a DLP "
             "investigation they should be cross-referenced with the document set and "
             "with the user's authorised cloud accounts."),
            ("personal_email", email_hits, "MEDIUM", "Personal Webmail Access",
             "Personal webmail accessed from a corporate device is a potential exfil "
             "channel (compose-and-send-as-attachment)."),
            ("tor_anonymizer", privacy_hits, "HIGH", "Anonymity / VPN Service Visits",
             "Visits to known privacy / VPN / Tor-related services may indicate an attempt "
             "to obscure exfiltration or access activity."),
        ]:
            if not hits:
                continue
            headers = ["timestamp", "domain", "url", "service", "source"]
            rows = []
            for h in hits[:30]:
                rows.append([
                    str(h.get("ts", ""))[:19],
                    h["domain"],
                    h["url"][:120] + ("…" if len(h["url"]) > 120 else ""),
                    h["service"],
                    h["source"],
                ])
            out.append(InvestigationFinding(
                category=category,
                title=f"{len(hits)} {label.lower()} found in browser history",
                severity=sev,
                summary=f"Browser history contains {len(hits)} visit(s) to known {label.lower()}.",
                detail=why,
                evidence=[EvidenceSnippet(
                    title=label,
                    source="usn_lnk_mru/browsers",
                    headers=headers,
                    rows=rows,
                    highlight={"domain", "service"},
                )],
                iocs=sorted({h["url"] for h in hits[:50]}),
                timeline=[(h.get("ts"), f"Visited {h['domain']}") for h in hits if h.get("ts")][:50],
            ))

        return out

    def _match_url_line(self, line: str, source: str, hits: List[Dict[str, Any]]) -> None:
        """Scan a single line of text for URLs that match indicator domains."""
        for url_match in re.finditer(r'https?://[^\s",<>\]\)]+', line):
            url = url_match.group(0).rstrip(".,;)")
            domain = _domain_from_url(url)
            if not domain:
                continue
            cat: Optional[str] = None
            service: Optional[str] = None
            for d, name in KNOWN_FILESHARING_DOMAINS.items():
                if d == domain or domain.endswith("." + d):
                    cat, service = "fileshare", name
                    break
            if cat is None:
                for d, name in KNOWN_CLOUD_DOMAINS.items():
                    if d == domain or domain.endswith("." + d):
                        cat, service = "cloud", name
                        break
            if cat is None:
                for d, name in KNOWN_PERSONAL_EMAIL.items():
                    if d == domain or domain.endswith("." + d):
                        cat, service = "personal_email", name
                        break
            if cat is None:
                for d, name in KNOWN_PRIVACY_TOOLS.items():
                    if d == domain or domain.endswith("." + d):
                        cat, service = "privacy", name
                        break
            if cat is None:
                continue
            ts_match = re.search(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
            ts = _parse_ts(ts_match.group(1)) if ts_match else None
            hits.append({
                "category": cat, "url": url, "domain": domain,
                "service": service, "ts": ts, "source": source,
            })

    def _fallback_scan_browser_history(self) -> List[Dict[str, Any]]:
        """Direct SQLite read of Chrome/Edge History when Hindsight failed."""
        hits: List[Dict[str, Any]] = []
        users_dir = self.ctx.mount_point / "Users"
        if not users_dir.exists():
            return hits
        try:
            user_dirs = list(users_dir.iterdir())
        except (PermissionError, OSError):
            return hits

        import sqlite3, tempfile, shutil

        history_paths = []
        for user_dir in user_dirs:
            try:
                if not user_dir.is_dir():
                    continue
            except (PermissionError, OSError):
                continue
            for browser, rel in [
                ("Chrome", r"AppData\Local\Google\Chrome\User Data"),
                ("Edge",   r"AppData\Local\Microsoft\Edge\User Data"),
            ]:
                base = user_dir / rel
                if not base.exists():
                    continue
                try:
                    for sub in base.iterdir():
                        try:
                            h = sub / "History"
                            if h.exists():
                                history_paths.append((browser, user_dir.name, sub.name, h))
                        except (PermissionError, OSError):
                            continue
                except (PermissionError, OSError):
                    continue

        for browser, username, profile, hist in history_paths:
            try:
                # Copy to temp because SQLite needs write-access for journal files
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                    shutil.copy2(hist, tmp.name)
                    tmp_path = tmp.name
                conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True, timeout=5)
                cur = conn.cursor()
                cur.execute(
                    "SELECT url, last_visit_time FROM urls "
                    "ORDER BY last_visit_time DESC LIMIT 5000"
                )
                for url, lvt in cur.fetchall():
                    domain = _domain_from_url(url or "")
                    if not domain:
                        continue
                    line = f"{lvt} {url}"
                    self._match_url_line(line, f"{browser}/{username}/{profile}", hits)
                conn.close()
            except Exception as e:
                log.warning("Fallback History read failed for %s/%s: %s", browser, username, e)

        return hits

    # ── module: Credential theft indicators ───────────────────────────────

    def _scan_credential_theft(self) -> List[InvestigationFinding]:
        out: List[InvestigationFinding] = []
        # Match against prefetch + amcache for known credential dumpers
        cred_indicators = {k: v for k, v in KNOWN_HACKTOOLS.items()
                           if any(t in v[0].lower() for t in
                                  ["credential", "lsass", "mimikatz", "kerberos", "password",
                                   "ntlm", "secretsdump", "pwd"])}
        hits = self._search_execution_artifacts(cred_indicators)
        if hits:
            headers = ["tool", "evidence_path", "first_seen", "source"]
            rows = [_row_to_list(h, headers, 100) for h in hits[:25]]
            out.append(InvestigationFinding(
                category="credential_theft",
                title=f"Credential-theft tooling detected ({len(hits)} reference(s))",
                severity="CRITICAL",
                summary="Execution artifacts contain references to known credential-dumping tools.",
                detail=(
                    "The Windows Prefetch and AmcacheParser tracks tracked program execution. "
                    "References to LSASS dumpers, Mimikatz, secretsdump, and similar tools "
                    "in these artifacts strongly suggest credential-theft activity occurred on "
                    "this host. Each row below shows the tool name and the artifact in which "
                    "it was found."
                ),
                evidence=[EvidenceSnippet(
                    title="Credential-theft tools in execution artifacts",
                    source="prefetch_amcache_mft",
                    headers=headers,
                    rows=rows,
                    highlight={"tool", "evidence_path"},
                )],
                iocs=[h["evidence_path"] for h in hits[:50]],
            ))
        return out

    # ── module: Persistence ───────────────────────────────────────────────

    def _scan_persistence(self) -> List[InvestigationFinding]:
        out: List[InvestigationFinding] = []
        artifacts_json = self.parsed / "registry" / "artifacts.json"
        if not artifacts_json.exists():
            return out
        try:
            data = json.loads(artifacts_json.read_text(encoding="utf-8", errors="replace"))
            artifacts = data.get("artifacts", {})
        except Exception:
            return out

        suspicious_persistence = []
        for key in ["persistence", "autoruns", "run_keys", "scheduled_tasks", "services"]:
            payload = artifacts.get(key)
            if isinstance(payload, dict) and "data" in payload:
                payload = payload["data"]
            if not isinstance(payload, list):
                continue
            for entry in payload:
                if not isinstance(entry, dict):
                    continue
                # Suspicion heuristics — non-Microsoft signed paths in autoruns
                path = (entry.get("ImagePath") or entry.get("image_path")
                        or entry.get("Command") or entry.get("Path") or "").lower()
                if not path:
                    continue
                # Known-good prefixes
                normal = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                          r"\systemroot\system32\\", r"\??\c:\windows\system32\\",
                          "c:\\program files\\", "c:\\program files (x86)\\")
                if any(path.startswith(p) for p in normal):
                    continue
                # Scripts and unusual paths
                suspicious_persistence.append({
                    "category": key,
                    "name": entry.get("Name") or entry.get("name") or entry.get("KeyName") or "?",
                    "path": entry.get("ImagePath") or entry.get("image_path")
                            or entry.get("Command") or entry.get("Path") or "",
                    "user": entry.get("user") or entry.get("User") or "",
                })

        if suspicious_persistence:
            headers = ["category", "name", "path", "user"]
            rows = [_row_to_list(r, headers, 100) for r in suspicious_persistence[:30]]
            out.append(InvestigationFinding(
                category="persistence",
                title=f"{len(suspicious_persistence)} non-standard persistence mechanism(s)",
                severity="HIGH",
                summary=(
                    f"Found {len(suspicious_persistence)} autorun/service/scheduled-task entries "
                    f"with image paths outside standard Windows or Program Files directories."
                ),
                detail=(
                    "Standard Windows components live in %SystemRoot%\\System32 or Program Files. "
                    "Persistence entries pointing to other locations (user profile, AppData, "
                    "ProgramData, Temp, etc.) are atypical and warrant individual review. "
                    "Validate each entry by checking the file's digital signature and reputation."
                ),
                evidence=[EvidenceSnippet(
                    title="Non-standard persistence entries",
                    source="registry/persistence,services,scheduled_tasks",
                    headers=headers,
                    rows=rows,
                    highlight={"path"},
                )],
                iocs=[r["path"] for r in suspicious_persistence[:50] if r["path"]],
            ))
        return out

    # ── module: Lateral movement ──────────────────────────────────────────

    def _scan_lateral_movement(self) -> List[InvestigationFinding]:
        out: List[InvestigationFinding] = []
        # Look for PsExec / wmiexec / atexec in execution artifacts
        lat_tools = {k: v for k, v in KNOWN_HACKTOOLS.items()
                     if any(t in v[0].lower() for t in
                            ["psexec", "wmiexec", "atexec", "smbexec", "remote", "lateral"])}
        hits = self._search_execution_artifacts(lat_tools)
        if hits:
            headers = ["tool", "evidence_path", "first_seen", "source"]
            rows = [_row_to_list(h, headers, 100) for h in hits[:25]]
            out.append(InvestigationFinding(
                category="lateral_movement",
                title=f"Lateral-movement tooling detected ({len(hits)} reference(s))",
                severity="HIGH",
                summary="Execution artifacts reference known lateral-movement tools.",
                detail=(
                    "Tools like PsExec, wmiexec, and atexec are commonly used by adversaries "
                    "to pivot between hosts after initial access. Their presence in Prefetch "
                    "or Amcache indicates the tool was executed on this system."
                ),
                evidence=[EvidenceSnippet(
                    title="Lateral-movement tooling references",
                    source="prefetch_amcache_mft",
                    headers=headers,
                    rows=rows,
                    highlight={"tool"},
                )],
                iocs=[h["evidence_path"] for h in hits],
            ))
        return out

    # ── module: Log tampering / clearing ──────────────────────────────────

    def _scan_log_tampering(self) -> List[InvestigationFinding]:
        out: List[InvestigationFinding] = []
        # Event ID 1102 = Audit log was cleared (Security)
        # Event ID 104  = Log file cleared (System)
        events_dir = self.parsed / "event_logs"
        if not events_dir.exists():
            return out

        clear_events = []
        for csv_path in events_dir.rglob("*.csv"):
            rdr = _safe_open_csv(csv_path)
            if not rdr:
                continue
            for row in rdr:
                eid = row.get("EventId", row.get("Event Id", ""))
                try:
                    eid_int = int(eid)
                except (ValueError, TypeError):
                    continue
                if eid_int in (1102, 104):
                    clear_events.append({
                        "event_id": eid,
                        "time": row.get("TimeCreated", row.get("Time Created", "")),
                        "user": row.get("UserName", row.get("User Name", "")),
                        "channel": row.get("Channel", csv_path.stem),
                        "source_csv": csv_path.name,
                    })
        if clear_events:
            headers = ["time", "event_id", "user", "channel", "source_csv"]
            rows = [_row_to_list(r, headers, 100) for r in clear_events]
            out.append(InvestigationFinding(
                category="log_tampering",
                title=f"Audit log cleared ({len(clear_events)} occurrence(s))",
                severity="CRITICAL",
                summary=f"Found {len(clear_events)} log-clear event(s) (Event ID 1102/104).",
                detail=(
                    "Event ID 1102 in the Security log records when an administrator clears "
                    "the audit log. Event ID 104 in System records similar clears for other "
                    "channels. These events are themselves logged because adversaries use "
                    "log clearing to cover their tracks. Investigate the timestamp, the "
                    "preceding/following activity, and the user account responsible."
                ),
                evidence=[EvidenceSnippet(
                    title="Audit-log clear events",
                    source="event_logs",
                    headers=headers,
                    rows=rows,
                    highlight={"event_id", "user"},
                )],
                iocs=[],
                timeline=[(_parse_ts(r["time"]), f"Log cleared by {r['user']}") for r in clear_events],
            ))
        return out

    # ── module: Anti-forensic / privacy tools ─────────────────────────────

    def _scan_anti_forensic(self) -> List[InvestigationFinding]:
        out: List[InvestigationFinding] = []
        # Look for VPN / Tor binaries in prefetch
        privacy_tools = {
            "tor.exe": "Tor anonymity network",
            "torbrowser.exe": "Tor Browser",
            "openvpn.exe": "OpenVPN client",
            "nordvpn.exe": "NordVPN",
            "expressvpn.exe": "ExpressVPN",
            "protonvpn.exe": "ProtonVPN",
            "ccleaner.exe": "CCleaner (privacy/anti-forensics)",
            "bcwipe.exe": "BCWipe (file shredder)",
            "eraser.exe": "Eraser (file shredder)",
            "sdelete.exe": "SDelete (Sysinternals shredder)",
            "sdelete64.exe": "SDelete64",
        }
        # Adapt to expected format for _search_execution_artifacts
        privacy_indicators = {k: (v, "MEDIUM") for k, v in privacy_tools.items()}
        hits = self._search_execution_artifacts(privacy_indicators)
        if hits:
            headers = ["tool", "evidence_path", "first_seen", "source"]
            rows = [_row_to_list(h, headers, 100) for h in hits[:25]]
            out.append(InvestigationFinding(
                category="anti_forensic",
                title=f"Privacy / anti-forensic tools detected ({len(hits)} reference(s))",
                severity="HIGH",
                summary="VPN, Tor, or file-wiping tools are present in execution history.",
                detail=(
                    "Tools that anonymise traffic (Tor, VPNs) or destructively delete files "
                    "(SDelete, BCWipe, Eraser, CCleaner) are not malicious in themselves but "
                    "are commonly found alongside data-exfiltration or anti-forensic activity. "
                    "Investigate each tool's installation path, run frequency, and timeline "
                    "context."
                ),
                evidence=[EvidenceSnippet(
                    title="Privacy / anti-forensic tooling",
                    source="prefetch_amcache_mft",
                    headers=headers,
                    rows=rows,
                    highlight={"tool"},
                )],
                iocs=[h["evidence_path"] for h in hits],
            ))
        return out

    # ── module: Generic hacktool sweep ────────────────────────────────────

    def _scan_hacktools(self) -> List[InvestigationFinding]:
        out: List[InvestigationFinding] = []
        hits = self._search_execution_artifacts(KNOWN_HACKTOOLS)
        if not hits:
            return out

        # Group by severity
        by_sev: Dict[str, List[Dict]] = {}
        for h in hits:
            by_sev.setdefault(h["severity"], []).append(h)

        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            if sev not in by_sev:
                continue
            group = by_sev[sev]
            headers = ["tool", "description", "evidence_path", "source"]
            rows = [_row_to_list(h, headers, 100) for h in group[:25]]
            out.append(InvestigationFinding(
                category="hacktools",
                title=f"{len(group)} {sev.lower()}-severity offensive tool reference(s)",
                severity=sev,
                summary=(
                    f"Execution artifacts reference {len(group)} known offensive security "
                    f"tool(s) at {sev.lower()} severity."
                ),
                detail=(
                    "These tools are catalogued in the public threat-intel literature as being "
                    "primarily used for offensive operations. Even legitimate red-team or "
                    "pentesting use must be authorised; verify against approved-tooling lists."
                ),
                evidence=[EvidenceSnippet(
                    title=f"{sev} offensive tools",
                    source="prefetch_amcache_mft",
                    headers=headers,
                    rows=rows,
                    highlight={"tool"},
                )],
                iocs=[h["evidence_path"] for h in group],
            ))
        return out

    # ── shared helper: search prefetch + amcache CSVs for known names ─────

    def _search_execution_artifacts(self, indicators: Dict[str, Tuple[str, str]]) -> List[Dict[str, Any]]:
        """Search prefetch/*.csv and amcache/*.csv for filenames/paths matching the indicators."""
        hits: List[Dict[str, Any]] = []
        candidates = [
            self.parsed / "prefetch_amcache_mft" / "prefetch",
            self.parsed / "prefetch_amcache_mft" / "amcache",
            self.parsed / "prefetch_amcache_mft" / "mft",
        ]
        for src_dir in candidates:
            if not src_dir.exists():
                continue
            for csv_path in src_dir.glob("*.csv"):
                rdr = _safe_open_csv(csv_path)
                if not rdr:
                    continue
                for row in rdr:
                    # Build a single search blob from all path-like fields
                    blob = " ".join(
                        str(row.get(f, "")) for f in (
                            "ExecutableName", "Executable Name", "Name", "FileName",
                            "FullPath", "Path", "FilePath", "SourceFileName", "TargetFileName",
                            "ImagePath", "ApplicationName"
                        )
                    ).lower()
                    if not blob.strip():
                        continue
                    for name, (desc, sev) in indicators.items():
                        if name.lower() in blob:
                            ts = row.get("LastRun") or row.get("Last Run") or \
                                 row.get("FileKeyLastWriteTimestamp") or ""
                            hits.append({
                                "tool": name,
                                "description": desc,
                                "severity": sev,
                                "evidence_path": (row.get("FullPath") or row.get("Path")
                                                  or row.get("ExecutableName") or "")[:200],
                                "first_seen": str(ts)[:19],
                                "source": csv_path.name,
                            })
                            break
        return hits
