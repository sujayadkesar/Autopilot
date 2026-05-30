"""
Case Profiles — pre-built investigation workflows.

A profile maps a *kind* of investigation (DLP, Malware, Phishing, etc.) to:
  * the deterministic-engine focus areas to enable
  * the specific artefact checks that matter for this case type
  * the fields the GUI should ask the user to fill in (sensitive filenames for DLP,
    suspicious process names for malware, etc.)

The user can:
  1. Pick a profile in the Setup page
  2. Provide profile-specific keywords / file lists
  3. Run the pipeline — the engine + keyword scanner produce profile-targeted findings
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class KeywordPrompt:
    """A field on the Setup UI asking the user for case-specific keywords."""
    key: str                # programmatic key (e.g. "sensitive_filenames")
    label: str              # UI label
    placeholder: str        # placeholder text shown in the textarea
    multiline: bool = True  # show as textarea vs single-line input
    required: bool = False
    description: str = ""   # explanation shown below the field


@dataclass
class CaseProfile:
    """A pre-built investigation profile."""
    key: str                          # programmatic id
    display_name: str                 # shown in the dropdown
    short_description: str            # one-liner for the dropdown subtitle
    long_description: str             # multi-line panel describing what runs
    focus_areas: List[str]            # which engine modules run
    keyword_prompts: List[KeywordPrompt] = field(default_factory=list)
    workflow_summary: List[str] = field(default_factory=list)  # rendered in the report


# ────────────────────────────────────────────────────────────────────────────
# Built-in profiles
# ────────────────────────────────────────────────────────────────────────────

PROFILES: List[CaseProfile] = [
    # ─── 1. Generic / Unknown ────────────────────────────────────────────────
    CaseProfile(
        key="generic",
        display_name="Generic Forensic Triage",
        short_description="Run all baseline checks (no specific case type)",
        long_description=(
            "Runs every detection module against every artefact category. Useful when "
            "the nature of the incident isn't yet known, or for a baseline triage pass."
        ),
        focus_areas=[
            "usb_exfil", "cloud_upload", "fileshare_upload", "credential_theft",
            "lateral_movement", "persistence", "log_tampering", "anti_forensic",
            "hacktools", "personal_email",
        ],
        keyword_prompts=[
            KeywordPrompt(
                key="search_keywords",
                label="Optional: Keywords to search across all artefacts",
                placeholder="confidential\nsensitive_data\nproject_codename\nIP_addr_or_hostname\n...",
                description="Each line is searched (case-insensitive substring) against browser "
                            "history, recent files, prefetch, registry artefacts, and event logs.",
            ),
        ],
        workflow_summary=[
            "Baseline detection rules across all 8 modules",
            "User-provided keyword search across every parsed CSV/JSON",
            "USB device enumeration",
            "Browser cloud/fileshare/webmail visits",
            "Persistence sweep + offensive-tool catalogue",
            "Audit-log clearing detection",
        ],
    ),

    # ─── 2. DLP / Insider Threat ─────────────────────────────────────────────
    CaseProfile(
        key="dlp",
        display_name="DLP / Insider Threat / Data Exfiltration",
        short_description="User suspected of taking data out — USB, cloud, fileshare",
        long_description=(
            "Specialised workflow for data-loss-prevention investigations. The engine "
            "concentrates on egress channels (USB, cloud storage, anonymous file-shares, "
            "webmail) and correlates them with file-access timestamps. If you provide a "
            "list of sensitive filenames or DLP-flagged terms, every artefact is scanned "
            "for matches and matching file activity is reported as evidence."
        ),
        focus_areas=[
            "usb_exfil", "cloud_upload", "fileshare_upload",
            "personal_email", "anti_forensic",
        ],
        keyword_prompts=[
            KeywordPrompt(
                key="sensitive_filenames",
                label="Sensitive filenames or partial names (one per line)",
                placeholder="customer_db.xlsx\npayroll_2026\nproject_phoenix\nclient_list\n...",
                description="The engine searches MFT, USN journal, LNK shortcuts, browser "
                            "downloads and cloud-upload activity for these names. "
                            "Each hit becomes a finding with the exact artefact row as evidence.",
            ),
            KeywordPrompt(
                key="sensitive_keywords",
                label="DLP-classification keywords or document tags (optional)",
                placeholder="CONFIDENTIAL\nINTERNAL ONLY\nTRADE SECRET\nproject codename\n...",
                description="Searched in browser titles, document bookmarks, and recent-file paths.",
            ),
            KeywordPrompt(
                key="watched_extensions",
                label="File extensions of interest (one per line, default: archives + docs)",
                placeholder=".zip\n.7z\n.rar\n.xlsx\n.docx\n.pdf\n.csv",
                description="Recent-file and download activity for these extensions is highlighted.",
            ),
        ],
        workflow_summary=[
            "USB-device enumeration (USBSTOR registry → first/last connect timestamps)",
            "LNK shortcuts pointing to D:-Z: drive letters (removable media)",
            "Browser visits to cloud storage and anonymous file-sharing services",
            "Download history with destination paths",
            "Personal webmail access (compose-and-send-as-attachment channel)",
            "Sensitive-filename hits across MFT, recent files, downloads, and browser history",
            "Anti-forensic tool indicators (CCleaner, Eraser, BCWipe, SDelete)",
            "Archive-tool execution (7-Zip, WinRAR) with timestamps",
        ],
    ),

    # ─── 3. Malware / Compromise ─────────────────────────────────────────────
    CaseProfile(
        key="malware",
        display_name="Malware / Active Compromise",
        short_description="Suspected infection — find the malicious binary, persistence, lateral moves",
        long_description=(
            "Workflow for active-compromise investigations. The engine focuses on "
            "process-execution evidence (Prefetch, Amcache, $MFT) for known malware names, "
            "non-standard persistence (autoruns, services, scheduled tasks), credential-theft "
            "tools, lateral-movement indicators, and audit-log tampering. "
            "If you provide IOCs (file hashes, process names, C2 domains), each is searched "
            "across all artefacts and matches become findings."
        ),
        focus_areas=[
            "credential_theft", "lateral_movement", "persistence",
            "log_tampering", "anti_forensic", "hacktools",
        ],
        keyword_prompts=[
            KeywordPrompt(
                key="malicious_filenames",
                label="Suspected malicious filenames / process names (optional)",
                placeholder="evil.exe\nsvchost_fake\ndropper\nimplant\nbeacon\n...",
                description="Searched in Prefetch, Amcache, $MFT, services, and scheduled tasks.",
            ),
            KeywordPrompt(
                key="malicious_hashes",
                label="Known-bad SHA1/SHA256/MD5 hashes (optional)",
                placeholder="d41d8cd98f00b204e9800998ecf8427e\n44d88612fea8a8f36de82e1278abb02f\n...",
                description="Hashes are matched against Amcache (which records every binary's hash).",
            ),
            KeywordPrompt(
                key="c2_domains_or_ips",
                label="Suspected C2 domains or IPs (optional)",
                placeholder="evil.example.com\n203.0.113.42\nbeacon.bad\n...",
                description="Searched in browser history, DNS event logs, and registry network keys.",
            ),
            KeywordPrompt(
                key="malware_family_names",
                label="Known/suspected malware family names (optional)",
                placeholder="Emotet\nCobalt Strike\nQakbot\nLockBit\n...",
                description="Family/tool names are matched against Amcache, Prefetch and $MFT. "
                            "Any located binary is then analyzed with capa (capabilities + ATT&CK) and YARA.",
            ),
            KeywordPrompt(
                key="extra_sample_dirs",
                label="Extra directories on the image to deep-scan (optional)",
                placeholder="Users\\victim\\AppData\\Local\\Temp\nProgramData\\suspicious\n...",
                description="Every PE file under these paths is scanned with capa and YARA, "
                            "independent of Amcache. Paths are relative to the mounted image root.",
            ),
            KeywordPrompt(
                key="custom_yara_rules",
                label="Custom YARA rule files or folders (optional)",
                placeholder="C:\\rules\\apt.yar\nC:\\rules\\ransomware\\",
                description="Added to the bundled rule set in tools/yara_rules/. "
                            "Accepts .yar/.yara files or directories.",
            ),
        ],
        workflow_summary=[
            "Process-execution sweep (Prefetch, Amcache, $MFT) for known offensive tooling",
            "User-supplied malware filename / hash / family / C2 IOC search across all artefacts",
            "Hash/name match → locate binary on image → capa capability + ATT&CK analysis",
            "YARA signature scan of located binaries and any supplied sample directories",
            "Non-standard persistence: registry Run keys, services, scheduled tasks, WMI",
            "Credential-theft tooling (Mimikatz, secretsdump, lsass.dmp) detection",
            "Lateral-movement tooling (PsExec, wmiexec, atexec, Impacket) detection",
            "Event ID 1102/104 audit-log clear detection",
            "Privacy / anti-forensic tool detection (Tor, VPN, file-shredders)",
            "Suspicious process-creation events (4688) outside system32",
        ],
    ),

    # ─── 4. Phishing / Initial-Access ────────────────────────────────────────
    CaseProfile(
        key="phishing",
        display_name="Phishing / Email-Borne Initial Access",
        short_description="User clicked a link / opened an attachment — trace the entry vector",
        long_description=(
            "Reconstructs the user's actions immediately before suspected compromise: "
            "browser navigation timeline, recent downloads (especially documents and archives), "
            "Office macro-enabled file execution (in Prefetch / OFC.tmp / RecentDocs), "
            "and the resulting child processes."
        ),
        focus_areas=[
            "credential_theft", "persistence", "hacktools",
        ],
        keyword_prompts=[
            KeywordPrompt(
                key="incident_window",
                label="Approximate incident time window (optional)",
                placeholder="2026-04-25 09:00 to 2026-04-25 12:00",
                multiline=False,
                description="Restricts timeline analysis to this window when present.",
            ),
            KeywordPrompt(
                key="suspicious_senders",
                label="Suspicious sender addresses or domains (optional)",
                placeholder="hr-update@evil.com\n@bad-domain.org\n...",
                description="Searched in browser history (webmail), event logs, and saved files.",
            ),
            KeywordPrompt(
                key="lure_filenames",
                label="Lure document filenames (optional)",
                placeholder="invoice_2026.docm\nresume.zip\nshipment_details.xlsx\n...",
                description="Tracked across MFT, downloads, RecentDocs, Office MRU.",
            ),
        ],
        workflow_summary=[
            "Browser-download timeline (target paths + source URLs)",
            "Office macro-enabled document execution (RecentDocs + Office MRU)",
            "Child-process trees from suspected lure files (4688 + Sysmon 1)",
            "PowerShell script-block events (4104) immediately after lure open",
            "Persistence + credential-theft + lateral-movement sweep (post-execution)",
        ],
    ),

    # ─── 5. Ransomware ───────────────────────────────────────────────────────
    CaseProfile(
        key="ransomware",
        display_name="Ransomware",
        short_description="Encrypted files / ransom note — identify variant, entry point, scope",
        long_description=(
            "Focused workflow for ransomware cases. Searches for ransom-note filenames, "
            "encryption-tool execution, mass-rename activity in $MFT/USN, shadow-copy deletion, "
            "and known ransomware-family binary indicators."
        ),
        focus_areas=[
            "persistence", "credential_theft", "lateral_movement",
            "log_tampering", "data_destruction", "hacktools",
        ],
        keyword_prompts=[
            KeywordPrompt(
                key="ransom_note_names",
                label="Ransom-note filenames seen in the environment",
                placeholder="HOW_TO_DECRYPT.txt\nREADME_RECOVER.html\n_FILES_ARE_ENCRYPTED_.txt\n...",
                description="Searched across MFT and USN to identify the encryption sweep timeline.",
            ),
            KeywordPrompt(
                key="encrypted_extensions",
                label="Extension suffix added to encrypted files (e.g. .locked)",
                placeholder=".locked\n.encrypted\n.crypt\n.lockbit\n...",
                multiline=True,
                description="MFT records bearing these extensions are timestamped and counted.",
            ),
        ],
        workflow_summary=[
            "Ransom-note filename sweep across MFT and USN",
            "Mass-rename detection (USN journal anomalies)",
            "Shadow-copy deletion events (vssadmin, wbadmin, WMIC)",
            "Encryption-tool execution evidence",
            "Lateral-movement + credential-theft (entry-point reconstruction)",
            "Audit-log clear events (defensive evasion)",
        ],
    ),

    # ─── 6. Lateral Movement / AD Compromise ────────────────────────────────
    CaseProfile(
        key="lateral",
        display_name="Lateral Movement / AD Compromise",
        short_description="Hop from host to host — RDP, SMB, WMI, Kerberos abuse",
        long_description=(
            "Examines authentication, remote-execution, and credential-related artefacts. "
            "Particularly relevant for domain-joined hosts where the adversary may have "
            "moved to/from this machine via PsExec, WMI, RDP, or pass-the-hash."
        ),
        focus_areas=[
            "lateral_movement", "credential_theft", "persistence",
            "log_tampering", "hacktools",
        ],
        keyword_prompts=[
            KeywordPrompt(
                key="suspect_accounts",
                label="Suspect user / service accounts (optional)",
                placeholder="svc_backup\nadmin_temp\nlocaladmin\n...",
                description="Searched in security event logs, scheduled tasks, services, "
                            "and registry user lists.",
            ),
            KeywordPrompt(
                key="suspect_hosts",
                label="Suspect remote hostnames or IPs (optional)",
                placeholder="DC01\n10.0.0.42\nworkstation-99\n...",
                description="Searched in event logs (4624/4625 source), RDP / SMB events.",
            ),
        ],
        workflow_summary=[
            "Authentication events: failed (4625), explicit-creds (4648), Kerberos (4768/4769)",
            "RDP session events (TerminalServices-LocalSessionManager)",
            "SMB / share-access events",
            "PsExec / wmiexec / atexec / Impacket execution evidence",
            "BloodHound / SharpHound / Rubeus / Kerberoast indicators",
            "Account-management events (4720/4732 — new admin accounts)",
        ],
    ),
]


def get_profile(key: str) -> Optional[CaseProfile]:
    for p in PROFILES:
        if p.key == key:
            return p
    return None


def list_profiles() -> List[CaseProfile]:
    return PROFILES
