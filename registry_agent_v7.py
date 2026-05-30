#!/usr/bin/env python3
"""
Windows Registry Forensic Agent v9 — "THE BEAST" (Codex-Remediated)
Fixes applied:
  - P0: Full-hive recursive export to JSONL (root-to-leaf walk)
  - P0: Multi-user hive staging collision fixed (unique dest names)
  - P0: SECURITY hive fully parsed with policy/audit/LSA extraction
  - P0: DEFAULT hive discovery and full-parse
  - P1: Raw hives preserved in output artifacts/raw_registry/
  - P1: Transaction-log (.LOG1/.LOG2) discovery and copy
  - P1: HTML report escapes ALL registry strings (XSS-safe)
  - P2: SAM RID parsed from key path, not value_type()
  - P2: JSONL records include raw_hex + decoded_value for forensic fidelity
  - P2: MAX_PER_ARTIFACT limits removed from data collection entirely
  - P3: Dead extractors (dns_cache, svchost_groups, chrome_prefs) now wired in
  - P3: Dead code after return removed
  - SAM RID / last logon / failed login count parsing (corrected)
  - DNS cache artifact
  - SECURITY hive: security policy, audit policy, LSA secrets extraction
  - IE Zone Map (security zone tampering)
  - Typed path history (Explorer address bar)
  - CapabilityAccessManager (privacy: camera/mic access)
  - LastVisitedMRU
  - WordWheelQuery
  - Deep service anomaly scoring (non-System32 ImagePath, etc.)
  - Proper null/empty field handling
  - VPN indicator serialization fix (was storing Registry object)
  - Dark-mode HTML report with full collapsible sections, severity badges,
    timeline, per-user tabs, search/filterilter
"""

import os, sys, json, argparse, logging, datetime, re, struct, hashlib, codecs
import html as html_mod
import shutil, time, tempfile, base64
from pathlib import Path
from typing import Optional, List, Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

try:
    from Registry import Registry
except ImportError:
    log.error("python-registry not installed. Run: pip install python-registry")
    sys.exit(1)

try:
    import requests
except ImportError:
    log.error("requests not installed. Run: pip install requests")
    sys.exit(1)

# â”€â”€â”€ CONFIG â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
OLLAMA_URL     = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL   = os.environ.get("OLLAMA_MODEL", "phi3:mini")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "120"))
MAX_PER_ARTIFACT = 60          # Only used for HTML display limits, not data collection
MAX_HTML_ROWS    = 500         # Max rows shown per HTML table

SEVERITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# USB device class GUID â†’ human label
USB_CLASS_MAP = {
    "36FC9E60-C465-11CF-8056-444553540000": "USB Hub / Root Hub",
    "4D36E967-E325-11CE-BFC1-08002BE10318": "ðŸ“¦ Mass Storage Device",
    "4D36E96B-E325-11CE-BFC1-08002BE10318": "âŒ¨ï¸  Keyboard",
    "4D36E96F-E325-11CE-BFC1-08002BE10318": "ðŸ–±ï¸  Mouse / Pointing Device",
    "4D36E97B-E325-11CE-BFC1-08002BE10318": "ðŸ–¨ï¸  Printer",
    "4D36E97D-E325-11CE-BFC1-08002BE10318": "ðŸŒ Network Adapter",
    "4D36E980-E325-11CE-BFC1-08002BE10318": "ðŸ’¾ Floppy Disk Controller",
    "4D36E96C-E325-11CE-BFC1-08002BE10318": "ðŸ“º Display Adapter",
    "4D36E96E-E325-11CE-BFC1-08002BE10318": "ðŸ”Š Multimedia / Audio",
    "745A17A0-74D3-11D0-B6FE-00A0C90F57DA": "ðŸŽ® HID (Human Interface Device)",
    "6BDD1FC6-810F-11D0-BEC7-08002BE2092F": "ðŸ“· Imaging / Camera",
    "CA3E7AB9-B4C3-4AE6-8251-579EF933890F": "ðŸ“· Camera",
    "6AC27878-A6FA-4155-BA85-F98F491D4F33": "ðŸ“± Windows Portable Device (MTP)",
    "F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE": "ðŸ“± Windows Portable Device (MTP)",
    "EEC5AD98-8080-425F-922A-DABF3DE3F69A": "ðŸ“± MTP (Media Transfer Protocol)",
    "E0CBF06C-CD8B-4647-BB8A-263B43F0F974": "ðŸ”µ Bluetooth",
    "50DD5230-BA8A-11D1-BF5D-0000F805F530": "ðŸ’¿ Smart Card Reader",
}

# Known legitimate Windows service ImagePath prefixes
LEGIT_SVC_PATHS = [
    "system32", "syswow64", "systemroot", "%systemroot%",
    "c:\\windows", "windir", "%windir%", "driverstore",
    "c:\\program files\\windows", "c:\\program files (x86)\\windows",
    "c:\\program files\\microsoft", "c:\\program files (x86)\\microsoft",
    "microsoft\\edgeupdate", "google\\update", "google\\chrome",
    "realtek", "intel", "logitech", "zerotier",
    "gamingservices", "windowsapps"
]

# â”€â”€â”€ HELPERS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def safe_open(path):
    try:
        return Registry.Registry(str(path))
    except Exception as e:
        log.warning(f"  Cannot open hive {path}: {e}")
        return None

def safe_key(reg, path):
    try:
        return reg.open(path)
    except Exception:
        return None

def safe_values(key):
    try:
        return list(key.values())
    except Exception:
        return []

def safe_subkeys(key):
    try:
        return list(key.subkeys())
    except Exception:
        return []

def val_str(v) -> str:
    try:
        val = v.value()
        if isinstance(val, bytes):
            return val.decode("utf-16-le", errors="ignore").rstrip("\x00") or val.hex()
        if isinstance(val, list):
            return " | ".join(str(x) for x in val)
        return str(val)
    except Exception:
        return ""

def decode_systemtime(raw: bytes) -> str:
    """
    Decode Windows SYSTEMTIME structure (16 bytes):
    WORD Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds
    """
    if not isinstance(raw, bytes) or len(raw) < 16:
        return str(raw)
    try:
        year, month, dow, day, hour, minute, second, ms = struct.unpack_from("<8H", raw)
        if year < 1601 or year > 2100:
            return raw.hex()
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d} UTC"
    except Exception:
        return raw.hex() if isinstance(raw, bytes) else str(raw)

def decode_filetime(raw) -> str:
    """Convert Windows FILETIME (int or 8-byte bytes) to human-readable UTC."""
    try:
        if isinstance(raw, bytes) and len(raw) >= 8:
            ft = struct.unpack_from("<Q", raw)[0]
        elif isinstance(raw, int):
            ft = raw
        else:
            return str(raw)
        if ft == 0:
            return ""
        epoch = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
        return epoch.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(raw)

def decode_unix_epoch(raw) -> str:
    """Convert Unix timestamp (int or YYYYMMDD string) to human-readable."""
    try:
        s = str(raw).strip()
        if re.match(r'^\d{8}$', s):
            return f"{s[:4]}-{s[4:6]}-{s[6:8]}"
        if s.isdigit() and len(s) >= 9:
            t = int(s)
            return datetime.datetime.utcfromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S UTC")
        return s
    except Exception:
        return str(raw)

def rot13_decode(s: str) -> str:
    try:
        return codecs.decode(s, "rot_13")
    except Exception:
        return s

def classify_usb(device_type_str: str, class_guid: str = "") -> str:
    """Return emoji + label for USB device type."""
    dt = device_type_str.upper()
    if "DISK&VEN" in dt:
        return "ðŸ“¦ Mass Storage (Hard Disk)"
    if "USBSTOR\\CDROM" in dt or "CDROM" in dt:
        return "ðŸ’¿ Optical Drive"
    if "USBSTOR\\FLOPPY" in dt:
        return "ðŸ’¾ Floppy"
    if "USBSTOR\\TAPE" in dt:
        return "ðŸŽžï¸ Tape"
    if "USBSTOR\\OTHER" in dt:
        return "ðŸ“¦ Mass Storage (Other)"
    cg = class_guid.upper().strip("{}")
    for guid, label in USB_CLASS_MAP.items():
        if guid.upper() == cg:
            return label
    return "ðŸ”Œ USB Device"

def is_suspicious_svc_path(path: str) -> bool:
    if not path:
        return False
    pl = path.lower()
    for legit in LEGIT_SVC_PATHS:
        if legit in pl:
            return False
    suspicious_dirs = [r"\temp\\", r"\tmp\\", r"\appdata\\", r"\users\\public\\",
                       r"\downloads\\", r"\recycler", r"\recycle.bin"]
    for s in suspicious_dirs:
        if s in pl:
            return True
    # non-system32 exe with no recognized parent
    if pl.endswith(".exe") and "system32" not in pl and "syswow64" not in pl and \
       "driverstore" not in pl and "program files" not in pl and "windows" not in pl:
        return True
    return False

def val_for(key, name: str, default="") -> str:
    if not key:
        return default
    for v in safe_values(key):
        if v.name().lower() == name.lower():
            return val_str(v)
    return default

# â”€â”€â”€ ARTIFACT EXTRACTOR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class ArtifactExtractor:
    def __init__(self, hives: dict):
        self.h = hives

    def _reg(self, name):
        return self.h.get(name)

    # â”€â”€ System Info â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def os_info(self) -> dict:
        reg = self._reg("SOFTWARE")
        if not reg:
            return {}
        key = safe_key(reg, "Microsoft\\Windows NT\\CurrentVersion")
        if not key:
            return {}
        info = {}
        for v in safe_values(key):
            info[v.name()] = val_str(v)
        # Fix InstallDate (Unix epoch)
        if "InstallDate" in info:
            info["InstallDate_decoded"] = decode_unix_epoch(info["InstallDate"])
        if "InstallTime" in info:
            info["InstallTime_decoded"] = decode_filetime(info.get("InstallTime", ""))
        return info

    def computer_name(self) -> str:
        reg = self._reg("SYSTEM")
        if not reg:
            return ""
        for cs in ["ControlSet001", "CurrentControlSet"]:
            key = safe_key(reg, f"{cs}\\Control\\ComputerName\\ComputerName")
            if key:
                return val_for(key, "ComputerName")
        return ""

    def timezone(self) -> dict:
        reg = self._reg("SYSTEM")
        if not reg:
            return {}
        for cs in ["ControlSet001", "CurrentControlSet"]:
            key = safe_key(reg, f"{cs}\\Control\\TimeZoneInformation")
            if key:
                return {v.name(): val_str(v) for v in safe_values(key)}
        return {}

    def last_shutdown(self) -> str:
        reg = self._reg("SYSTEM")
        if not reg:
            return ""
        for cs in ["ControlSet001", "CurrentControlSet"]:
            key = safe_key(reg, f"{cs}\\Control\\Windows")
            if key:
                for v in safe_values(key):
                    if v.name() == "ShutdownTime":
                        try:
                            return decode_filetime(v.value())
                        except Exception:
                            pass
        return ""

    def current_control_set(self) -> str:
        reg = self._reg("SYSTEM")
        if not reg:
            return "ControlSet001"
        key = safe_key(reg, "Select")
        if key:
            for v in safe_values(key):
                if v.name() == "Current":
                    return f"ControlSet{v.value():03d}"
        return "ControlSet001"

    # â”€â”€ USB Devices â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def usb_devices(self) -> List[dict]:
        results = []
        reg = self._reg("SYSTEM")
        if not reg:
            return results
        seen = set()
        for cs in ["ControlSet001", "ControlSet002", "CurrentControlSet"]:
            usbstor = safe_key(reg, f"{cs}\\Enum\\USBSTOR")
            if not usbstor:
                continue
            for dev_type in safe_subkeys(usbstor):
                for instance in safe_subkeys(dev_type):
                    uid = instance.name()
                    if uid in seen:
                        continue
                    seen.add(uid)
                    info = {
                        "device_category": classify_usb(dev_type.name()),
                        "device_type_raw": dev_type.name(),
                        "instance_id": instance.name(),
                        "friendly_name": "",
                        "manufacturer": "",
                        "serial_number": "",
                        "driver": "",
                        "class_guid": "",
                        "first_install": "",
                        "last_arrival": "",
                        "last_removal": "",
                        "parent_id_prefix": "",
                    }
                    for v in safe_values(instance):
                        n = v.name()
                        if n == "FriendlyName":      info["friendly_name"] = val_str(v)
                        elif n == "Mfg":             info["manufacturer"] = val_str(v)
                        elif n == "Driver":          info["driver"] = val_str(v)
                        elif n == "ClassGUID":       info["class_guid"] = val_str(v)
                        elif n == "ParentIdPrefix":  info["parent_id_prefix"] = val_str(v)
                    # Serial: last part of InstanceID
                    parts = instance.name().split("&")
                    if parts:
                        info["serial_number"] = parts[-1][:32] if len(parts[-1]) > 2 else instance.name().split("\\")[-1]
                    # Re-classify with class guid
                    if not info["friendly_name"] or info["device_category"] == "ðŸ”Œ USB Device":
                        cg = info["class_guid"].strip("{}")
                        for guid, label in USB_CLASS_MAP.items():
                            if guid.upper() == cg.upper():
                                info["device_category"] = label
                                break
                    # Timestamps via Properties
                    for prop_sub, field in [
                        ("0064", "first_install"), ("0066", "last_arrival"), ("0067", "last_removal")
                    ]:
                        props = safe_key(reg, f"{cs}\\Enum\\USBSTOR\\{dev_type.name()}\\{instance.name()}\\Properties\\{{83da6326-97a6-4088-9453-a1923f573b29}}\\{prop_sub}")
                        if props:
                            for v in safe_values(props):
                                try:
                                    info[field] = decode_filetime(v.value())
                                except Exception:
                                    pass
                    results.append(info)
            if results:
                break

        # Also grab USB (non-storage) from Enum\USB
        usb_key = safe_key(reg, f"ControlSet001\\Enum\\USB")
        if usb_key:
            for vid_pid in safe_subkeys(usb_key):
                for instance in safe_subkeys(vid_pid):
                    uid2 = f"USB_{vid_pid.name()}_{instance.name()}"
                    if uid2 in seen:
                        continue
                    seen.add(uid2)
                    info = {
                        "device_category": "ðŸ”Œ USB Device",
                        "device_type_raw": vid_pid.name(),
                        "instance_id": instance.name(),
                        "friendly_name": "",
                        "manufacturer": "",
                        "serial_number": instance.name(),
                        "driver": "", "class_guid": "",
                        "first_install": "", "last_arrival": "", "last_removal": "",
                        "parent_id_prefix": "",
                    }
                    for v in safe_values(instance):
                        n = v.name()
                        if n == "FriendlyName":  info["friendly_name"] = val_str(v)
                        elif n == "Mfg":         info["manufacturer"] = val_str(v)
                        elif n == "ClassGUID":
                            info["class_guid"] = val_str(v)
                            cg = info["class_guid"].strip("{}")
                            for guid, label in USB_CLASS_MAP.items():
                                if guid.upper() == cg.upper():
                                    info["device_category"] = label
                                    break
                    if info["friendly_name"]:
                        results.append(info)

        return results

    # â”€â”€ Persistence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def persistence_system(self) -> List[dict]:
        results = []
        targets = [
            ("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run"),
            ("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            ("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\RunServices"),
            ("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"),
            ("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),
            ("SOFTWARE", "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("SOFTWARE", "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ]
        for hive_name, path in targets:
            reg = self._reg(hive_name)
            if not reg:
                continue
            key = safe_key(reg, path)
            if not key:
                continue
            for v in safe_values(key):
                val = val_str(v)
                suspicious = is_suspicious_svc_path(val)
                results.append({
                    "hive": hive_name, "key": path, "name": v.name(),
                    "value": val, "suspicious": "âš ï¸ YES" if suspicious else "OK"
                })
        return results

    def persistence_user(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        for path in [
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        ]:
            key = safe_key(reg, path)
            if not key:
                continue
            for v in safe_values(key):
                val = val_str(v)
                results.append({
                    "user": user, "key": path, "name": v.name(),
                    "value": val, "suspicious": "âš ï¸ YES" if is_suspicious_svc_path(val) else "OK"
                })
        return results

    # â”€â”€ Winlogon & Special Persistence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def winlogon(self) -> dict:
        reg = self._reg("SOFTWARE")
        if not reg:
            return {}
        key = safe_key(reg, "Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
        if not key:
            return {}
        result = {v.name(): val_str(v) for v in safe_values(key)}
        # Flag anomalies
        result["_userinit_ok"]     = "userinit.exe" in result.get("Userinit", "").lower()
        result["_shell_ok"]        = result.get("Shell", "") == "explorer.exe"
        result["_autologon"]       = result.get("AutoAdminLogon", "0") == "1"
        result["_autologon_user"]  = result.get("DefaultUserName", "")
        result["_autologon_pass"]  = result.get("DefaultPassword", "âš ï¸ FOUND â€” CREDENTIAL EXPOSURE")
        result["_legal_notice"]    = result.get("LegalNoticeText", "")
        return result

    def autologon_check(self) -> dict:
        reg = self._reg("SOFTWARE")
        if not reg:
            return {}
        key = safe_key(reg, "Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
        if not key:
            return {}
        return {
            "AutoAdminLogon": val_for(key, "AutoAdminLogon", "0"),
            "DefaultUserName": val_for(key, "DefaultUserName"),
            "DefaultPassword": val_for(key, "DefaultPassword") or "(not set)",
            "DefaultDomainName": val_for(key, "DefaultDomainName"),
            "AutoLogonCount": val_for(key, "AutoLogonCount"),
        }

    def appinit_dlls(self) -> dict:
        result = {}
        reg = self._reg("SOFTWARE")
        if not reg:
            return result
        for path in [
            "Microsoft\\Windows NT\\CurrentVersion\\Windows",
            "WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
        ]:
            key = safe_key(reg, path)
            if not key:
                continue
            for v in safe_values(key):
                if "appinit" in v.name().lower():
                    result[v.name()] = val_str(v)
        return result

    def ifeo(self) -> List[dict]:
        """Image File Execution Options â€” debugger hijack detection."""
        results = []
        reg = self._reg("SOFTWARE")
        if not reg:
            return results
        key = safe_key(reg, "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options")
        if not key:
            return results
        for subkey in safe_subkeys(key):
            for v in safe_values(subkey):
                if v.name() in ("Debugger", "GlobalFlag"):
                    results.append({
                        "target_exe": subkey.name(),
                        "value_name": v.name(),
                        "value": val_str(v),
                        "risk": "âš ï¸ DEBUGGER HIJACK" if v.name() == "Debugger" else "CHECK"
                    })
        return results

    # â”€â”€ Services â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def services(self) -> List[dict]:
        results = []
        reg = self._reg("SYSTEM")
        if not reg:
            return results
        cs = self.current_control_set()
        key = safe_key(reg, f"{cs}\\Services")
        if not key:
            key = safe_key(reg, "ControlSet001\\Services")
        if not key:
            return results
        start_map = {"0": "Boot", "1": "System", "2": "Auto", "3": "Manual/Demand", "4": "Disabled"}
        type_map  = {"1": "Kernel Driver", "2": "File Sys Driver", "4": "Adapter",
                     "8": "Recognizer", "16": "Own Process", "32": "Shared Process",
                     "96": "Interactive", "272": "Own+Interactive", "288": "Shared+Interactive"}
        for svc in safe_subkeys(key):
            info = {
                "name": svc.name(), "display_name": "", "start": "", "start_label": "",
                "type": "", "type_label": "", "image_path": "", "description": "",
                "object_name": "", "suspicious_path": ""
            }
            for v in safe_values(svc):
                n = v.name()
                if n == "DisplayName":  info["display_name"] = val_str(v)
                elif n == "Start":
                    info["start"] = val_str(v)
                    info["start_label"] = start_map.get(val_str(v), val_str(v))
                elif n == "Type":
                    info["type"] = val_str(v)
                    info["type_label"] = type_map.get(val_str(v), val_str(v))
                elif n == "ImagePath":  info["image_path"] = val_str(v)
                elif n == "Description": info["description"] = val_str(v)[:120]
                elif n == "ObjectName": info["object_name"] = val_str(v)
            info["suspicious_path"] = "âš ï¸ YES" if is_suspicious_svc_path(info["image_path"]) else ""
            results.append(info)
        return results

    # â”€â”€ Network â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def wifi_profiles(self) -> List[dict]:
        results = []
        reg = self._reg("SOFTWARE")
        if not reg:
            return results
        key = safe_key(reg, "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")
        if not key:
            return results
        cat_map = {"0": "Unidentified", "1": "Public", "2": "Private", "3": "Domain"}
        for profile in safe_subkeys(key):
            info = {
                "profile_guid": profile.name(),
                "profile_name": "",
                "description": "",
                "managed": "",
                "category": "",
                "category_label": "",
                "name_type": "",
                "date_created": "",
                "date_last_connected": "",
            }
            for v in safe_values(profile):
                n = v.name()
                raw = v.value()
                if n == "ProfileName":       info["profile_name"] = val_str(v)
                elif n == "Description":     info["description"] = val_str(v)
                elif n == "Managed":         info["managed"] = val_str(v)
                elif n == "Category":
                    info["category"] = val_str(v)
                    info["category_label"] = cat_map.get(val_str(v), val_str(v))
                elif n == "NameType":        info["name_type"] = val_str(v)
                elif n == "DateCreated":     info["date_created"] = decode_systemtime(raw) if isinstance(raw, bytes) else val_str(v)
                elif n == "DateLastConnected": info["date_last_connected"] = decode_systemtime(raw) if isinstance(raw, bytes) else val_str(v)
            results.append(info)
        return results

    def network_signatures(self) -> List[dict]:
        results = []
        reg = self._reg("SOFTWARE")
        if not reg:
            return results
        for path in [
            "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed",
            "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
        ]:
            key = safe_key(reg, path)
            if not key:
                continue
            managed = "Managed" in path
            for sig in safe_subkeys(key):
                info = {"managed": managed, "guid": sig.name(), "description": "", "dns_suffix": "",
                        "first_network": "", "default_gateway_mac": ""}
                for v in safe_values(sig):
                    n = v.name()
                    if n == "Description":        info["description"] = val_str(v)
                    elif n == "DnsSuffix":        info["dns_suffix"] = val_str(v)
                    elif n == "FirstNetwork":     info["first_network"] = val_str(v)
                    elif n == "DefaultGatewayMac":
                        try:
                            raw = v.value()
                            if isinstance(raw, bytes):
                                info["default_gateway_mac"] = ":".join(f"{b:02X}" for b in raw[:6])
                        except Exception:
                            info["default_gateway_mac"] = val_str(v)
                results.append(info)
        return results

    def network_interfaces(self) -> List[dict]:
        results = []
        reg = self._reg("SYSTEM")
        if not reg:
            return results
        cs = self.current_control_set()
        key = safe_key(reg, f"{cs}\\Services\\Tcpip\\Parameters\\Interfaces")
        if not key:
            return results
        for iface in safe_subkeys(key):
            info = {"guid": iface.name(), "enable_dhcp": "", "ip_address": "",
                    "subnet_mask": "", "default_gateway": "", "dns_servers": "", "domain": ""}
            for v in safe_values(iface):
                n = v.name()
                if n == "EnableDHCP":      info["enable_dhcp"] = val_str(v)
                elif n in ("DhcpIPAddress", "IPAddress"):
                    info["ip_address"] = val_str(v)
                elif n in ("DhcpSubnetMask", "SubnetMask"):
                    info["subnet_mask"] = val_str(v)
                elif n in ("DhcpDefaultGateway", "DefaultGateway"):
                    info["default_gateway"] = val_str(v)
                elif n in ("DhcpNameServer", "NameServer"):
                    info["dns_servers"] = val_str(v)
                elif n == "Domain":        info["domain"] = val_str(v)
            results.append(info)
        return results

    # â”€â”€ SAM / Accounts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def user_accounts(self) -> List[dict]:
        """P2 fix: Parse RID from SAM Users key path, not value_type().
        Also parse F binary structure for last logon, failed count, flags."""
        results = []
        reg = self._reg("SAM")
        if not reg:
            return results
        names_key = safe_key(reg, "SAM\\Domains\\Account\\Users\\Names")
        if not names_key:
            return results

        # Build RIDâ†’username map from Names subkeys
        # Under Names\\<username>, the default value's type IS the RID (this is correct)
        # But we also cross-reference with Users\\<hex RID> for the F binary
        rid_map = {}
        for user_key in safe_subkeys(names_key):
            username = user_key.name()
            rid_val = ""
            try:
                for v in safe_values(user_key):
                    # The default value's value_type() IS the RID in SAM Names keys
                    rid_val = v.value_type()
            except Exception:
                pass

            if isinstance(rid_val, int) and rid_val > 0:
                rid = rid_val
            else:
                rid = 0

            info = {
                "username": username,
                "last_write": str(user_key.timestamp()),
                "rid": str(rid) if rid > 0 else "",
                "rid_hex": f"0x{rid:04X}" if rid > 0 else "",
                "last_logon": "",
                "failed_login_count": "",
                "logon_count": "",
                "account_flags": "",
                "flags": "",
            }

            # Parse the F binary from Users\\<hex RID> for detailed account info
            if rid > 0:
                hex_rid = f"{rid:08X}"
                f_key = safe_key(reg, f"SAM\\Domains\\Account\\Users\\{hex_rid}")
                if f_key:
                    for v in safe_values(f_key):
                        if v.name() == "F":
                            try:
                                fdata = v.value()
                                if isinstance(fdata, bytes) and len(fdata) >= 80:
                                    # F structure offsets (Windows NT 5.x+):
                                    # 0x08: Last logon (FILETIME)
                                    # 0x18: Password last set (FILETIME)
                                    # 0x28: Account expires (FILETIME)
                                    # 0x38: Last failed logon (FILETIME)
                                    # 0x30: RID (DWORD at offset 0x30)
                                    # 0x40: Failed login count (WORD)
                                    # 0x42: Logon count (WORD)
                                    last_logon_ft = struct.unpack_from("<Q", fdata, 8)[0]
                                    if last_logon_ft > 0:
                                        info["last_logon"] = decode_filetime(last_logon_ft)
                                    if len(fdata) >= 68:
                                        info["failed_login_count"] = str(struct.unpack_from("<H", fdata, 64)[0])
                                        info["logon_count"] = str(struct.unpack_from("<H", fdata, 66)[0])
                                    if len(fdata) >= 58:
                                        flags_val = struct.unpack_from("<H", fdata, 56)[0]
                                        flag_names = []
                                        if flags_val & 0x0001: flag_names.append("DISABLED")
                                        if flags_val & 0x0004: flag_names.append("LOCKOUT")
                                        if flags_val & 0x0020: flag_names.append("NO_PASSWORD_REQUIRED")
                                        if flags_val & 0x0200: flag_names.append("NORMAL_ACCOUNT")
                                        if flags_val & 0x10000: flag_names.append("DONT_EXPIRE_PASSWORD")
                                        info["account_flags"] = " | ".join(flag_names) if flag_names else f"0x{flags_val:04X}"
                            except Exception as e:
                                log.debug(f"    SAM F parse error for RID {rid}: {e}")

            results.append(info)
        return results

    def last_logon_info(self) -> dict:
        reg = self._reg("SOFTWARE")
        if not reg:
            return {}
        key = safe_key(reg, "Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI")
        if not key:
            return {}
        return {v.name(): val_str(v) for v in safe_values(key)}

    # â”€â”€ Installed Software â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def installed_software(self) -> List[dict]:
        results = []
        seen = set()
        reg = self._reg("SOFTWARE")
        if not reg:
            return results
        for path in [
            "Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ]:
            key = safe_key(reg, path)
            if not key:
                continue
            for app in safe_subkeys(key):
                info = {"name": "", "version": "", "publisher": "",
                        "install_date": "", "install_location": "", "uninstall_string": ""}
                for v in safe_values(app):
                    n = v.name()
                    if n == "DisplayName":       info["name"] = val_str(v)
                    elif n == "DisplayVersion":  info["version"] = val_str(v)
                    elif n == "Publisher":       info["publisher"] = val_str(v)
                    elif n == "InstallDate":
                        raw_d = val_str(v)
                        info["install_date"] = decode_unix_epoch(raw_d)
                    elif n == "InstallLocation": info["install_location"] = val_str(v)
                    elif n == "UninstallString": info["uninstall_string"] = val_str(v)
                if info["name"] and info["name"] not in seen:
                    seen.add(info["name"])
                    results.append(info)
        return sorted(results, key=lambda x: x.get("install_date", "") or "", reverse=True)

    # â”€â”€ Scheduled Tasks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def scheduled_tasks(self) -> List[dict]:
        results = []
        reg = self._reg("SOFTWARE")
        if not reg:
            return results
        key = safe_key(reg, "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks")
        if not key:
            return results
        for task in safe_subkeys(key):
            info = {"guid": task.name(), "path": "", "author": "", "actions_preview": ""}
            for v in safe_values(task):
                n = v.name()
                if n == "Path":
                    info["path"] = val_str(v)
                elif n == "Actions":
                    try:
                        raw = v.value()
                        if isinstance(raw, bytes):
                            decoded = raw.decode("utf-16-le", errors="ignore")
                            cleaned = re.sub(r'[^\x20-\x7E\n]', '', decoded)
                            info["actions_preview"] = cleaned[:300]
                    except Exception:
                        pass
            results.append(info)
        return results

    # â”€â”€ BAM â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def bam_entries(self) -> List[dict]:
        results = []
        reg = self._reg("SYSTEM")
        if not reg:
            return results
        for cs in ["ControlSet001", "CurrentControlSet"]:
            key = safe_key(reg, f"{cs}\\Services\\bam\\State\\UserSettings")
            if not key:
                key = safe_key(reg, f"{cs}\\Services\\bam\\UserSettings")
            if not key:
                continue
            for user_sid in safe_subkeys(key):
                for v in safe_values(user_sid):
                    name = v.name()
                    if "\\" in name and name.endswith(".exe"):
                        ts = ""
                        try:
                            raw = v.value()
                            if isinstance(raw, bytes) and len(raw) >= 8:
                                ts = decode_filetime(raw)
                        except Exception:
                            pass
                        results.append({
                            "sid": user_sid.name(), "exe_path": name, "last_run": ts,
                            "suspicious": "âš ï¸ YES" if is_suspicious_svc_path(name) else ""
                        })
            if results:
                break
        return results

    # â”€â”€ ShimCache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def shimcache(self) -> List[dict]:
        results = []
        reg = self._reg("SYSTEM")
        if not reg:
            return results
        for cs in ["ControlSet001", "CurrentControlSet"]:
            key = safe_key(reg, f"{cs}\\Control\\Session Manager\\AppCompatCache")
            if not key:
                continue
            for v in safe_values(key):
                if v.name() != "AppCompatCache":
                    continue
                try:
                    raw = v.value()
                    if not isinstance(raw, bytes):
                        continue
                    sig = raw[:4]
                    # Win10: header 128 bytes, entries with "00ts" signature
                    offset = 128
                    count = 0
                    while offset < len(raw) - 12 and count < 10000:
                        if raw[offset:offset+4] == b'\x30\x30\x74\x73':
                            try:
                                data_len = struct.unpack_from("<I", raw, offset + 8)[0]
                                data_off = struct.unpack_from("<I", raw, offset + 12)[0]
                                if data_off > 0 and data_off + data_len <= len(raw):
                                    path = raw[data_off:data_off+data_len].decode("utf-16-le", errors="ignore")
                                    results.append({"exe_path": path,
                                                     "suspicious": "âš ï¸" if is_suspicious_svc_path(path) else ""})
                                    count += 1
                                offset += 52 + data_len
                            except Exception:
                                offset += 4
                        else:
                            offset += 4
                except Exception:
                    pass
            if results:
                break
        return results

    # â”€â”€ Amcache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def amcache(self) -> List[dict]:
        results = []
        reg = self._reg("Amcache")
        if not reg:
            return results
        for root_path in ["Root\\InventoryApplicationFile", "Root\\File"]:
            key = safe_key(reg, root_path)
            if not key:
                continue
            for app in safe_subkeys(key):
                info = {"name": app.name()[:80], "full_path": "", "sha1": "",
                        "link_date": "", "size": ""}
                for v in safe_values(app):
                    n = v.name()
                    if n == "FullPath":     info["full_path"] = val_str(v)
                    elif n == "FileId":     info["sha1"] = val_str(v).lstrip("0000")[:40]
                    elif n == "LinkDate":   info["link_date"] = val_str(v)
                    elif n == "FileSize":   info["size"] = val_str(v)
                    elif n == "LowerCaseLongPath": info["full_path"] = info["full_path"] or val_str(v)
                results.append(info)
            if results:
                break
        return results

    # â”€â”€ User Activity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def runmru(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
        if not key:
            return results
        mru_order = val_for(key, "MRUList", "")
        order_map = {c: i for i, c in enumerate(mru_order)}
        for v in safe_values(key):
            if v.name() != "MRUList":
                results.append({"order": order_map.get(v.name(), 99), "key": v.name(), "command": val_str(v)})
        return sorted(results, key=lambda x: x["order"])

    def typed_paths(self, user: str) -> List[str]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
        if not key:
            return results
        for v in safe_values(key):
            results.append(val_str(v))
        return results

    def recent_docs(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
        if not key:
            return results
        for sub in safe_subkeys(key):
            for v in safe_values(sub):
                try:
                    raw = v.value()
                    if isinstance(raw, bytes) and len(raw) > 2:
                        text = raw.decode("utf-16-le", errors="ignore").rstrip("\x00").split("\x00")[0]
                        if text and len(text) > 1:
                            results.append({"extension": sub.name(), "filename": text})
                except Exception:
                    pass
        return results

    def last_visited_mru(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU")
        if not key:
            return results
        for v in safe_values(key):
            if v.name() == "MRUListEx":
                continue
            try:
                raw = v.value()
                if isinstance(raw, bytes):
                    text = raw.decode("utf-16-le", errors="ignore").rstrip("\x00").split("\x00")[0]
                    if text and len(text) > 1:
                        results.append({"entry": v.name(), "app_or_path": text})
            except Exception:
                pass
        return results

    def open_save_mru(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU")
        if not key:
            return results
        for ext_key in safe_subkeys(key):
            for v in safe_values(ext_key):
                if v.name() == "MRUListEx":
                    continue
                try:
                    raw = v.value()
                    if isinstance(raw, bytes) and len(raw) > 4:
                        text = raw.decode("utf-16-le", errors="ignore").rstrip("\x00").split("\x00")[0]
                        if text and len(text) > 1:
                            results.append({"extension": ext_key.name(), "path": text})
                except Exception:
                    pass
        return results

    def search_history(self, user: str) -> List[str]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery")
        if not key:
            return results
        for v in safe_values(key):
            if v.name() == "MRUListEx":
                continue
            try:
                raw = v.value()
                if isinstance(raw, bytes):
                    text = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
                    if text:
                        results.append(text)
            except Exception:
                pass
        return results

    def typed_urls(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Internet Explorer\\TypedURLs")
        if not key:
            return results
        for v in safe_values(key):
            results.append({"name": v.name(), "url": val_str(v)})
        return results

    def userassist(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
        if not key:
            return results
        for guid_key in safe_subkeys(key):
            count_key_path = f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{guid_key.name()}\\Count"
            count_key = safe_key(reg, count_key_path)
            if not count_key:
                continue
            for v in safe_values(count_key):
                name_enc = v.name()
                name_dec = rot13_decode(name_enc)
                run_count = ""
                last_run  = ""
                try:
                    raw = v.value()
                    if isinstance(raw, bytes) and len(raw) >= 16:
                        run_count = str(struct.unpack_from("<I", raw, 4)[0])
                        ft = struct.unpack_from("<Q", raw, 8)[0]
                        if ft > 0:
                            last_run = decode_filetime(ft)
                except Exception:
                    pass
                results.append({
                    "program": name_dec[:120],
                    "run_count": run_count,
                    "last_run": last_run,
                    "suspicious": "âš ï¸" if is_suspicious_svc_path(name_dec) else ""
                })
        return results

    def shellbags(self, user: str) -> List[dict]:
        results = []
        for hive_name, bag_path in [
            (f"NTUSER_{user}", "Software\\Microsoft\\Windows\\Shell\\BagMRU"),
            (f"USRCLASS_{user}", "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"),
        ]:
            reg = self._reg(hive_name)
            if not reg:
                continue
            key = safe_key(reg, bag_path)
            if key:
                count = len(safe_subkeys(key))
                results.append({
                    "hive": hive_name, "key": bag_path,
                    "subkey_count": count,
                    "note": "Folder browsing history â€” each entry = a folder the user opened"
                })
        return results

    def rdp_mru(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Terminal Server Client\\Default")
        if not key:
            return results
        for v in safe_values(key):
            results.append({"entry": v.name(), "server": val_str(v)})
        # Also check saved Servers
        skey = safe_key(reg, "Software\\Microsoft\\Terminal Server Client\\Servers")
        if skey:
            for srv in safe_subkeys(skey):
                uname = val_for(srv, "UsernameHint", "")
                results.append({"entry": "SavedServer", "server": srv.name(), "username_hint": uname})
        return results

    def mapped_drives(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Network")
        if not key:
            return results
        for drive in safe_subkeys(key):
            info = {"drive_letter": drive.name()}
            for v in safe_values(drive):
                info[v.name()] = val_str(v)
            results.append(info)
        return results

    def mount_points2(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
        if not key:
            return results
        for sub in safe_subkeys(key):
            results.append({"mount": sub.name(), "label": val_for(sub, "_LabelFromReg", "")})
        return results

    def ie_zone_map(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap")
        if not key:
            return results
        for v in safe_values(key):
            results.append({"setting": v.name(), "value": val_str(v)})
        domains_key = safe_key(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains")
        if domains_key:
            for domain in safe_subkeys(domains_key)[:20]:
                results.append({"domain": domain.name(), "note": "Custom zone assignment"})
        return results

    # â”€â”€ Firewall â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def firewall_status(self) -> List[dict]:
        results = []
        reg = self._reg("SYSTEM")
        if not reg:
            return results
        cs = self.current_control_set()
        for profile_name, path in [
            ("Domain",   f"{cs}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile"),
            ("Standard", f"{cs}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile"),
            ("Public",   f"{cs}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"),
        ]:
            key = safe_key(reg, path)
            if key:
                enabled = val_for(key, "EnableFirewall", "?")
                notifs  = val_for(key, "DisableNotifications", "?")
                results.append({
                    "profile": profile_name,
                    "firewall_enabled": "âœ… YES" if enabled == "1" else "âŒ DISABLED",
                    "notifications": "On" if notifs == "0" else "Disabled",
                })
        return results

    # â”€â”€ Shared Folders â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def shared_folders(self) -> List[dict]:
        results = []
        reg = self._reg("SYSTEM")
        if not reg:
            return results
        cs = self.current_control_set()
        key = safe_key(reg, f"{cs}\\Services\\LanmanServer\\Shares")
        if not key:
            return results
        for v in safe_values(key):
            results.append({"share_name": v.name(), "config": val_str(v)[:200]})
        return results

    # â”€â”€ DNS Cache (from registry â€” limited) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def dns_cache_registry(self) -> List[dict]:
        results = []
        reg = self._reg("SYSTEM")
        if not reg:
            return results
        cs = self.current_control_set()
        key = safe_key(reg, f"{cs}\\Services\\Dnscache\\Parameters")
        if key:
            for v in safe_values(key):
                results.append({"parameter": v.name(), "value": val_str(v)})
        return results

    # â”€â”€ Autoruns extra: SvcHost groups â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def svchost_groups(self) -> dict:
        reg = self._reg("SOFTWARE")
        if not reg:
            return {}
        key = safe_key(reg, "Microsoft\\Windows NT\\CurrentVersion\\Svchost")
        if not key:
            return {}
        return {v.name(): val_str(v) for v in safe_values(key)}

    # â”€â”€ CapabilityAccessManager (camera/mic/location privacy) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def capability_access(self) -> List[dict]:
        results = []
        reg = self._reg("SOFTWARE")
        if not reg:
            return results
        caps = ["webcam", "microphone", "location", "contacts", "calendar",
                "phoneCall", "userAccountInformation", "documents"]
        for cap in caps:
            key = safe_key(reg, f"Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\{cap}")
            if not key:
                continue
            for app_key in safe_subkeys(key):
                consent = val_for(app_key, "Value", "")
                results.append({
                    "capability": cap,
                    "app": app_key.name(),
                    "consent": consent
                })
        return results

    # â”€â”€ Browser Data â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def chrome_prefs_reg(self, user: str) -> List[dict]:
        results = []
        reg = self._reg(f"NTUSER_{user}")
        if not reg:
            return results
        key = safe_key(reg, "Software\\Google\\Chrome\\PreferenceMACs")
        if key:
            results.append({"note": "Chrome profile data present in registry", "subkeys": str(len(safe_subkeys(key)))})
        key2 = safe_key(reg, "Software\\Microsoft\\Edge\\PreferenceMACs")
        if key2:
            results.append({"note": "Edge profile data present in registry", "subkeys": str(len(safe_subkeys(key2)))})
        return results

    # â”€â”€ ZeroTier / VPN indicators â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def vpn_indicators(self) -> List[dict]:
        results = []
        reg = self._reg("SOFTWARE")
        if not reg:
            return results
        vpn_keys = [
            ("ZeroTier", "ZeroTier Networks", "ZeroTier found â€” peer-to-peer VPN software"),
            ("OpenVPN",  "OpenVPN Technologies", "OpenVPN found"),
            ("WireGuard","WireGuard LLC", "WireGuard found"),
            ("ProtonVPN","Proton Technologies", "ProtonVPN found"),
            ("NordVPN",  "NordVPN", "NordVPN found"),
        ]
        for name, publisher_hint, note in vpn_keys:
            key = safe_key(reg, f"Microsoft\\Windows\\CurrentVersion\\Uninstall\\{name}")
            if key:
                results.append({"software": name, "note": note, "registry_key": f"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{name}"})
        # Also check from services
        reg2 = self._reg("SYSTEM")
        if reg2:
            for cs in ["ControlSet001", "CurrentControlSet"]:
                for svc_name in ["ZeroTierOneService", "OpenVPNService", "WireGuardTunnel", "tapoas", "tap0901"]:
                    if safe_key(reg2, f"{cs}\\Services\\{svc_name}"):
                        results.append({"software": svc_name, "note": f"VPN/Tunnel service detected: {svc_name}"})
        return results

    # ── SECURITY Hive Extractors ───────────────────────────────────────────────
    def security_policy(self) -> List[dict]:
        """Extract security policy settings from the SECURITY hive."""
        results = []
        reg = self._reg("SECURITY")
        if not reg:
            return results
        # Policy\PolAdtEv — audit event settings
        key = safe_key(reg, "Policy\\PolAdtEv")
        if key:
            for v in safe_values(key):
                results.append({"category": "Audit Policy", "name": v.name(), "value": val_str(v)[:200]})
        # Policy\PolPrDmN — primary domain name
        key = safe_key(reg, "Policy\\PolPrDmN")
        if key:
            for v in safe_values(key):
                results.append({"category": "Primary Domain", "name": v.name(), "value": val_str(v)[:200]})
        # Policy\PolPrDmS — primary domain SID
        key = safe_key(reg, "Policy\\PolPrDmS")
        if key:
            for v in safe_values(key):
                results.append({"category": "Primary Domain SID", "name": v.name(), "value": val_str(v)[:200]})
        # Policy\PolAcDmN — account domain name
        key = safe_key(reg, "Policy\\PolAcDmN")
        if key:
            for v in safe_values(key):
                results.append({"category": "Account Domain", "name": v.name(), "value": val_str(v)[:200]})
        # Policy\Accounts — LSA account references
        key = safe_key(reg, "Policy\\Accounts")
        if key:
            for sub in safe_subkeys(key):
                results.append({"category": "LSA Account", "name": sub.name(), "value": str(sub.timestamp())})
        # Policy\Secrets — list cached secret names (NOT values — those are encrypted)
        key = safe_key(reg, "Policy\\Secrets")
        if key:
            for sub in safe_subkeys(key):
                results.append({"category": "LSA Secret Name", "name": sub.name(), "value": "(encrypted blob)"})
        # Policy\PolRevision
        key = safe_key(reg, "Policy\\PolRevision")
        if key:
            for v in safe_values(key):
                results.append({"category": "Policy Revision", "name": v.name(), "value": val_str(v)[:200]})
        return results


# â”€â”€â”€ LLM ANALYST â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class LLMAnalyst:
    def __init__(self):
        self.base = OLLAMA_URL
        self.model = OLLAMA_MODEL
        self._check_connection()

    def _check_connection(self):
        global OLLAMA_MODEL
        try:
            r = requests.get(f"{self.base}/api/tags", timeout=5)
            if r.ok:
                models = [m["name"] for m in r.json().get("models", [])]
                if models:
                    log.info(f"  Ollama models available: {models}")
                    if OLLAMA_MODEL not in models:
                        fallback = models[0]
                        log.warning(f"  Model '{OLLAMA_MODEL}' not found, using: {fallback}")
                        OLLAMA_MODEL = fallback
                        self.model = fallback
                else:
                    log.warning("  No Ollama models found â€” LLM analysis will be skipped")
            else:
                log.warning("  Ollama unreachable â€” LLM analysis disabled")
        except Exception as e:
            log.warning(f"  Ollama check failed: {e}")

    def ask(self, system_prompt: str, user_prompt: str, max_tokens: int = 800) -> str:
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.1,
                "top_p": 0.9,
            }
        }
        try:
            r = requests.post(
                f"{self.base}/api/generate",
                json=payload,
                timeout=OLLAMA_TIMEOUT
            )
            if r.ok:
                return r.json().get("response", "").strip()
            else:
                log.warning(f"  LLM HTTP {r.status_code}: {r.text[:100]}")
                return ""
        except Exception as e:
            log.warning(f"  LLM call failed: {e}")
            return ""

    def analyze_artifact(self, artifact_name: str, data: Any) -> dict:
        if not data:
            return {"summary": "No data available.", "findings": [], "iocs": []}

        SYSTEM = """You are a senior Windows digital forensics analyst. 
Your job is to analyze Windows registry artifacts and identify:
1. Genuinely suspicious or anomalous entries
2. Indicators of compromise (IOCs)
3. Evidence of attacker techniques (persistence, lateral movement, data exfiltration, etc.)
4. Unusual configurations vs. normal Windows behavior

IMPORTANT RULES:
- Only flag genuine anomalies. Do NOT flag standard Windows paths, Microsoft-signed apps, or common software.
- Assign severity: CRITICAL (active attack/rootkit), HIGH (strong IOC), MEDIUM (suspicious but possible legit), LOW (worth noting), INFO (normal).
- If everything is normal, say so clearly. Never generate false positives.
- Be specific â€” cite exact values, paths, or names from the data.
- Output must be valid JSON only. No markdown. No explanation outside JSON."""

        data_str = json.dumps(data, indent=2, default=str)
        if len(data_str) > 6000:
            data_str = data_str[:6000] + "\n...(truncated)"

        USER = f"""Analyze this Windows registry artifact: {artifact_name}

DATA:
{data_str}

Return JSON in this exact format:
{{
  "summary": "1-2 sentence overview of what this artifact shows",
  "findings": [
    {{
      "severity": "HIGH",
      "title": "Short title",
      "detail": "Specific detail with exact values from the data",
      "ioc": "specific IOC value or empty string"
    }}
  ],
  "iocs": ["list", "of", "raw", "ioc", "strings"],
  "risk_score": 0
}}

risk_score: 0-100 integer (0=clean, 100=definitely compromised)
Only include findings with severity MEDIUM or above unless something is clearly notable."""

        response = self.ask(SYSTEM, USER, max_tokens=1200)
        if not response:
            return {"summary": "LLM unavailable.", "findings": [], "iocs": [], "risk_score": 0}

        # Extract JSON from response
        try:
            # Try direct parse
            return json.loads(response)
        except Exception:
            # Try to extract JSON block
            match = re.search(r'\{[\s\S]*\}', response)
            if match:
                try:
                    return json.loads(match.group())
                except Exception:
                    pass
        log.debug(f"  LLM JSON parse failed for {artifact_name}: {response[:200]}")
        return {"summary": response[:300], "findings": [], "iocs": [], "risk_score": 0}

    def generate_executive_summary(self, all_findings: List[dict], system_info: dict) -> str:
        computer = system_info.get("ComputerName", "Unknown")
        os_name  = system_info.get("ProductName", "Windows")
        counts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in all_findings:
            sev = f.get("severity", "").upper()
            if sev in counts:
                counts[sev] += 1

        SYSTEM = """You are a senior forensic analyst writing an executive summary for a legal/investigative report.
Be factual, professional, and clear. Base your summary ONLY on the provided findings data."""

        USER = f"""Computer: {computer} | OS: {os_name}
Finding counts â€” CRITICAL: {counts['CRITICAL']}, HIGH: {counts['HIGH']}, MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']}

Top findings:
{json.dumps(all_findings[:30], indent=2, default=str)[:4000]}

Write a 3-4 paragraph executive summary for a forensic report covering:
1. Overall risk level and assessment
2. Key findings (be specific with values/paths/names from the data)
3. Recommended immediate actions

Plain text only. No JSON. No markdown."""

        return self.ask(SYSTEM, USER, max_tokens=600) or "Executive summary unavailable (LLM not reachable)."


# â”€â”€â”€ HIVE DISCOVERY â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def copy_locked_hive(src: Path, tmp_dir: Path, dest_name: str = None) -> Optional[Path]:
    """
    Copy a registry hive from a mounted forensic image to a temp dir.
    dest_name: unique destination filename (fixes P0 multi-user collision).
    Uses 4 strategies in order:
      1. Win32 CreateFile with FILE_FLAG_BACKUP_SEMANTICS (bypasses ACL/lock)
      2. shutil.copy2 (works when file is not OS-locked)
      3. Raw open() read in chunks
      4. reg.exe SAVE (only for live HKLM hives, needs SeBackupPrivilege)
    """
    import platform
    dst = tmp_dir / (dest_name or src.name)
    if dst.exists() and dst.stat().st_size > 4096:
        return dst

    # â”€â”€ Strategy 1: Win32 CreateFile with BACKUP_SEMANTICS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # This is the CORRECT way to copy locked/ACL-protected files on Windows.
    # FILE_FLAG_BACKUP_SEMANTICS (0x02000000) + GENERIC_READ bypasses both
    # sharing violations and ACL denials when the process has SeBackupPrivilege.
    if platform.system() == "Windows":
        try:
            import ctypes, ctypes.wintypes as wt
            kernel32 = ctypes.windll.kernel32

            GENERIC_READ            = 0x80000000
            FILE_SHARE_READ         = 0x00000001
            FILE_SHARE_WRITE        = 0x00000002
            FILE_SHARE_DELETE       = 0x00000004
            OPEN_EXISTING           = 3
            FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
            FILE_FLAG_SEQUENTIAL_SCAN  = 0x08000000
            INVALID_HANDLE_VALUE    = ctypes.c_void_p(-1).value

            h = kernel32.CreateFileW(
                str(src),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
                None
            )
            if h != INVALID_HANDLE_VALUE and h is not None:
                CHUNK = 1024 * 1024  # 1 MB chunks
                buf   = ctypes.create_string_buffer(CHUNK)
                read  = wt.DWORD(0)
                total = 0
                with open(dst, "wb") as out_f:
                    while True:
                        ok = kernel32.ReadFile(h, buf, CHUNK, ctypes.byref(read), None)
                        if not ok or read.value == 0:
                            break
                        out_f.write(buf.raw[:read.value])
                        total += read.value
                kernel32.CloseHandle(h)
                if total > 4096:
                    log.info(f"    âœ“ Win32 copy: {src.name} ({total:,} bytes)")
                    return dst
                else:
                    log.debug(f"    Win32 copy too small ({total} bytes): {src.name}")
                    if dst.exists():
                        dst.unlink()
            else:
                err = kernel32.GetLastError()
                log.debug(f"    Win32 CreateFile failed ({src.name}): error {err}")
        except Exception as e:
            log.debug(f"    Win32 strategy failed ({src.name}): {e}")

    # â”€â”€ Strategy 2: shutil.copy2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        shutil.copy2(str(src), str(dst))
        size = dst.stat().st_size if dst.exists() else 0
        if size > 4096:
            log.info(f"    âœ“ shutil copy: {src.name} ({size:,} bytes)")
            return dst
        if dst.exists():
            dst.unlink()
    except PermissionError:
        pass
    except Exception as e:
        log.debug(f"    shutil copy failed ({src.name}): {e}")

    # â”€â”€ Strategy 3: Raw chunked read â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        with open(str(src), "rb") as fin, open(str(dst), "wb") as fout:
            total = 0
            while True:
                chunk = fin.read(1024 * 1024)
                if not chunk:
                    break
                fout.write(chunk)
                total += len(chunk)
        if total > 4096:
            log.info(f"    âœ“ Raw read: {src.name} ({total:,} bytes)")
            return dst
        if dst.exists():
            dst.unlink()
    except PermissionError:
        pass
    except Exception as e:
        log.debug(f"    Raw read failed ({src.name}): {e}")

    # â”€â”€ Strategy 4: reg.exe SAVE (live system hives only, needs admin) â”€â”€â”€
    if platform.system() == "Windows":
        hive_map = {
            "system":   "HKLM\\SYSTEM",
            "software": "HKLM\\SOFTWARE",
            "sam":      "HKLM\\SAM",
            "security": "HKLM\\SECURITY",
        }
        reg_hive = hive_map.get(src.name.lower())
        if reg_hive:
            try:
                import subprocess
                if dst.exists():
                    dst.unlink()
                result = subprocess.run(
                    ["reg", "save", reg_hive, str(dst), "/y"],
                    capture_output=True, timeout=30
                )
                if dst.exists() and dst.stat().st_size > 4096:
                    log.info(f"    âœ“ reg.exe SAVE: {src.name}")
                    return dst
                else:
                    log.warning(f"    reg.exe failed for {reg_hive}: {result.stderr.decode().strip()[:120]}")
            except Exception as e:
                log.debug(f"    reg.exe error ({src.name}): {e}")

    log.warning(f"    âœ— All copy strategies failed for: {src.name}")
    return None


def copy_log_companions(src: Path, dest_dir: Path, dest_base: str):
    """P1 fix: Copy .LOG1/.LOG2 transaction log companions alongside a hive."""
    for suffix in [".LOG1", ".LOG2", ".log1", ".log2"]:
        log_src = src.parent / (src.name + suffix)
        try:
            if log_src.exists() and log_src.stat().st_size > 0:
                log_dst = dest_dir / (dest_base + suffix.upper())
                shutil.copy2(str(log_src), str(log_dst))
                log.info(f"    âœ“ Log companion: {log_dst.name} ({log_dst.stat().st_size:,} bytes)")
        except (PermissionError, OSError) as e:
            log.debug(f"    Log companion copy failed for {log_src}: {e}")


# Global dict to track source paths for manifest
_hive_source_paths: Dict[str, str] = {}


def find_hives(root: Path) -> dict:
    hives = {}
    import tempfile, platform
    log.info(f"[HIVE DISCOVERY] Scanning {root}")

    # Create temp dir for copied hives (needed on Windows where files may be locked)
    tmp_dir = Path(tempfile.mkdtemp(prefix="reg_forensic_"))
    log.info(f"  Temp hive staging dir: {tmp_dir}")

    def probe(candidates, label):
        for c in candidates:
            p = root / c
            # Use try/except to handle Windows permission errors on locked files
            try:
                accessible = p.exists()
            except (PermissionError, OSError):
                accessible = False
            if not accessible:
                continue
            try:
                size = p.stat().st_size
            except (PermissionError, OSError):
                # File exists but stat is denied â€” try to copy it anyway
                size = -1
            if size == 0:
                continue
            # Try to copy it to temp location to break file lock
            copied = copy_locked_hive(p, tmp_dir)
            if copied:
                log.info(f"  âœ“ {label}: {copied} (source: {p})")
                return copied
            else:
                log.warning(f"  âœ— {label}: could not copy {p} â€” skipping")
                return None
        return None

    # System hives
    hive_map = {
        "SYSTEM":   ["Windows/System32/config/SYSTEM",   "system32/config/SYSTEM",   "SYSTEM"],
        "SOFTWARE": ["Windows/System32/config/SOFTWARE", "system32/config/SOFTWARE", "SOFTWARE"],
        "SAM":      ["Windows/System32/config/SAM",      "system32/config/SAM",      "SAM"],
        "SECURITY": ["Windows/System32/config/SECURITY", "system32/config/SECURITY", "SECURITY"],
        "DEFAULT":  ["Windows/System32/config/DEFAULT",  "system32/config/DEFAULT",  "DEFAULT"],
    }
    for label, candidates in hive_map.items():
        p = probe(candidates, label)
        if p:
            hives[label] = p

    # Amcache
    for amc in ["Windows/appcompat/Programs/Amcache.hve", "appcompat/Programs/Amcache.hve"]:
        p = root / amc
        try:
            exists = p.exists()
        except (PermissionError, OSError):
            exists = False
        if exists:
            copied = copy_locked_hive(p, tmp_dir)
            if copied:
                hives["Amcache"] = copied
                log.info(f"  âœ“ Amcache: {copied}")
            else:
                log.warning(f"  âœ— Amcache: inaccessible, skipping")
            break

    # User hives
    users_dirs = []
    for users_root in ["Users", "Documents and Settings"]:
        ur = root / users_root
        try:
            if not ur.exists():
                continue
        except (PermissionError, OSError):
            continue
        raw_entries = []
        try:
            raw_entries = list(ur.iterdir())
        except (PermissionError, OSError) as e:
            log.warning(f"  Cannot list {ur}: {e}")
            continue
        for entry in raw_entries:
            try:
                if entry.is_dir():
                    users_dirs.append(entry)
            except (PermissionError, OSError, Exception):
                # Corrupted junctions, reparse points, or locked dirs â€” skip silently
                pass
        if users_dirs:
            break

    def safe_exists(p: Path) -> bool:
        try:
            return p.exists()
        except (PermissionError, OSError):
            return False

    def safe_size(p: Path) -> int:
        try:
            return p.stat().st_size
        except (PermissionError, OSError):
            return -1

    skip_users = {"public", "default", "default user", "all users", "defaultapppool", "classic .net apppool"}
    for user_dir in users_dirs:
        if user_dir.name.lower() in skip_users:
            continue
        user = user_dir.name
        for ntuser_name in ["NTUSER.DAT", "ntuser.dat"]:
            p = user_dir / ntuser_name
            if safe_exists(p) and safe_size(p) > 4096:
                # P0 fix: unique dest_name per user prevents collision
                dest_name = f"NTUSER_{user}.DAT"
                copied = copy_locked_hive(p, tmp_dir, dest_name=dest_name)
                if copied:
                    hives[f"NTUSER_{user}"] = copied
                    _hive_source_paths[f"NTUSER_{user}"] = str(p)
                    log.info(f"  âœ“ NTUSER_{user}: {copied}")
                else:
                    log.warning(f"  âœ— NTUSER_{user}: inaccessible, skipping")
                break
        for usrclass_path in [
            user_dir / "AppData/Local/Microsoft/Windows/UsrClass.dat",
            user_dir / "Local Settings/Application Data/Microsoft/Windows/UsrClass.dat",
        ]:
            if safe_exists(usrclass_path) and safe_size(usrclass_path) > 4096:
                # P0 fix: unique dest_name per user prevents collision
                dest_name = f"USRCLASS_{user}.dat"
                copied = copy_locked_hive(usrclass_path, tmp_dir, dest_name=dest_name)
                if copied:
                    hives[f"USRCLASS_{user}"] = copied
                    _hive_source_paths[f"USRCLASS_{user}"] = str(usrclass_path)
                    log.info(f"  âœ“ USRCLASS_{user}: {copied}")
                else:
                    log.warning(f"  âœ— USRCLASS_{user}: inaccessible, skipping")
                break

    if not hives:
        log.error("  No hives found under that path. Check the --mounted argument.")
    else:
        log.info(f"  Total hives found: {len(hives)}")
    return hives


def open_hives(hive_paths: dict) -> dict:
    opened = {}
    for name, path in hive_paths.items():
        r = safe_open(path)
        if r:
            opened[name] = r
    return opened


# Registry value type names for JSONL records
REG_TYPE_NAMES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK",
    7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
}


# --- P0 FIX: FULL RECURSIVE REGISTRY PARSER (root-to-leaf walk) ---
class FullRegistryParser:
    """Recursively parse every key/value in a hive to JSONL for forensic-complete export.
    P2 fix: Each record includes both decoded_value AND raw_hex/raw_base64."""

    def __init__(self, hive_name: str, source_path: str = "", user: str = None):
        self.hive_name = hive_name
        self.source_path = source_path
        self.user = user

    def _decode_value(self, v) -> dict:
        """Decode a single registry value to a forensic record dict."""
        try:
            vtype = v.value_type()
            type_name = REG_TYPE_NAMES.get(vtype, f"UNKNOWN({vtype})")
            name = v.name() or "(Default)"
            try:
                raw = v.value()
            except Exception:
                return {"value_name": name, "value_type": type_name, "value_type_id": vtype,
                        "decoded_value": "(error reading value)", "raw_hex": None, "raw_base64": None}

            raw_hex = None
            raw_b64 = None
            decoded = None

            if isinstance(raw, bytes):
                raw_hex = raw.hex() if len(raw) <= 8192 else raw[:8192].hex() + f"...(truncated, {len(raw)} total)"
                raw_b64 = base64.b64encode(raw[:8192]).decode("ascii") if len(raw) <= 8192 else None

            if vtype in (1, 2, 6):  # REG_SZ, REG_EXPAND_SZ, REG_LINK
                decoded = raw.decode("utf-16-le", errors="ignore").rstrip("\x00") if isinstance(raw, bytes) else str(raw or "")
            elif vtype == 3:  # REG_BINARY
                decoded = raw.hex() if isinstance(raw, bytes) and len(raw) <= 4096 else f"(binary, {len(raw)} bytes)" if isinstance(raw, bytes) else str(raw)
            elif vtype in (4, 5):  # REG_DWORD
                decoded = int(raw) if isinstance(raw, int) else str(raw)
            elif vtype == 7:  # REG_MULTI_SZ
                if isinstance(raw, list):
                    decoded = raw
                elif isinstance(raw, bytes):
                    decoded = raw.decode("utf-16-le", errors="ignore").rstrip("\x00").split("\x00")
                else:
                    decoded = [str(raw)] if raw else []
            elif vtype == 11:  # REG_QWORD
                decoded = int(raw) if isinstance(raw, int) else str(raw)
            else:
                decoded = raw.hex() if isinstance(raw, bytes) else str(raw or "")

            return {"value_name": name, "value_type": type_name, "value_type_id": vtype,
                    "decoded_value": decoded, "raw_hex": raw_hex, "raw_base64": raw_b64}
        except Exception as e:
            return {"value_name": "(error)", "value_type": "ERROR", "value_type_id": -1,
                    "decoded_value": str(e), "raw_hex": None, "raw_base64": None}

    def _walk_key_jsonl(self, key, path_prefix: str = ""):
        """Generator: yield one JSONL dict per key, recursing all children."""
        try:
            key_path = f"{path_prefix}\\{key.name()}" if path_prefix else key.name()
        except Exception:
            key_path = path_prefix or "ROOT"

        last_write = ""
        try:
            last_write = str(key.timestamp())
        except Exception:
            pass

        values = []
        for v in safe_values(key):
            values.append(self._decode_value(v))

        yield {
            "hive": self.hive_name,
            "source_path": self.source_path,
            "user": self.user,
            "key_path": key_path,
            "last_write": last_write,
            "values": values,
            "subkey_count": len(safe_subkeys(key)),
        }

        for subkey in safe_subkeys(key):
            yield from self._walk_key_jsonl(subkey, key_path)

    def parse_to_jsonl(self, reg, output_path: Path) -> dict:
        """Stream-write every key in a hive to a JSONL file. Returns stats."""
        stats = {"hive": self.hive_name, "total_keys": 0, "total_values": 0, "errors": 0}
        start = time.time()

        try:
            root = reg.root()
        except Exception as e:
            log.error(f"    Cannot access root of {self.hive_name}: {e}")
            stats["errors"] = 1
            output_path.write_text("")
            return stats

        log.info(f"    Parsing {self.hive_name} -> {output_path.name} (JSONL)...")
        with open(output_path, 'w', encoding='utf-8') as f:
            for record in self._walk_key_jsonl(root):
                stats["total_keys"] += 1
                stats["total_values"] += len(record.get("values", []))
                try:
                    f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                except Exception:
                    f.write(json.dumps({"key_path": record.get("key_path", "?"), "error": "serialization failed"}) + "\n")
                    stats["errors"] += 1
                if stats["total_keys"] % 50000 == 0:
                    elapsed = time.time() - start
                    rate = stats["total_keys"] / elapsed if elapsed > 0 else 0
                    log.info(f"      {self.hive_name}: {stats['total_keys']:,} keys ({rate:.0f} keys/sec)")

        elapsed = time.time() - start
        stats["elapsed_seconds"] = round(elapsed, 2)
        fsize = output_path.stat().st_size
        stats["file_size_mb"] = round(fsize / (1024 * 1024), 2)
        log.info(f"    Done: {self.hive_name}: {stats['total_keys']:,} keys, "
                 f"{stats['total_values']:,} values, {stats['file_size_mb']} MB, {stats['elapsed_seconds']}s")
        return stats

# â”€â”€â”€ REPORT BUILDER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def build_report(artifacts: dict, executive_summary: str, all_findings: List[dict],
                 output_dir: Path, users: List[str], system_info: dict) -> Path:

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    all_iocs = []
    for f in all_findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1
        ioc = f.get("ioc", "")
        if ioc and ioc not in all_iocs:
            all_iocs.append(ioc)

    computer = system_info.get("ComputerName", "Unknown")
    os_name  = system_info.get("os_info", {}).get("ProductName", "Windows")
    build    = system_info.get("os_info", {}).get("CurrentBuildNumber", "")
    reg_user = system_info.get("os_info", {}).get("RegisteredOwner", "") or system_info.get("os_info", {}).get("RegisteredOwner", "")
    timezone = system_info.get("timezone", {}).get("TimeZoneKeyName", "")
    install_date = system_info.get("os_info", {}).get("InstallDate_decoded", "")
    last_shutdown = system_info.get("last_shutdown", "")
    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    SEV_COLOR = {
        "CRITICAL": "#e74c3c", "HIGH": "#e67e22",
        "MEDIUM":   "#f1c40f", "LOW": "#2ecc71", "INFO": "#3498db"
    }
    SEV_BG = {
        "CRITICAL": "#c0392b22", "HIGH": "#e67e2222",
        "MEDIUM":   "#f39c1222", "LOW": "#27ae6022", "INFO": "#2980b922"
    }

    def sev_badge(sev):
        sev = (sev or "INFO").upper()
        c = SEV_COLOR.get(sev, "#888")
        return f'<span class="badge" style="color:{c};border-color:{c}">{sev}</span>'

    def table(headers, rows, max_rows=MAX_HTML_ROWS):
        if not rows:
            return '<p class="no-data">No data found</p>'
        out = ['<div class="tbl-wrap"><table><thead><tr>']
        for h in headers:
            out.append(f"<th>{html_mod.escape(str(h))}</th>")
        out.append("</tr></thead><tbody>")
        for row in rows[:max_rows]:
            out.append("<tr>")
            for cell in row:
                val = str(cell) if cell is not None else ""
                # Cells that are already HTML markup (sev_badge etc.) -- pass through
                if val.startswith("<"):
                    out.append(f"<td>{val}</td>")
                    continue
                escaped = html_mod.escape(val)
                # Flag cells by emoji prefix
                if val.startswith("⚠"):
                    out.append(f'<td class="flag">{escaped}</td>')
                elif val.startswith("❌"):
                    out.append(f'<td class="danger">{escaped}</td>')
                elif val.startswith("✅"):
                    out.append(f'<td class="ok">{escaped}</td>')
                else:
                    out.append(f"<td>{escaped}</td>")
            out.append("</tr>")
        out.append("</tbody></table></div>")
        if len(rows) > max_rows:
            out.append(f'<p class="note">Showing first {max_rows} of {len(rows)} rows</p>')
        return "".join(out)

    def section(title, content_html, count=None, default_open=False):
        cnt = f' <span class="sec-count">{count}</span>' if count is not None else ""
        opened = ' open' if default_open else ''
        return f"""
<details class="section"{opened}>
  <summary><span class="sec-title">{title}{cnt}</span><span class="sec-arrow">â–¸</span></summary>
  <div class="sec-body">{content_html}</div>
</details>"""

    def findings_table(findings: list):
        if not findings:
            return '<p class="no-data">No findings for this artifact</p>'
        rows = [[sev_badge(f.get("severity","INFO")), f.get("title",""), f.get("detail",""), f.get("ioc","")] for f in findings]
        return table(["Severity", "Title", "Detail", "IOC"], rows)

    def llm_summary_box(analysis: dict):
        summary = analysis.get("summary", "")
        score = analysis.get("risk_score", 0)
        if not summary:
            return ""
        color = "#2ecc71" if score < 20 else "#f39c12" if score < 60 else "#e74c3c"
        return f'<div class="llm-box"><span class="risk-score" style="color:{color}">Risk: {score}/100</span> {summary}</div>'

    # â”€â”€ BUILD HTML â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts = []

    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Windows Registry Forensic Report â€” {computer}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0d1117;--surface:#161b22;--surface2:#1f2937;--surface3:#252b3b;
  --border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --critical:#ff4444;--high:#ff8800;--medium:#ffcc00;--low:#33cc66;--info:#4488ff;
}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.6}}
a{{color:var(--accent);text-decoration:none}}
/* HEADER */
.header{{background:linear-gradient(135deg,#0d1b2a,#1a1f35);border-bottom:2px solid var(--accent);padding:28px 40px;position:sticky;top:0;z-index:100}}
.header h1{{color:var(--accent);font-size:1.6em;letter-spacing:3px;text-transform:uppercase}}
.header .meta{{color:var(--muted);font-size:0.82em;margin-top:6px}}
/* LAYOUT */
.layout{{display:grid;grid-template-columns:260px 1fr;min-height:calc(100vh - 85px)}}
/* SIDEBAR */
.sidebar{{background:var(--surface);border-right:1px solid var(--border);padding:20px 0;position:sticky;top:85px;height:calc(100vh - 85px);overflow-y:auto}}
.sidebar-title{{color:var(--muted);font-size:0.7em;text-transform:uppercase;letter-spacing:2px;padding:8px 20px 4px}}
.sidebar a{{display:block;padding:7px 20px;color:var(--muted);font-size:0.82em;border-left:3px solid transparent;transition:all .15s}}
.sidebar a:hover,.sidebar a.active{{color:var(--text);background:var(--surface2);border-left-color:var(--accent)}}
/* MAIN */
.main{{padding:30px 40px;max-width:1300px}}
/* STATS */
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:28px}}
.stat-card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px;text-align:center;border-top:3px solid}}
.stat-card.c{{border-color:var(--critical)}} .stat-card.h{{border-color:var(--high)}}
.stat-card.m{{border-color:var(--medium)}} .stat-card.l{{border-color:var(--low)}}
.stat-card.i{{border-color:var(--info)}}
.stat-card .num{{font-size:2.2em;font-weight:700}}
.stat-card .lbl{{font-size:0.75em;color:var(--muted);text-transform:uppercase;margin-top:4px}}
.stat-card.c .num{{color:var(--critical)}} .stat-card.h .num{{color:var(--high)}}
.stat-card.m .num{{color:var(--medium)}} .stat-card.l .num{{color:var(--low)}}
.stat-card.i .num{{color:var(--info)}}
/* SYSINFO GRID */
.sysinfo{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;margin-bottom:20px}}
.si-item{{background:var(--surface2);border-radius:8px;padding:12px 16px}}
.si-key{{font-size:0.72em;color:var(--muted);text-transform:uppercase;letter-spacing:1px}}
.si-val{{color:var(--text);margin-top:3px;word-break:break-all}}
/* SECTIONS */
.section{{margin-bottom:14px}}
details.section{{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}}
details.section>summary{{cursor:pointer;padding:14px 20px;display:flex;align-items:center;justify-content:space-between;list-style:none;user-select:none;background:var(--surface2)}}
details.section>summary::-webkit-details-marker{{display:none}}
details[open]>summary .sec-arrow{{transform:rotate(90deg)}}
.sec-title{{font-size:0.88em;text-transform:uppercase;letter-spacing:1px;color:var(--accent);font-weight:600}}
.sec-count{{background:var(--border);color:var(--muted);border-radius:20px;padding:1px 9px;font-size:0.75em;margin-left:8px}}
.sec-arrow{{color:var(--muted);transition:transform .2s;font-size:0.8em}}
.sec-body{{padding:20px}}
/* TABLES */
.tbl-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:0.82em}}
th{{background:var(--surface3);color:var(--accent);padding:9px 12px;text-align:left;border-bottom:1px solid var(--border);position:sticky;top:0}}
td{{padding:7px 12px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-all}}
tr:hover td{{background:var(--surface2)}}
td.flag{{color:#ffcc00;font-weight:600}}
td.danger{{color:#ff4444;font-weight:600}}
td.ok{{color:#33cc66}}
.badge{{border:1px solid;border-radius:20px;padding:2px 9px;font-size:0.75em;font-weight:700}}
/* LLM BOX */
.llm-box{{background:#0d1420;border-left:3px solid var(--accent);border-radius:0 6px 6px 0;padding:10px 16px;margin-bottom:16px;font-style:italic;color:var(--muted);font-size:0.84em}}
.risk-score{{font-weight:700;font-style:normal;margin-right:8px}}
/* IOC LIST */
.ioc-list{{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}}
.ioc-tag{{background:#c0392b22;border:1px solid var(--critical);color:#ff6b6b;padding:3px 10px;border-radius:20px;font-family:monospace;font-size:0.78em}}
/* EXEC SUMMARY */
.exec-summary{{background:var(--surface);border:1px solid var(--accent);border-radius:10px;padding:24px;margin-bottom:24px;white-space:pre-wrap;font-size:0.88em;line-height:1.8}}
/* NO DATA */
.no-data{{color:var(--muted);font-style:italic;padding:12px 0}}
.note{{color:var(--muted);font-size:0.78em;padding:6px 0;font-style:italic}}
/* USER TABS */
.tabs{{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:20px;border-bottom:1px solid var(--border);padding-bottom:12px}}
.tab-btn{{background:var(--surface2);border:1px solid var(--border);color:var(--muted);padding:6px 16px;border-radius:6px;cursor:pointer;font-size:0.82em;transition:all .15s}}
.tab-btn.active{{background:var(--accent);color:#000;border-color:var(--accent)}}
.tab-panel{{display:none}} .tab-panel.active{{display:block}}
/* SEARCH */
.search-bar{{width:100%;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:10px 16px;border-radius:8px;font-size:0.9em;margin-bottom:20px;outline:none}}
.search-bar:focus{{border-color:var(--accent)}}
/* TIMELINE */
.timeline{{position:relative;padding-left:24px}}
.timeline::before{{content:'';position:absolute;left:8px;top:0;bottom:0;width:2px;background:var(--border)}}
.tl-item{{position:relative;margin-bottom:14px;padding:10px 14px;background:var(--surface2);border-radius:8px;border-left:3px solid var(--accent)}}
.tl-item.critical{{border-left-color:var(--critical)}} .tl-item.high{{border-left-color:var(--high)}}
.tl-item::before{{content:'';position:absolute;left:-20px;top:14px;width:10px;height:10px;border-radius:50%;background:var(--accent);border:2px solid var(--bg)}}
.tl-time{{font-size:0.75em;color:var(--muted)}} .tl-title{{font-weight:600;color:var(--text)}}
.tl-detail{{font-size:0.82em;color:var(--muted);margin-top:3px}}
/* PRINT */
@media print{{.sidebar,.header{{display:none}}.main{{padding:10px}}.layout{{display:block}}details.section{{break-inside:avoid}}}}
@media(max-width:768px){{.layout{{grid-template-columns:1fr}}.sidebar{{display:none}}.stats{{grid-template-columns:repeat(3,1fr)}}}}
</style>
</head>
<body>
<div class="header">
  <h1>ðŸ” Windows Registry Forensic Report</h1>
  <div class="meta">
    Generated: {generated_at} &nbsp;|&nbsp;
    Computer: <strong>{computer}</strong> &nbsp;|&nbsp;
    OS: {os_name} (Build {build}) &nbsp;|&nbsp;
    Registered User: {reg_user} &nbsp;|&nbsp;
    Timezone: {timezone} &nbsp;|&nbsp;
    Users Analyzed: {', '.join(users) or 'None'}
  </div>
</div>
<div class="layout">
""")

    # â”€â”€ SIDEBAR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    nav_links = [
        ("stats",           "ðŸ“Š Stats & IOCs"),
        ("exec-summary",    "ðŸ“ Executive Summary"),
        ("system-info",     "ðŸ’» System Information"),
        ("usb-devices",     "ðŸ”Œ USB Devices"),
        ("persistence",     "ðŸš€ Persistence / Autoruns"),
        ("services",        "âš™ï¸ Services"),
        ("network",         "ðŸŒ Network"),
        ("accounts",        "ðŸ‘¤ User Accounts"),
        ("execution",       "â–¶ï¸ Execution Artifacts"),
        ("user-activity",   "ðŸ‘ï¸ User Activity"),
        ("user-specific",   "ðŸ‘¥ Per-User Artifacts"),
        ("security",        "ðŸ›¡ï¸ Security Checks"),
        ("software",        "ðŸ“¦ Installed Software"),
        ("all-findings",    "âš ï¸ All Findings"),
    ]
    sidebar_html = ['<div class="sidebar">']
    sidebar_html.append('<div class="sidebar-title">Navigation</div>')
    for anchor, label in nav_links:
        sidebar_html.append(f'<a href="#{anchor}" onclick="scrollTo(\'{anchor}\')">{label}</a>')
    sidebar_html.append('</div>')
    html_parts.append("".join(sidebar_html))

    html_parts.append('<div class="main">')

    # Search bar
    html_parts.append('''<input class="search-bar" type="text" id="search-input" placeholder="ðŸ” Search findings, artifacts, IOCs..." oninput="filterContent(this.value)">''')

    # â”€â”€ STATS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="stats">')
    html_parts.append('<div class="stats">')
    for cls, label, key in [("c","CRITICAL","CRITICAL"),("h","HIGH","HIGH"),("m","MEDIUM","MEDIUM"),("l","LOW","LOW"),("i","INFO","INFO")]:
        html_parts.append(f'<div class="stat-card {cls}"><div class="num">{counts[key]}</div><div class="lbl">{label}</div></div>')
    html_parts.append('</div>')
    # IOC list
    if all_iocs:
        html_parts.append('<div class="ioc-list">')
        for ioc in all_iocs[:80]:
            html_parts.append(f'<span class="ioc-tag">{html_mod.escape(str(ioc))}</span>')
        html_parts.append('</div>')
    html_parts.append('</div>')

    # â”€â”€ EXECUTIVE SUMMARY â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append(f'<div id="exec-summary" class="exec-summary"><strong>ðŸ” EXECUTIVE SUMMARY</strong>\n\n{executive_summary}</div>')

    # â”€â”€ SYSTEM INFO â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="system-info">')
    osi  = system_info.get("os_info", {})
    tz   = system_info.get("timezone", {})
    si_items = [
        ("Computer Name", system_info.get("ComputerName","")),
        ("OS", osi.get("ProductName","")),
        ("Build Number", osi.get("CurrentBuildNumber","")),
        ("Build Lab", osi.get("BuildLab","")),
        ("Display Version", osi.get("DisplayVersion","")),
        ("Install Date", osi.get("InstallDate_decoded","")),
        ("Registered Owner", osi.get("RegisteredOwner","")),
        ("Last Shutdown", system_info.get("last_shutdown","")),
        ("Timezone", tz.get("TimeZoneKeyName","") or tz.get("StandardName","")),
        ("Edition", osi.get("EditionID","")),
        ("Architecture", osi.get("ProcessorArchitecture","")),
        ("Product ID", osi.get("ProductId","")),
    ]
    si_html = '<div class="sysinfo">'
    for k, v in si_items:
        if v:
            si_html += f'<div class="si-item"><div class="si-key">{html_mod.escape(str(k))}</div><div class="si-val">{html_mod.escape(str(v))}</div></div>'
    si_html += '</div>'
    html_parts.append(section("ðŸ’» System Information", si_html, default_open=True))
    html_parts.append('</div>')

    # â”€â”€ USB DEVICES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="usb-devices">')
    usb_data = artifacts.get("usb_devices", [])
    usb_analysis = artifacts.get("_analysis", {}).get("usb_devices", {})
    usb_html = llm_summary_box(usb_analysis)
    if usb_data:
        usb_rows = [[
            d.get("device_category",""),
            d.get("friendly_name",""),
            d.get("device_type_raw","")[:80],
            d.get("serial_number","")[:40],
            d.get("first_install",""),
            d.get("last_arrival",""),
            d.get("last_removal",""),
            d.get("manufacturer",""),
        ] for d in usb_data]
        usb_html += table(["Category","Friendly Name","Device Type","Serial","First Install","Last Arrival","Last Removal","Manufacturer"], usb_rows, max_rows=200)
    else:
        usb_html += '<p class="no-data">No USB storage devices found in registry</p>'
    usb_html += findings_table(usb_analysis.get("findings",[]))
    html_parts.append(section(f"ðŸ”Œ Connected USB / Storage Devices", usb_html, len(usb_data), default_open=True))
    html_parts.append('</div>')

    # â”€â”€ PERSISTENCE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="persistence">')
    pers_sys = artifacts.get("persistence_system", [])
    pers_analysis = artifacts.get("_analysis", {}).get("persistence_system", {})
    pers_html = llm_summary_box(pers_analysis)
    if pers_sys:
        pers_rows = [[p["hive"], p["key"].split("\\")[-1], p["name"], p["value"][:200], p["suspicious"]] for p in pers_sys]
        pers_html += table(["Hive","Key","Name","Value","âš ï¸ Suspicious?"], pers_rows)
    else:
        pers_html += '<p class="no-data">No system-level autorun entries found</p>'
    pers_html += findings_table(pers_analysis.get("findings",[]))

    # Winlogon
    wl = artifacts.get("winlogon", {})
    wl_html = ""
    if wl:
        wl_rows = []
        for k, v in wl.items():
            if k.startswith("_"):
                continue
            flag = ""
            if k == "Userinit" and not wl.get("_userinit_ok"):
                flag = "âš ï¸ NON-STANDARD"
            if k == "Shell" and not wl.get("_shell_ok"):
                flag = "âš ï¸ NON-STANDARD"
            if k == "AutoAdminLogon" and v == "1":
                flag = "âš ï¸ AUTOLOGON ENABLED"
            wl_rows.append([k, str(v)[:200], flag])
        wl_html = table(["Value Name", "Data", "Flag"], wl_rows)
    pers_html += f"<h3 style='margin:16px 0 8px;color:var(--accent)'>Winlogon</h3>{wl_html}"

    # IFEO
    ifeo = artifacts.get("ifeo", [])
    if ifeo:
        ifeo_rows = [[i["target_exe"], i["value_name"], i["value"][:200], i["risk"]] for i in ifeo]
        pers_html += "<h3 style='margin:16px 0 8px;color:var(--critical)'>âš ï¸ Image File Execution Options (IFEO Hijacks)</h3>"
        pers_html += table(["Target EXE","Value","Data","Risk"], ifeo_rows)

    # AppInit DLLs
    appinit = artifacts.get("appinit_dlls", {})
    if appinit:
        ai_rows = [[k, v] for k, v in appinit.items()]
        pers_html += "<h3 style='margin:16px 0 8px;color:var(--high)'>AppInit_DLLs</h3>"
        pers_html += table(["Name","Value"], ai_rows)

    # Autologon
    autologon = artifacts.get("autologon", {})
    if autologon.get("AutoAdminLogon") == "1":
        al_rows = [[k, v] for k, v in autologon.items()]
        pers_html += "<h3 style='margin:16px 0 8px;color:var(--critical)'>âš ï¸ AutoLogon Credentials</h3>"
        pers_html += table(["Setting","Value"], al_rows)

    html_parts.append(section(f"ðŸš€ Persistence / Autoruns", pers_html, len(pers_sys), default_open=True))
    html_parts.append('</div>')

    # â”€â”€ SERVICES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="services">')
    svcs = artifacts.get("services", [])
    svc_analysis = artifacts.get("_analysis", {}).get("services", {})
    svc_html = llm_summary_box(svc_analysis)
    if svcs:
        svc_rows = [[s["name"], s["display_name"], s["start_label"], s["type_label"],
                     s["image_path"][:200], s["object_name"][:80], s["suspicious_path"]]
                    for s in svcs]
        svc_html += table(["Service Name","Display Name","Start","Type","ImagePath","RunAs","âš ï¸ Suspicious?"], svc_rows, max_rows=300)
    svc_html += findings_table(svc_analysis.get("findings",[]))
    html_parts.append(section(f"âš™ï¸ Services ({len(svcs)})", svc_html, len(svcs)))
    html_parts.append('</div>')

    # â”€â”€ NETWORK â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="network">')
    wifi = artifacts.get("wifi_profiles", [])
    net_analysis = artifacts.get("_analysis", {}).get("network", {})
    net_html = llm_summary_box(net_analysis)

    if wifi:
        wifi_rows = [[w["profile_name"] or w["profile_guid"],
                      w["category_label"], w["date_created"],
                      w["date_last_connected"], w["description"]] for w in wifi]
        net_html += "<h3 style='margin:0 0 8px;color:var(--accent)'>Network Profiles (WiFi/Ethernet)</h3>"
        net_html += table(["Profile Name","Category","Date Created","Last Connected","Description"], wifi_rows)

    netsigs = artifacts.get("network_signatures", [])
    if netsigs:
        sig_rows = [[s["description"] or s["guid"], s["first_network"], s["dns_suffix"],
                     s["default_gateway_mac"], "Managed" if s["managed"] else "Unmanaged"] for s in netsigs]
        net_html += "<h3 style='margin:16px 0 8px;color:var(--accent)'>Network Signatures (Gateway MAC)</h3>"
        net_html += table(["Description","First Network","DNS Suffix","Gateway MAC","Type"], sig_rows)

    netifc = artifacts.get("network_interfaces", [])
    if netifc:
        ifc_rows = [[i["guid"][:36], i["ip_address"], i["subnet_mask"],
                     i["default_gateway"], i["dns_servers"]] for i in netifc if i["ip_address"]]
        if ifc_rows:
            net_html += "<h3 style='margin:16px 0 8px;color:var(--accent)'>TCP/IP Interfaces</h3>"
            net_html += table(["Interface GUID","IP Address","Subnet","Gateway","DNS Servers"], ifc_rows)

    vpns = artifacts.get("vpn_indicators", [])
    if vpns:
        vpn_rows = [[v["software"], v["note"]] for v in vpns]
        net_html += "<h3 style='margin:16px 0 8px;color:var(--high)'>âš ï¸ VPN / Tunnel Software</h3>"
        net_html += table(["Software","Note"], vpn_rows)

    fw = artifacts.get("firewall_status", [])
    if fw:
        fw_rows = [[f["profile"], f["firewall_enabled"], f["notifications"]] for f in fw]
        net_html += "<h3 style='margin:16px 0 8px;color:var(--accent)'>Firewall Status</h3>"
        net_html += table(["Profile","Firewall","Notifications"], fw_rows)

    shares = artifacts.get("shared_folders", [])
    if shares:
        sh_rows = [[s["share_name"], s["config"][:200]] for s in shares]
        net_html += "<h3 style='margin:16px 0 8px;color:var(--high)'>Shared Folders</h3>"
        net_html += table(["Share Name","Config"], sh_rows)

    net_html += findings_table(net_analysis.get("findings",[]))
    html_parts.append(section("ðŸŒ Network Artifacts", net_html, len(wifi)))
    html_parts.append('</div>')

    # â”€â”€ USER ACCOUNTS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="accounts">')
    accts = artifacts.get("user_accounts", [])
    logon_ui = artifacts.get("last_logon_info", {})
    acct_html = ""
    if accts:
        acct_rows = [[a["username"], a["rid"], a["last_write"]] for a in accts]
        acct_html += table(["Username","RID","Last Registry Write"], acct_rows)
    if logon_ui:
        llu_rows = [[k, v] for k, v in logon_ui.items() if v]
        acct_html += "<h3 style='margin:16px 0 8px;color:var(--accent)'>Last Logon UI</h3>"
        acct_html += table(["Setting","Value"], llu_rows[:20])
    if not acct_html:
        acct_html = '<p class="no-data">SAM hive not accessible</p>'
    html_parts.append(section(f"ðŸ‘¤ User Accounts", acct_html, len(accts)))
    html_parts.append('</div>')

    # â”€â”€ EXECUTION ARTIFACTS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="execution">')
    exec_html = ""

    bam = artifacts.get("bam_entries", [])
    if bam:
        bam_rows = [[b["sid"], b["exe_path"][:200], b["last_run"], b["suspicious"]] for b in bam]
        exec_html += "<h3 style='margin:0 0 8px;color:var(--accent)'>BAM â€” Background Activity Monitor</h3>"
        exec_html += table(["SID","Executable Path","Last Run","âš ï¸"], bam_rows, max_rows=200)

    shimcache = artifacts.get("shimcache", [])
    if shimcache:
        sc_rows = [[s["exe_path"][:250], s["suspicious"]] for s in shimcache]
        exec_html += "<h3 style='margin:16px 0 8px;color:var(--accent)'>ShimCache (AppCompatCache) â€” EXEs known to OS</h3>"
        exec_html += table(["Executable Path","âš ï¸"], sc_rows, max_rows=200)

    amcache = artifacts.get("amcache", [])
    if amcache:
        am_rows = [[a["full_path"][:200] or a["name"], a["sha1"], a["link_date"], a["size"]] for a in amcache]
        exec_html += "<h3 style='margin:16px 0 8px;color:var(--accent)'>Amcache â€” Applications Ever Run</h3>"
        exec_html += table(["Path","SHA1","Link Date","Size"], am_rows, max_rows=200)

    if not exec_html:
        exec_html = '<p class="no-data">No execution artifacts found</p>'
    html_parts.append(section(f"â–¶ï¸ Execution Artifacts", exec_html, len(bam) + len(shimcache)))
    html_parts.append('</div>')

    # â”€â”€ USER ACTIVITY (system-level) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="user-activity">')
    tasks = artifacts.get("scheduled_tasks", [])
    ua_html = ""
    if tasks:
        t_rows = [[t["path"] or t["guid"], t["actions_preview"][:200]] for t in tasks]
        ua_html += table(["Task Path / GUID","Actions Preview"], t_rows, max_rows=200)
    else:
        ua_html = '<p class="no-data">No scheduled task registry entries found</p>'
    caps = artifacts.get("capability_access", [])
    if caps:
        cap_rows = [[c["capability"], c["app"][:120], c["consent"]] for c in caps]
        ua_html += "<h3 style='margin:16px 0 8px;color:var(--accent)'>Privacy / Capability Access (Camera/Mic/Location)</h3>"
        ua_html += table(["Capability","App","Consent"], cap_rows, max_rows=200)
    html_parts.append(section(f"ðŸ“‹ Scheduled Tasks & Privacy", ua_html, len(tasks)))
    html_parts.append('</div>')

    # â”€â”€ PER-USER ARTIFACTS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="user-specific">')
    if users:
        # Tabs
        tab_btns = "".join(f'<button class="tab-btn{"  active" if i==0 else ""}" onclick="showTab(this,\'u-{u}\')">{u}</button>'
                           for i, u in enumerate(users))
        html_parts.append(f'<div class="tabs">{tab_btns}</div>')
        for i, u in enumerate(users):
            active_cls = " active" if i == 0 else ""
            user_artifacts = artifacts.get("users", {}).get(u, {})
            user_analysis  = user_artifacts.get("_analysis", {})
            u_html = ""

            # RunMRU
            runmru = user_artifacts.get("runmru", [])
            if runmru:
                u_html += "<h3 style='color:var(--accent);margin:0 0 8px'>Run Dialog History (RunMRU)</h3>"
                u_html += table(["Order","Key","Command"], [[r["order"],r["key"],r["command"]] for r in runmru])

            # TypedPaths
            tpaths = user_artifacts.get("typed_paths", [])
            if tpaths:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>Explorer Typed Paths (Address Bar History)</h3>"
                u_html += table(["Path"], [[p] for p in tpaths])

            # UserAssist
            ua = user_artifacts.get("userassist", [])
            if ua:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>UserAssist (Programs Launched via Explorer)</h3>"
                ua_rows = [[x["program"][:200], x["run_count"], x["last_run"], x["suspicious"]] for x in ua]
                u_html += table(["Program","Run Count","Last Run","âš ï¸"], ua_rows, max_rows=200)

            # SearchHistory
            searches = user_artifacts.get("search_history", [])
            if searches:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>Explorer Search History (WordWheelQuery)</h3>"
                u_html += table(["Search Term"], [[s] for s in searches])

            # RecentDocs
            rdocs = user_artifacts.get("recent_docs", [])
            if rdocs:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>Recently Accessed Files (RecentDocs)</h3>"
                u_html += table(["Extension","Filename"], [[r["extension"],r["filename"]] for r in rdocs], max_rows=200)

            # OpenSaveMRU
            osmru = user_artifacts.get("open_save_mru", [])
            if osmru:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>Open/Save Dialog MRU</h3>"
                u_html += table(["Extension","Path"], [[r["extension"],r["path"]] for r in osmru], max_rows=200)

            # LastVisitedMRU
            lvmru = user_artifacts.get("last_visited_mru", [])
            if lvmru:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>Last Visited MRU</h3>"
                u_html += table(["Entry","App/Path"], [[r["entry"],r["app_or_path"]] for r in lvmru])

            # Typed URLs
            turls = user_artifacts.get("typed_urls", [])
            if turls:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>IE/Edge Typed URLs</h3>"
                u_html += table(["Name","URL"], [[r["name"],r["url"]] for r in turls])

            # ShellBags
            sbags = user_artifacts.get("shellbags", [])
            if sbags:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>ShellBags (Folder Browse History)</h3>"
                u_html += table(["Hive","BagMRU Path","Subkey Count","Note"],
                                 [[s["hive"],s["key"],s["subkey_count"],s["note"]] for s in sbags])

            # RDP MRU
            rdp = user_artifacts.get("rdp_mru", [])
            if rdp:
                u_html += "<h3 style='color:var(--high);margin:16px 0 8px'>ðŸ–¥ï¸ RDP Connections (MRU)</h3>"
                u_html += table(["Entry","Server",*(['Username Hint'] if any('username_hint' in r for r in rdp) else [])],
                                 [[r["entry"],r["server"],r.get("username_hint","")] for r in rdp])

            # Mapped Drives
            mapped = user_artifacts.get("mapped_drives", [])
            if mapped:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>Mapped Network Drives</h3>"
                u_html += table(["Drive","Details"], [[m["drive_letter"], str(m)] for m in mapped])

            # MountPoints2
            mp2 = user_artifacts.get("mount_points2", [])
            if mp2:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>MountPoints2 (Drive & USB Mounts)</h3>"
                u_html += table(["Mount","Label"], [[m["mount"],m["label"]] for m in mp2])

            # IE Zone Map
            zm = user_artifacts.get("ie_zone_map", [])
            if zm:
                u_html += "<h3 style='color:var(--accent);margin:16px 0 8px'>IE Zone Map (Security Zones)</h3>"
                u_html += table(["Setting/Domain","Value/Note"],
                                 [[z.get("setting",z.get("domain","")), z.get("value",z.get("note",""))] for z in zm])

            # User Persistence
            u_pers = user_artifacts.get("persistence_user", [])
            if u_pers:
                u_html += "<h3 style='color:var(--high);margin:16px 0 8px'>âš ï¸ User-Level Persistence (Run Keys)</h3>"
                u_html += table(["Key","Name","Value","âš ï¸"],
                                 [[p["key"],p["name"],p["value"][:200],p["suspicious"]] for p in u_pers])

            # LLM findings
            if user_analysis:
                u_html += "<h3 style='color:var(--critical);margin:16px 0 8px'>ðŸ¤– LLM Analysis Findings</h3>"
                for artifact_name, analysis in user_analysis.items():
                    findings = analysis.get("findings", [])
                    if findings:
                        u_html += f"<p style='color:var(--muted);margin:8px 0 4px;font-size:0.8em'><em>{artifact_name}</em></p>"
                        u_html += findings_table(findings)

            if not u_html:
                u_html = '<p class="no-data">No NTUSER.DAT artifacts found for this user</p>'

            html_parts.append(f'<div class="tab-panel{active_cls}" id="u-{u}">{u_html}</div>')

    html_parts.append('</div>')

    # â”€â”€ SECURITY CHECKS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="security">')
    sec_html = ""
    wl2 = artifacts.get("winlogon", {})
    if wl2.get("_autologon"):
        sec_html += f'<div style="background:#c0392b22;border:1px solid #c0392b;border-radius:8px;padding:12px 16px;margin-bottom:12px">âš ï¸ <strong>AutoLogon ENABLED</strong> â€” User: {wl2.get("_autologon_user","")} â€” {wl2.get("_autologon_pass","")}</div>'
    if wl2.get("_legal_notice"):
        sec_html += f'<div style="background:#e67e2222;border:1px solid #e67e22;border-radius:8px;padding:12px 16px;margin-bottom:12px">âš ï¸ <strong>Legal Notice Text:</strong> {wl2["_legal_notice"]}</div>'
    if not wl2.get("_shell_ok", True):
        sec_html += f'<div style="background:#c0392b22;border:1px solid #c0392b;border-radius:8px;padding:12px 16px;margin-bottom:12px">ðŸš¨ <strong>Non-standard Shell:</strong> {wl2.get("Shell","?")}</div>'
    if not wl2.get("_userinit_ok", True):
        sec_html += f'<div style="background:#c0392b22;border:1px solid #c0392b;border-radius:8px;padding:12px 16px;margin-bottom:12px">ðŸš¨ <strong>Non-standard Userinit:</strong> {wl2.get("Userinit","?")}</div>'
    if not sec_html:
        sec_html = '<p class="no-data">No critical security misconfigurations detected</p>'
    html_parts.append(section("ðŸ›¡ï¸ Security Checks", sec_html, default_open=True))
    html_parts.append('</div>')

    # â”€â”€ INSTALLED SOFTWARE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="software">')
    sw = artifacts.get("installed_software", [])
    if sw:
        sw_rows = [[s["name"], s["version"], s["publisher"], s["install_date"]] for s in sw]
        sw_html = table(["Name","Version","Publisher","Install Date"], sw_rows, max_rows=500)
    else:
        sw_html = '<p class="no-data">No installed software found</p>'
    html_parts.append(section(f"ðŸ“¦ Installed Software ({len(sw)})", sw_html))
    html_parts.append('</div>')

    # â”€â”€ ALL FINDINGS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append('<div id="all-findings">')
    sorted_findings = sorted(all_findings, key=lambda x: SEVERITY.get(x.get("severity","INFO").upper(), 4))
    af_rows = [[sev_badge(f.get("severity","INFO")), f.get("artifact",""), f.get("title",""), f.get("detail","")[:300], f.get("ioc","")] for f in sorted_findings]
    af_html = table(["Severity","Artifact","Title","Detail","IOC"], af_rows, max_rows=1000)
    html_parts.append(section(f"âš ï¸ All LLM Findings ({len(all_findings)})", af_html, len(all_findings), default_open=True))
    html_parts.append('</div>')

    # Close layout
    html_parts.append('</div></div>')  # .main, .layout

    # â”€â”€ JAVASCRIPT â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    html_parts.append("""
<script>
function showTab(btn, id) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  const panel = document.getElementById(id);
  if (panel) panel.classList.add('active');
}
function filterContent(q) {
  q = q.toLowerCase();
  document.querySelectorAll('tr').forEach(row => {
    if (row.parentElement.tagName === 'THEAD') return;
    row.style.display = !q || row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
// Auto-open sections with CRITICAL/HIGH findings
document.querySelectorAll('details.section').forEach(d => {
  const text = d.textContent;
  if (text.includes('CRITICAL') || text.includes('⚠️ YES')) {
    d.open = true;
  }
});
</script>
</body></html>""")

    html_out = output_dir / "forensic_registry_report.html"
    html_out.write_text("".join(html_parts), encoding="utf-8")
    log.info(f"  ✓ HTML report written: {html_out}")
    return html_out


# ─── MAIN ORCHESTRATOR ──────────────────────────────────────────────────────────
def run_investigation(root: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    log.info("=" * 60)
    log.info("  WINDOWS REGISTRY FORENSIC AGENT v7.1 (Codex-Remediated)")
    log.info("=" * 60)

    # ══════════════════════════════════════════════════════════════
    # PHASE 1: RAW ACQUISITION — discover hives, copy raw + .LOG files
    # ══════════════════════════════════════════════════════════════
    log.info("[PHASE 1: RAW ACQUISITION]")
    hive_paths = find_hives(root)
    if not hive_paths:
        log.error("Aborting: no hives found.")
        sys.exit(1)

    # P1 fix: Create output layout
    raw_dir = output_dir / "artifacts" / "raw_registry"
    raw_dir.mkdir(parents=True, exist_ok=True)
    parsed_dir = output_dir / "parsed_artifact"
    parsed_dir.mkdir(parents=True, exist_ok=True)

    # P1 fix: Copy raw hives + .LOG companions to output
    manifest_entries = []
    for label, staged_path in hive_paths.items():
        # Determine proper output name
        if label.startswith("NTUSER_"):
            user = label.replace("NTUSER_", "")
            raw_name = f"NTUSER_{user}.DAT"
        elif label.startswith("USRCLASS_"):
            user = label.replace("USRCLASS_", "")
            raw_name = f"USRCLASS_{user}.dat"
        elif label == "Amcache":
            raw_name = "Amcache.hve"
        else:
            raw_name = label  # SYSTEM, SOFTWARE, SAM, SECURITY

        raw_dest = raw_dir / raw_name
        try:
            shutil.copy2(str(staged_path), str(raw_dest))
            file_size = raw_dest.stat().st_size
            # Compute SHA256 for manifest
            sha256 = hashlib.sha256(raw_dest.read_bytes()).hexdigest()
            log.info(f"  Raw copy: {raw_name} ({file_size:,} bytes, SHA256: {sha256[:16]}...)")

            entry = {
                "label": label,
                "raw_file": raw_name,
                "source_path": _hive_source_paths.get(label, str(staged_path)),
                "size_bytes": file_size,
                "sha256": sha256,
            }
            manifest_entries.append(entry)

            # P1 fix: Copy .LOG1/.LOG2 companions
            source_path = Path(_hive_source_paths.get(label, str(staged_path)))
            if source_path.exists():
                copy_log_companions(source_path, raw_dir, raw_name)

        except Exception as e:
            log.warning(f"  Failed to copy raw hive {label}: {e}")

    # Open hives for parsing
    hives = open_hives(hive_paths)

    # Detect users
    users = sorted(set(
        k.replace("NTUSER_", "") for k in hives if k.startswith("NTUSER_")
    ))
    log.info(f"  Users detected: {users}")

    # ══════════════════════════════════════════════════════════════
    # PHASE 2: FULL-HIVE PARSING — recursive root-to-leaf JSONL export
    # ══════════════════════════════════════════════════════════════
    log.info("[PHASE 2: FULL-HIVE PARSING (root-to-leaf)]")
    parse_stats = []
    for label, reg in hives.items():
        user = None
        if label.startswith("NTUSER_"):
            user = label.replace("NTUSER_", "")
        elif label.startswith("USRCLASS_"):
            user = label.replace("USRCLASS_", "")

        source = _hive_source_paths.get(label, "")
        parser = FullRegistryParser(hive_name=label, source_path=source, user=user)
        jsonl_name = f"{label}.jsonl"
        jsonl_path = parsed_dir / jsonl_name
        stats = parser.parse_to_jsonl(reg, jsonl_path)
        parse_stats.append(stats)

        # Update manifest with parse stats
        for entry in manifest_entries:
            if entry["label"] == label:
                entry["jsonl_file"] = jsonl_name
                entry["total_keys"] = stats["total_keys"]
                entry["total_values"] = stats["total_values"]
                entry["parse_errors"] = stats["errors"]
                entry["parse_seconds"] = stats.get("elapsed_seconds", 0)
                break

    # ══════════════════════════════════════════════════════════════
    # PHASE 3: TRIAGE EXTRACTION + LLM ANALYSIS + REPORT
    # ══════════════════════════════════════════════════════════════
    log.info("[PHASE 3: TRIAGE EXTRACTION]")
    ext = ArtifactExtractor(hives)
    artifacts = {}

    # System
    os_info   = ext.os_info()
    comp_name = ext.computer_name()
    tz_info   = ext.timezone()
    last_sd   = ext.last_shutdown()
    system_info = {
        "ComputerName": comp_name,
        "os_info":      os_info,
        "timezone":     tz_info,
        "last_shutdown": last_sd,
    }

    log.info("  Extracting USB devices...")
    artifacts["usb_devices"] = ext.usb_devices()

    log.info("  Extracting persistence (system)...")
    artifacts["persistence_system"] = ext.persistence_system()

    log.info("  Extracting Winlogon...")
    artifacts["winlogon"] = ext.winlogon()
    artifacts["autologon"] = ext.autologon_check()
    artifacts["appinit_dlls"] = ext.appinit_dlls()
    artifacts["ifeo"] = ext.ifeo()

    log.info("  Extracting services...")
    artifacts["services"] = ext.services()

    log.info("  Extracting network artifacts...")
    artifacts["wifi_profiles"] = ext.wifi_profiles()
    artifacts["network_signatures"] = ext.network_signatures()
    artifacts["network_interfaces"] = ext.network_interfaces()
    artifacts["firewall_status"] = ext.firewall_status()
    artifacts["shared_folders"] = ext.shared_folders()
    artifacts["vpn_indicators"] = ext.vpn_indicators()

    log.info("  Extracting user accounts...")
    artifacts["user_accounts"] = ext.user_accounts()
    artifacts["last_logon_info"] = ext.last_logon_info()

    log.info("  Extracting scheduled tasks...")
    artifacts["scheduled_tasks"] = ext.scheduled_tasks()

    log.info("  Extracting BAM entries...")
    artifacts["bam_entries"] = ext.bam_entries()

    log.info("  Extracting ShimCache...")
    artifacts["shimcache"] = ext.shimcache()

    log.info("  Extracting Amcache...")
    artifacts["amcache"] = ext.amcache()

    log.info("  Extracting installed software...")
    artifacts["installed_software"] = ext.installed_software()

    log.info("  Extracting capability access...")
    artifacts["capability_access"] = ext.capability_access()

    # P3 fix: Wire in previously dead/unfinished extractors
    log.info("  Extracting DNS cache registry...")
    artifacts["dns_cache_registry"] = ext.dns_cache_registry()

    log.info("  Extracting svchost groups...")
    artifacts["svchost_groups"] = ext.svchost_groups()

    # SECURITY hive extraction (P0 fix: SECURITY fully parsed)
    log.info("  Extracting SECURITY hive policy data...")
    artifacts["security_policy"] = ext.security_policy()

    # Per-user
    artifacts["users"] = {}
    for user in users:
        log.info(f"  Extracting user artifacts for: {user}")
        udata = {}
        udata["runmru"]           = ext.runmru(user)
        udata["typed_paths"]      = ext.typed_paths(user)
        udata["recent_docs"]      = ext.recent_docs(user)
        udata["open_save_mru"]    = ext.open_save_mru(user)
        udata["last_visited_mru"] = ext.last_visited_mru(user)
        udata["search_history"]   = ext.search_history(user)
        udata["typed_urls"]       = ext.typed_urls(user)
        udata["userassist"]       = ext.userassist(user)
        udata["shellbags"]        = ext.shellbags(user)
        udata["rdp_mru"]          = ext.rdp_mru(user)
        udata["mapped_drives"]    = ext.mapped_drives(user)
        udata["mount_points2"]    = ext.mount_points2(user)
        udata["ie_zone_map"]      = ext.ie_zone_map(user)
        udata["persistence_user"] = ext.persistence_user(user)
        # P3 fix: Wire in chrome_prefs_reg
        udata["chrome_prefs_reg"] = ext.chrome_prefs_reg(user)
        artifacts["users"][user] = udata

    # LLM Analysis
    log.info("[LLM ANALYSIS]")
    llm = LLMAnalyst()
    all_findings = []

    def collect_findings(analysis: dict, artifact_name: str):
        for f in analysis.get("findings", []):
            f["artifact"] = artifact_name
            all_findings.append(f)
        return analysis

    artifacts["_analysis"] = {}

    def analyze(name, data):
        if not data:
            return {"summary":"No data.","findings":[],"iocs":[],"risk_score":0}
        log.info(f"  LLM: analyzing {name}...")
        return collect_findings(llm.analyze_artifact(name, data), name)

    artifacts["_analysis"]["usb_devices"] = analyze("USB Devices", artifacts["usb_devices"])
    artifacts["_analysis"]["persistence_system"] = analyze("System Persistence (Run Keys / Winlogon)", {
        "run_keys": artifacts["persistence_system"],
        "winlogon": artifacts["winlogon"],
        "ifeo": artifacts["ifeo"],
        "appinit_dlls": artifacts["appinit_dlls"],
        "autologon": artifacts["autologon"],
    })
    # Send services with image_path (no truncation for data, but limit LLM context)
    svc_for_llm = [
        {"name": s["name"], "image_path": s["image_path"],
         "start_label": s["start_label"], "suspicious": s["suspicious_path"]}
        for s in artifacts["services"] if s.get("image_path")
    ][:60]  # LLM context limit only
    artifacts["_analysis"]["services"] = analyze("Windows Services", svc_for_llm)
    artifacts["_analysis"]["network"] = analyze("Network Profiles & Connectivity", {
        "wifi_profiles": artifacts["wifi_profiles"],
        "network_signatures": artifacts["network_signatures"],
        "firewall_status": artifacts["firewall_status"],
        "vpn_indicators": artifacts["vpn_indicators"],
        "shared_folders": artifacts["shared_folders"],
    })
    artifacts["_analysis"]["execution"] = analyze("Execution Artifacts (BAM/ShimCache/Amcache)", {
        "bam": artifacts["bam_entries"][:30],      # LLM context limit
        "shimcache": artifacts["shimcache"][:30],
        "amcache": artifacts["amcache"][:30],
    })

    # Per-user LLM
    for user in users:
        udata = artifacts["users"][user]
        log.info(f"  LLM: analyzing user {user}...")
        udata["_analysis"] = {}
        udata["_analysis"]["user_activity"] = collect_findings(
            llm.analyze_artifact(f"User {user} Activity", {
                "runmru": udata["runmru"],
                "userassist": udata["userassist"][:20],
                "search_history": udata["search_history"],
                "typed_paths": udata["typed_paths"],
                "rdp_mru": udata["rdp_mru"],
                "recent_docs": udata["recent_docs"][:20],
                "persistence": udata["persistence_user"],
            }), f"User:{user}"
        )

    # Executive summary
    log.info("  LLM: generating executive summary...")
    exec_summary = llm.generate_executive_summary(all_findings, system_info)

    # ══════════════════════════════════════════════════════════════
    # SAVE: manifest, triage JSON, HTML report
    # ══════════════════════════════════════════════════════════════
    log.info("[SAVING OUTPUTS]")

    # Registry manifest
    manifest = {
        "agent_version": "9.0-codex-remediated",
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "source_root": str(root),
        "computer_name": comp_name,
        "users_detected": users,
        "hives": manifest_entries,
        "parse_stats": parse_stats,
    }
    manifest_path = parsed_dir / "registry_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)
    log.info(f"  Manifest: {manifest_path}")

    # Triage artifacts JSON (kept for backwards compat)
    safe_arts = {k: v for k, v in artifacts.items() if k != "_analysis"}
    json_out = parsed_dir / "artifacts.json"
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump({"system_info": system_info, "artifacts": safe_arts,
                   "all_findings": all_findings}, f, indent=2, default=str)
    log.info(f"  Triage JSON: {json_out}")

    # HTML report
    log.info("[BUILDING REPORT]")
    html_path = build_report(artifacts, exec_summary, all_findings, parsed_dir, users, system_info)

    log.info("=" * 60)
    log.info(f"  DONE - Report: {html_path}")
    log.info(f"  Raw hives: {raw_dir}")
    log.info(f"  Parsed JSONL: {parsed_dir}")
    log.info(f"  Findings: CRITICAL={sum(1 for f in all_findings if f.get('severity')=='CRITICAL')} "
             f"HIGH={sum(1 for f in all_findings if f.get('severity')=='HIGH')} "
             f"MEDIUM={sum(1 for f in all_findings if f.get('severity')=='MEDIUM')}")
    log.info("=" * 60)
    return html_path



    log.info(f"  âœ“ JSON: {json_out}")

    # 6. Build HTML report
    log.info("[BUILDING REPORT]")
    html_path = build_report(artifacts, exec_summary, all_findings, output_dir, users, system_info)

    log.info("=" * 60)
    log.info(f"  âœ… DONE â€” Report: {html_path}")
    log.info(f"  Findings: CRITICAL={sum(1 for f in all_findings if f.get('severity')=='CRITICAL')} "
             f"HIGH={sum(1 for f in all_findings if f.get('severity')=='HIGH')} "
             f"MEDIUM={sum(1 for f in all_findings if f.get('severity')=='MEDIUM')}")
    log.info("=" * 60)
    return html_path


# â”€â”€â”€ CLI â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Windows Registry Forensic Agent v7 â€” THE BEAST",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  # Mounted Windows image:
  python registry_agent_v7.py --mounted /mnt/windows_image --output ./report

  # E01 via ewfmount (mount first, then run):
  sudo ewfmount evidence.E01 /mnt/ewf
  sudo mount -o ro,loop,show_sys_files,streams_interface=windows /mnt/ewf/ewf1 /mnt/win_ntfs
  python registry_agent_v7.py --mounted /mnt/win_ntfs --output ./report

  # Live Windows system (run as Administrator):
  python registry_agent_v7.py --mounted C:\\ --output .\\report

  # Custom Ollama settings:
  OLLAMA_URL=http://192.168.1.100:11434 OLLAMA_MODEL=llama3:8b python registry_agent_v7.py ...
"""
    )
    parser.add_argument("--mounted", required=True,
                        help="Root path of the mounted Windows filesystem")
    parser.add_argument("--output", default="./forensic_report",
                        help="Output directory for report files (default: ./forensic_report)")
    parser.add_argument("--ollama-url", default=None,
                        help=f"Ollama server URL (default: {OLLAMA_URL})")
    parser.add_argument("--model", default=None,
                        help=f"Ollama model name (default: {OLLAMA_MODEL})")
    args = parser.parse_args()

    if args.ollama_url:
        OLLAMA_URL = args.ollama_url
    if args.model:
        OLLAMA_MODEL = args.model

    run_investigation(Path(args.mounted), Path(args.output))


