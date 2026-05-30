"""
Curated indicator lists used by the deterministic forensic investigator.
These are matched against parsed artifacts (browser history, prefetch, registry, etc.)
to produce evidence-based findings without LLM involvement.
"""

from __future__ import annotations

# ── Cloud storage / personal sync ───────────────────────────────────────────
KNOWN_CLOUD_DOMAINS = {
    "drive.google.com":     "Google Drive",
    "docs.google.com":      "Google Docs",
    "googleusercontent.com": "Google Drive (user content)",
    "dropbox.com":          "Dropbox",
    "dl.dropboxusercontent.com": "Dropbox (download)",
    "onedrive.live.com":    "Microsoft OneDrive",
    "1drv.ms":              "Microsoft OneDrive (short)",
    "sharepoint.com":       "Microsoft SharePoint",
    "office365.com":        "Microsoft Office 365",
    "icloud.com":           "Apple iCloud",
    "mega.nz":              "MEGA",
    "mega.io":              "MEGA",
    "box.com":              "Box.com",
    "pcloud.com":           "pCloud",
    "drive.proton.me":      "Proton Drive",
    "drive.protonmail.com": "Proton Drive",
    "sync.com":             "Sync.com",
    "tresorit.com":         "Tresorit",
}

# ── File-sharing / one-shot upload services (HIGH-RISK exfil) ──────────────
KNOWN_FILESHARING_DOMAINS = {
    "wetransfer.com":       "WeTransfer",
    "we.tl":                "WeTransfer (short)",
    "anonfiles.com":        "AnonFiles",
    "anonfile.com":         "AnonFile",
    "file.io":              "File.io",
    "send.firefox.com":     "Firefox Send",
    "transfer.sh":          "Transfer.sh",
    "gofile.io":            "Gofile",
    "uploadfiles.io":       "UploadFiles",
    "sendspace.com":        "SendSpace",
    "mediafire.com":        "MediaFire",
    "zippyshare.com":       "ZippyShare",
    "filebin.net":          "Filebin",
    "smash.gg":             "Smash",
    "tempsend.com":         "TempSend",
    "pixeldrain.com":       "Pixeldrain",
    "uploadnow.io":         "UploadNow",
    "krakenfiles.com":      "KrakenFiles",
    "files.fm":             "Files.fm",
    "mixdrop.co":           "Mixdrop",
    "pastebin.com":         "Pastebin",
    "ghostbin.co":          "Ghostbin",
    "hastebin.com":         "Hastebin",
    "paste.ee":             "Paste.ee",
    "0bin.net":             "0bin",
    "pasteio.com":          "Paste.io",
    "controlc.com":         "ControlC paste",
    "rentry.co":            "Rentry paste",
}

# ── Personal email web interfaces (potential exfil channel) ────────────────
KNOWN_PERSONAL_EMAIL = {
    "mail.google.com":      "Gmail",
    "outlook.live.com":     "Outlook.com",
    "mail.yahoo.com":       "Yahoo Mail",
    "mail.protonmail.com":  "ProtonMail",
    "tutanota.com":         "Tutanota",
    "fastmail.com":         "FastMail",
    "mail.aol.com":         "AOL Mail",
    "icloud.com":           "iCloud Mail",
}

# ── Anonymity / privacy tools ──────────────────────────────────────────────
KNOWN_PRIVACY_TOOLS = {
    "torproject.org":       "Tor Browser project",
    "expressvpn.com":       "ExpressVPN",
    "nordvpn.com":          "NordVPN",
    "protonvpn.com":        "ProtonVPN",
    "mullvad.net":          "Mullvad VPN",
    "tunnelbear.com":       "TunnelBear VPN",
    "ipredator.se":         "IPredator VPN",
    "windscribe.com":       "Windscribe VPN",
    "psiphon3.com":         "Psiphon",
    "torguard.net":         "TorGuard VPN",
}

# ── Known hacking tools / malware utility names (case-insensitive substring) ─
KNOWN_HACKTOOLS = {
    "mimikatz":             ("Credential dumper",                  "CRITICAL"),
    "lazagne":              ("LaZagne password recovery",          "CRITICAL"),
    "procdump":             ("ProcDump (lsass dump tool)",         "HIGH"),
    "psexec":               ("PsExec remote execution",            "HIGH"),
    "psexec64":             ("PsExec64 remote execution",          "HIGH"),
    "paexec":               ("PAExec (PsExec clone)",              "HIGH"),
    "rdpwrap":              ("RDP Wrapper (multi-RDP)",            "HIGH"),
    "ncat":                 ("Ncat networking utility",            "MEDIUM"),
    "netcat":               ("Netcat networking utility",          "MEDIUM"),
    "nc.exe":               ("Netcat",                              "MEDIUM"),
    "powersploit":          ("PowerSploit framework",              "CRITICAL"),
    "powerview":            ("PowerView reconnaissance",           "HIGH"),
    "bloodhound":           ("BloodHound AD reconnaissance",       "HIGH"),
    "sharphound":           ("SharpHound AD enumeration",          "HIGH"),
    "rubeus":               ("Rubeus (Kerberos tool)",             "HIGH"),
    "kerberoast":           ("Kerberoasting tool",                 "HIGH"),
    "cobaltstrike":         ("Cobalt Strike beacon",               "CRITICAL"),
    "metasploit":           ("Metasploit framework",               "HIGH"),
    "msfvenom":             ("msfvenom payload generator",         "CRITICAL"),
    "empire":               ("PowerShell Empire C2",               "CRITICAL"),
    "covenant":             ("Covenant C2",                        "CRITICAL"),
    "sliver":               ("Sliver C2",                          "CRITICAL"),
    "havoc":                ("Havoc C2",                           "CRITICAL"),
    "winpeas":              ("WinPEAS privilege enum",             "HIGH"),
    "linpeas":              ("LinPEAS (cross-platform)",           "MEDIUM"),
    "seatbelt":             ("Seatbelt host recon",                "HIGH"),
    "sharpup":              ("SharpUp privilege enum",             "HIGH"),
    "watson":               ("Watson missing-patch enum",          "MEDIUM"),
    "hashcat":              ("Hashcat password cracker",           "MEDIUM"),
    "john.exe":             ("John the Ripper",                    "MEDIUM"),
    "wifite":               ("Wifite (wireless attack)",           "MEDIUM"),
    "responder":            ("Responder LLMNR poisoner",           "HIGH"),
    "inveigh":              ("Inveigh LLMNR poisoner",             "HIGH"),
    "impacket":             ("Impacket toolkit",                   "HIGH"),
    "ntlmrelayx":           ("NTLM relay attack",                  "CRITICAL"),
    "smbexec":              ("SMBexec lateral movement",           "HIGH"),
    "wmiexec":              ("WMIexec lateral movement",           "HIGH"),
    "atexec":               ("AtExec lateral movement",            "HIGH"),
    "secretsdump":          ("Impacket secretsdump",               "CRITICAL"),
    "process hacker":       ("Process Hacker (often abused)",      "LOW"),
    "processhacker":        ("Process Hacker",                     "LOW"),
    "sysinternals":         ("Sysinternals (legit but check)",     "INFO"),
    "advanced ip scanner":  ("Advanced IP Scanner (recon)",        "MEDIUM"),
    "angryipscanner":       ("Angry IP Scanner (recon)",           "MEDIUM"),
    "nmap":                 ("Nmap port scanner",                  "MEDIUM"),
    "zenmap":               ("Zenmap (Nmap GUI)",                  "MEDIUM"),
    "nirsoft":              ("NirSoft tools (browser/wifi pwd)",   "MEDIUM"),
    "webbrowserpassview":   ("WebBrowserPassView",                 "HIGH"),
    "wirelesskeyview":      ("WirelessKeyView",                    "HIGH"),
    "lsass.dmp":            ("LSASS process dump (cred theft)",    "CRITICAL"),
    "wce.exe":              ("Windows Credential Editor",          "CRITICAL"),
    "fgdump":               ("fgdump credential extractor",        "CRITICAL"),
    "pwdump":               ("pwdump credential extractor",        "CRITICAL"),

    # ── 2024-2025 IR engagement frequents ─────────────────────────────────
    "chisel":               ("Chisel reverse-tunnel (C2 alt)",     "CRITICAL"),
    "frpc":                 ("FRP fast-reverse-proxy (C2 tunnel)", "CRITICAL"),
    "frps":                 ("FRP server side",                    "HIGH"),
    "ligolo":               ("ligolo-ng SOCKS proxy (post-exploit)","CRITICAL"),
    "ligolo-ng":            ("ligolo-ng SOCKS proxy",              "CRITICAL"),
    "kerbrute":             ("Kerberos brute-forcer",              "HIGH"),
    "adrecon":              ("Active Directory recon",             "HIGH"),
    "pspy":                 ("pspy process spy",                   "HIGH"),
    "rclone":               ("rclone (cloud-sync abuse for exfil)","HIGH"),
    "megacmd":              ("MEGAcmd (cloud sync to MEGA.nz)",    "HIGH"),
    "anydesk":              ("AnyDesk remote-access (often abused)","MEDIUM"),
    "teamviewer":           ("TeamViewer (often abused)",          "LOW"),
    "screenconnect":        ("ScreenConnect / ConnectWise",        "MEDIUM"),
    "ngrok":                ("ngrok tunnelling",                   "HIGH"),
    "cloudflared":          ("Cloudflared tunnel",                 "MEDIUM"),
    "iox":                  ("iox port-forwarding",                "HIGH"),
    "stowaway":             ("Stowaway multi-hop proxy",           "HIGH"),
    "sliverc2":             ("Sliver C2 alias",                    "CRITICAL"),
    "havocc2":              ("Havoc C2 alias",                     "CRITICAL"),
    "brc4":                 ("Brute Ratel C2",                     "CRITICAL"),
    "brute ratel":          ("Brute Ratel C2",                     "CRITICAL"),
    "nighthawk":             ("Nighthawk C2",                      "CRITICAL"),
    "qakbot":               ("QakBot loader",                      "CRITICAL"),
    "icedid":               ("IcedID loader",                      "CRITICAL"),
    "emotet":               ("Emotet loader",                      "CRITICAL"),
    "trickbot":             ("TrickBot",                           "CRITICAL"),
    "raspberry robin":      ("Raspberry Robin worm",               "CRITICAL"),
    "akira":                ("Akira ransomware",                   "CRITICAL"),
    "blackcat":             ("BlackCat / ALPHV ransomware",        "CRITICAL"),
    "lockbit":              ("LockBit ransomware",                 "CRITICAL"),
    "blackbasta":           ("Black Basta ransomware",             "CRITICAL"),
    "playransom":           ("Play ransomware",                    "CRITICAL"),
    # Living-off-the-land binaries commonly abused
    "certutil":             ("certutil.exe (LOLBin — file download)","INFO"),
    "bitsadmin":            ("bitsadmin.exe (LOLBin — file download)","INFO"),
    "regsvr32":             ("regsvr32.exe (LOLBin — script proxy)","INFO"),
    "mshta":                ("mshta.exe (LOLBin — HTA proxy)",     "INFO"),
    "rundll32":             ("rundll32.exe (LOLBin — DLL exec)",   "INFO"),
}

# ── Archive / compression tools (relevant to staging exfil data) ───────────
KNOWN_ARCHIVERS = {
    "7z.exe":               "7-Zip",
    "7za.exe":              "7-Zip standalone",
    "winrar.exe":           "WinRAR",
    "rar.exe":              "RAR command-line",
    "winzip.exe":           "WinZip",
    "tar.exe":              "tar",
}

# ── Tor and anonymizer binaries ─────────────────────────────────────────────
KNOWN_TOR_BINARIES = {
    "tor.exe":              "Tor daemon",
    "torbrowser.exe":       "Tor Browser",
    "firefox.exe":          "Firefox (Tor bundle uses this)",  # weak signal alone
}

# ── Removable-media indicators (USB / external drives) ─────────────────────
USB_REGISTRY_KEYS_HINT = (
    r"SYSTEM\CurrentControlSet\Enum\USB",
    r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
    r"SOFTWARE\Microsoft\Windows Portable Devices",
)

# ── Investigation-prompt → focus areas (keyword extraction) ─────────────────
PROMPT_FOCUS_KEYWORDS = {
    "usb_exfil": [
        "usb", "removable", "external drive", "thumbdrive", "thumb drive",
        "external storage", "exfiltrat", "data theft", "data leak", "copied",
        "transferred", "stolen data", "stick",
    ],
    "cloud_upload": [
        "cloud", "upload", "drive.google", "dropbox", "onedrive",
        "icloud", "mega", "wetransfer", "shared link",
    ],
    "fileshare_upload": [
        "wetransfer", "anonfiles", "fileshar", "file shar", "pastebin", "we.tl",
        "ghostbin", "transfer.sh", "anonymous upload",
    ],
    "credential_theft": [
        "credential", "password", "lsass", "mimikatz", "lazagne", "kerberoast",
        "ntlm", "hash dump", "secretsdump",
    ],
    "lateral_movement": [
        "lateral", "psexec", "wmiexec", "rdp", "smb", "remote", "remoting",
        "winrm", "pivot",
    ],
    "persistence": [
        "persisten", "scheduled task", "service", "autorun", "registry run",
        "startup", "rootkit",
    ],
    "ransomware": [
        "ransom", "encryp", "cryptolocker", "lockbit", "blackcat", ".locked",
        "decrypt", "bitcoin",
    ],
    "data_destruction": [
        "wipe", "delete", "destroy", "shred", "anti-forensic", "log clear",
    ],
    "phishing": [
        "phish", "malicious email", "macro", "lure", "spear",
    ],
    "tor_anonymizer": [
        "tor", "onion", "anonymous", "vpn", "proxy", "anonymiz",
    ],
}
