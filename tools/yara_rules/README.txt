YARA rules directory
====================

Drop YARA rule files here (.yar / .yara) — they are compiled and applied to
binaries located during a malware-profile investigation, plus any sample
directories you specify.

  * Each rule file is compiled independently, so one broken file will not
    disable the rest of the set.
  * Subdirectories are searched recursively.
  * Additional rule files/folders can also be supplied per-case via the
    "Custom YARA rule files or folders" field (malware profile) or the
    CLI --yara-rules flag.

Good free rule sources:
  * https://github.com/Yara-Rules/rules
  * https://github.com/Neo23x0/signature-base  (Florian Roth)
  * https://github.com/elastic/protections-artifacts

capa.exe (Mandiant FLARE) is a separate tool — place capa.exe in the parent
tools/ directory to enable capability + ATT&CK analysis of located binaries.
