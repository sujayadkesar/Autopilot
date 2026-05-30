# DFIR Automation — Claude Code Guide

## Project Overview
Unified DFIR tool: GUI (PySide6) + CLI (Click) that runs pluggable forensic agents against a mounted Windows drive image. **AI is OPTIONAL** — by default the tool runs in fully-deterministic, evidence-cited automation mode using a curated indicator engine (`core/investigation/`). AI augmentation can be enabled to add narrative-style reports on top.

## Operating Modes
- **Deterministic (default)**: Extract → parse → rule-based investigation → Formal Investigation Report. Fast, reproducible, no hallucinations. Cites concrete evidence rows.
- **AI-augmented (optional)**: Additionally runs LLM analysis to produce AI Technical and AI Investigation reports. Slow on CPU (30–60+ min). Enable with `--enable-ai` (CLI) or the "Enable AI analysis" checkbox (GUI).

## Key Architecture
- `core/` — shared infrastructure (base agent, LLM client, tool runner, progress bus, report builder)
- `agents/<name>/` — one folder per forensic agent; auto-discovered on startup via `manifest.yaml`
- `orchestrator.py` — pipeline: extract → parse → analyze → report, all agents, parallel
- `cli.py` — Click CLI; same inputs as GUI
- `gui/` — PySide6 GUI; all heavy work on QThread/ThreadPoolExecutor, never on main thread
- `main.py` — `python main.py` → GUI; `python main.py cli ...` → CLI

## Tools Directory
Fixed at `<repo_root>/tools/`. No user input. User drops EZ Tools binaries here.
Also supported (optional): `capa.exe` (Mandiant FLARE — malware capability + ATT&CK),
`tools/yara_rules/` (YARA .yar/.yara rules), `WxTCmd.exe` (Windows Timeline),
`hayabusa.exe` (Sigma hunting — run `hayabusa update-rules` once).

## Python extras (optional, graceful-degradation)
- `playwright` + `playwright install chromium` — PDF reports + rasterized evidence-exhibit
  screenshots. Without it, HTML still renders.
- `yara-python` — YARA scanning in the malware profile.

## Malware Profile Workflow
Inputs (Setup fields / CLI): malicious filenames, known-bad hashes (MD5/SHA1/SHA256),
C2 domains/IPs, malware family names, extra sample dirs, custom YARA rules. Pipeline:
hash/name → match Amcache (+ on-disk hashing) → locate binary on image → run capa
(capabilities + ATT&CK) and YARA → evidence-cited findings. CLI flags:
`--malware-hashes-file`, `--yara-rules`, `--sample-dir`, `--run-capa/--no-capa`,
`--run-yara/--no-yara`, `--report-format html,pdf`. Code: `core/malware/`.

## Deterministic Analysis Layers (no AI)
- `core/eventlog/` — EventHawk-style: PowerShell 4104 reassembly + deobfuscation,
  process-ancestry chains, logon-session anomalies, IOC extraction, event-ID→ATT&CK.
- `core/investigation/_artifact_scans.py` — Recycle Bin ($I), Shellbags, WMI persistence,
  NTFS ADS, BAM/DAM, Windows Timeline.
- Findings carry ATT&CK tags; report exports `reports/attack_navigator.json` (Navigator
  layer) and `reports/ioc_rollup.json`.

## Reporting (evidence-grade)
`core/render/` (Playwright) rasterizes each evidence snippet into an authentic tool
"exhibit" screenshot (regedit / Event Viewer / file-table look-alike) with the relevant
cell highlighted, embeds them in the report, and prints a PDF. Toggle via
`--report-format html,pdf` (CLI) or the "Generate PDF report" checkbox (GUI).

## Output Layout
```
output/
├── artifacts/<agent>/          # raw copies
├── parsed_artifacts/<agent>/   # EZ Tools / python parser CSVs & JSONLs
└── reports/                    # per-agent HTML + final_forensic_report.html
```

## Adding a New Agent
1. Copy `agents/_template/` to `agents/<your_name>/`
2. Edit `manifest.yaml` (name, display_name, description)
3. Implement `extract()` and `parse()` in `agent.py` (inherits defaults for `analyze` and `report`)
4. Drop-in — no changes to core/ or gui/

## Running
```bash
pip install -r requirements.txt
python main.py                    # GUI (AI off by default — toggle in Setup)
python main.py cli --help         # CLI help
python main.py doctor             # environment check (AI is optional)

# CLI examples:
python main.py cli -d F:\ -o ./case01 --customer "Acme"          # deterministic (default)
python main.py cli -d F:\ -o ./case01 --customer "Acme" --enable-ai \
                  --model ollama:phi3:mini                       # with AI
```

## Reports Produced
- `reports/raw_evidence_report.html` — quick post-parse evidence dump
- `reports/formal_investigation_report.html` — **deterministic, evidence-cited (always)**
- `reports/final_forensic_report.html` — AI technical (only when `--enable-ai`)
- `reports/investigation_report.html` — AI narrative (only when `--enable-ai`)

## LLM Model Format (only when AI is enabled)
`ollama:<model>` — e.g. `ollama:phi3:mini`, `ollama:llama3:8b`, `ollama:qwen2.5:7b`

## GUI Threading Rules
- **Never** block the Qt event loop. All disk/subprocess/LLM calls go on QThread or pool.
- Log view: `QPlainTextEdit` with `setMaximumBlockCount(50000)`.
- Progress: emit signals from worker thread, receive in main thread slot.
