# DFIR Automation

Unified Windows forensics tool — **GUI** (PySide6) + **CLI** (Click) with pluggable agents and local LLM analysis.

## What it does

1. **Extracts** raw Windows artifacts from a mounted drive image (registry hives, $MFT, prefetch, USN journal, LNK files, browser history)
2. **Parses** them via EZ Tools (MFTECmd, AmcacheParser, PECmd, SrumECmd, RECmd, LECmd, Hindsight)
3. **Analyses** every parsed CSV/JSON with a local LLM (Ollama) using your case prompt as context
4. **Reports** per-agent HTML reports + a final combined forensic report with cover page, TOC, executive summary, IOC roll-up, timeline, and evidence tables

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Place EZ Tools in tools/ (see tools/README.md)

# 3. Start Ollama and pull a model
ollama serve
ollama pull phi3:mini

# 4. Launch GUI
python main.py

# 5. Or use CLI
python main.py cli \
  --drive E:\ \
  --output D:\Cases\Acme-2026 \
  --model ollama:phi3:mini \
  --customer "Acme Corp" \
  --prompt "Suspected USB exfiltration by departing employee. Investigate USB activity, recent files, archive tools."

# 6. Check environment
python main.py doctor
```

## GUI Inputs

| Field | Example |
|---|---|
| Customer name | Acme Corporation |
| Investigation date | 2026-04-26 |
| Mounted drive | E:\ |
| Output folder | D:\Cases\Acme-2026 |
| Local LLM model | `ollama:phi3:mini` |
| Investigation prompt | Case background + angles to investigate |

**Workers** are automatically set to max CPU cores.
**Tools directory** is fixed at `<repo>/tools/` — no input needed.

## Output Structure

```
output/
├── artifacts/                    # raw evidence files
│   ├── registry/
│   ├── prefetch_amcache_mft/
│   └── usn_lnk_mru/
├── parsed_artifacts/             # EZ Tools CSV output
│   ├── registry/
│   ├── prefetch_amcache_mft/
│   └── usn_lnk_mru/
├── reports/
│   ├── registry_report.html
│   ├── prefetch_amcache_mft_report.html
│   ├── usn_lnk_mru_report.html
│   └── final_forensic_report.html   ← the deliverable
├── findings.jsonl
├── manifest.json
└── pipeline.log
```

## Adding a New Agent

See [docs/AGENT_GUIDE.md](docs/AGENT_GUIDE.md). In short:

1. Copy `agents/_template/` → `agents/<your_name>/`
2. Edit `manifest.yaml`
3. Implement `extract()` and `parse()` in `agent.py`
4. Drop-in — appears in GUI automatically. No core changes needed.

## Available Agents

| Agent | Artifacts | Tools |
|---|---|---|
| `registry` | SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER, USRCLASS, Amcache | python-registry |
| `prefetch_amcache_mft` | $MFT, Amcache.hve, Prefetch, SRUDB | MFTECmd, AmcacheParser, PECmd, SrumECmd |
| `usn_lnk_mru` | USN Journal, LNK, MRU, Browser history | MFTECmd, RECmd, LECmd, Hindsight |

## LLM Model Format

`ollama:<model>` — prefix selects the backend (Ollama only in v1).

Examples: `ollama:phi3:mini`  `ollama:llama3:8b`  `ollama:qwen2.5:7b`  `ollama:mistral:7b`

## Dependencies

```
PySide6 PySide6-Addons python-registry requests rich click jinja2 pyyaml pydantic
```

## Architecture

```
core/         shared infrastructure (base_agent, llm_client, tool_runner, progress_bus, report/)
agents/       one folder per agent; auto-discovered via manifest.yaml
orchestrator  pipeline: extract → parse → analyze → report (parallel)
cli.py        Click CLI
gui/          PySide6 GUI (zero blocking on main thread)
main.py       single entry: GUI by default, CLI with subcommand
```
