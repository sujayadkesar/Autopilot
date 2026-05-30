# Writing a New DFIR Agent

This guide walks you through adding a new forensic agent — from zero to running in the GUI — **without touching any core files**.

## What is an Agent?

Each agent is a self-contained Python folder under `agents/<name>/` that:
1. **Extracts** raw artifacts from a mounted Windows drive
2. **Parses** them (using EZ Tools or Python parsers) into CSVs/JSONLs
3. **Analyzes** the parsed data with the local LLM (automatic unless you override)
4. **Reports** findings as an HTML section (automatic unless you override)

## Quick Start (5 minutes)

### 1. Copy the template

```powershell
Copy-Item -Recurse agents/_template agents/event_logs
```

### 2. Edit `manifest.yaml`

```yaml
# agents/event_logs/manifest.yaml
name: event_logs
display_name: Windows Event Logs
description: >
  Extracts Security, System, Application, and Sysmon event logs (.evtx),
  parses them with EvtxECmd into CSV, then sends to AI for analysis.
version: "1.0"
enabled_by_default: false
artifact_subdirs:
  - security
  - system
  - application
  - sysmon
```

### 3. Implement `agent.py`

```python
# agents/event_logs/agent.py
from __future__ import annotations
import shutil, time
from pathlib import Path
from typing import List
from core.base_agent import BaseAgent, ExtractResult, ParseResult
from core.case_context import CaseContext
from core.progress_bus import ProgressBus
from core.tool_runner import ExecutionError, ToolNotFoundError, ToolRunner

EVTX_TARGETS = {
    "security":    "Windows/System32/winevt/Logs/Security.evtx",
    "system":      "Windows/System32/winevt/Logs/System.evtx",
    "application": "Windows/System32/winevt/Logs/Application.evtx",
    "sysmon":      "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
}

class Agent(BaseAgent):
    name = "event_logs"
    display_name = "Windows Event Logs"
    description = "Security, System, Application, Sysmon EVTX → CSV via EvtxECmd"
    version = "1.0"
    artifact_subdirs = list(EVTX_TARGETS.keys())

    def extract(self, ctx: CaseContext, progress: ProgressBus) -> ExtractResult:
        progress.stage_started(self.name, "extract")
        t0 = time.time()
        copied: List[Path] = []
        for subdir, rel in EVTX_TARGETS.items():
            src = ctx.mount_point / rel.replace("/", "\\")
            if src.exists():
                dest_dir = ctx.agent_artifacts_dir(self.name) / subdir
                dest_dir.mkdir(parents=True, exist_ok=True)
                dst = dest_dir / src.name
                shutil.copy2(str(src), str(dst))
                copied.append(dst)
                progress.log("INFO", self.name, f"Copied {src.name}")
        progress.stage_done(self.name, "extract")
        return ExtractResult(self.name, success=bool(copied), artifacts=copied, elapsed=time.time()-t0)

    def parse(self, ctx: CaseContext, extract_result: ExtractResult, progress: ProgressBus) -> ParseResult:
        progress.stage_started(self.name, "parse")
        t0 = time.time()
        runner = ToolRunner(ctx.tools_dir)
        out_dir = ctx.agent_parsed_dir(self.name)
        out_dir.mkdir(parents=True, exist_ok=True)
        output_files: List[Path] = []
        try:
            exe = runner.resolve("evtxecmd")
            art_base = ctx.agent_artifacts_dir(self.name)
            for subdir in self.artifact_subdirs:
                evtx_dir = art_base / subdir
                if not evtx_dir.exists():
                    continue
                sub_out = out_dir / subdir
                sub_out.mkdir(parents=True, exist_ok=True)
                runner.run([str(exe), "-d", str(evtx_dir), "--csv", str(sub_out)],
                           f"EvtxECmd_{subdir}", timeout=300)
                output_files.extend(sub_out.glob("*.csv"))
        except ToolNotFoundError as e:
            progress.log("WARNING", self.name, f"EvtxECmd not found: {e}")
        except ExecutionError as e:
            progress.log("ERROR", self.name, f"Parse error: {e}")
        progress.stage_done(self.name, "parse")
        return ParseResult(self.name, success=bool(output_files), output_files=output_files, elapsed=time.time()-t0)
    # analyze() and report() use defaults — no code needed!
```

### 4. Drop `EvtxECmd.exe` into `tools/`

That's it. Launch the app — your new agent appears as a card.

---

## The Contribution Contract

| Method | Required | What it does |
|---|---|---|
| `extract()` | **Yes** | Copy raw artifacts from `ctx.mount_point` → `ctx.agent_artifacts_dir(self.name)/` |
| `parse()` | **Yes** | Run EZ Tools / parsers → `ctx.agent_parsed_dir(self.name)/` as CSVs |
| `analyze()` | Optional | Default: send every CSV/JSON to LLM with case prompt. Override for custom prompting. |
| `report()` | Optional | Default: render dark-mode HTML via Jinja2 template. Override for custom layout. |

## CaseContext Reference

```python
ctx.mount_point          # Path — mounted Windows drive (e.g. E:\)
ctx.output_dir           # Path — user-specified output folder
ctx.artifacts_dir        # Path — output/artifacts/
ctx.parsed_dir           # Path — output/parsed_artifacts/
ctx.reports_dir          # Path — output/reports/
ctx.tools_dir            # Path — <repo>/tools/ (hardcoded)
ctx.workers              # int  — os.cpu_count()
ctx.llm_model            # str  — "ollama:phi3:mini"
ctx.customer_name        # str
ctx.investigation_date   # date
ctx.case_reference       # str  — auto-generated
ctx.investigation_prompt # str  — the investigator's case prompt

# Convenience helpers (create dirs if needed):
ctx.agent_artifacts_dir(self.name)  # output/artifacts/<name>/
ctx.agent_parsed_dir(self.name)     # output/parsed_artifacts/<name>/
```

## ProgressBus Reference

```python
progress.stage_started(agent, stage)           # stage ∈ extract|parse|analyze|report
progress.stage_progress(agent, stage, pct, msg)
progress.stage_done(agent, stage)
progress.stage_error(agent, stage, error_msg)
progress.finding_added(agent, count, severity)
progress.log(level, agent, message)            # level ∈ DEBUG|INFO|WARNING|ERROR
```

## ToolRunner Reference

```python
runner = ToolRunner(ctx.tools_dir)
exe = runner.resolve("mftecmd")    # raises ToolNotFoundError if missing
exe = runner.resolve("amcacheparser")
exe = runner.resolve("pecmd")
exe = runner.resolve("srumecmd")
exe = runner.resolve("recmd")
exe = runner.resolve("lecmd")
exe = runner.resolve("evtxecmd")
exe = runner.resolve("hindsight")

rc, stdout, stderr = runner.run(
    cmd=[str(exe), "-f", str(input), "--csv", str(out)],
    artifact_name="MyLabel",
    timeout=300,
    expected_outputs=[out / "result.csv"],  # validates output was created
)

batch = runner.resolve_recmd_batch()   # finds DFIRBatch.reb or RECmd_Batch_MC.reb
```

## Folder Layout

```
agents/
└── event_logs/
    ├── __init__.py        # empty
    ├── manifest.yaml      # name, display_name, description, version, enabled_by_default
    └── agent.py           # class Agent(BaseAgent)
```

## Testing your agent

```bash
# Doctor check (tools present, Ollama reachable):
python main.py doctor

# Run only your new agent:
python main.py cli --drive E:\ --output ./test_out --model ollama:phi3:mini \
  --agents event_logs --prompt "Test investigation"

# Verify outputs:
ls test_out/artifacts/event_logs/
ls test_out/parsed_artifacts/event_logs/
ls test_out/reports/
```

The litmus test: your agent produces its report **without any change to core/ or gui/**.
