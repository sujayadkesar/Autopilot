# tools/ — EZ Tools Binaries

Place the following executables in this directory:

| Filename | Used by | Download |
|---|---|---|
| `MFTECmd.exe` | prefetch_amcache_mft, usn_lnk_mru | https://ericzimmerman.github.io |
| `AmcacheParser.exe` | prefetch_amcache_mft | https://ericzimmerman.github.io |
| `PECmd.exe` | prefetch_amcache_mft | https://ericzimmerman.github.io |
| `SrumECmd.exe` | prefetch_amcache_mft | https://ericzimmerman.github.io |
| `RECmd.exe` | usn_lnk_mru | https://ericzimmerman.github.io |
| `LECmd.exe` | usn_lnk_mru | https://ericzimmerman.github.io |
| `EvtxECmd.exe` | event_logs (future) | https://ericzimmerman.github.io |
| `hindsight.exe` | usn_lnk_mru (browsers) | https://github.com/obsidianforensics/hindsight |

## RECmd Batch Files

Place batch files in `tools/BatchExamples/` (or directly in `tools/`):

- `DFIRBatch.reb` — preferred
- `RECmd_Batch_MC.reb` — fallback

Download from: https://github.com/EricZimmerman/RECmd/tree/master/BatchExamples

## Quick download (all EZ Tools)

```powershell
# Via EZToolsAvalonia or Get-ZimmermanTools:
iwr -useb https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1 | iex
```
Move the downloaded `.exe` files into this `tools/` folder.

## Directory structure after setup

```
tools/
├── MFTECmd.exe
├── AmcacheParser.exe
├── PECmd.exe
├── SrumECmd.exe
├── RECmd.exe
├── LECmd.exe
├── EvtxECmd.exe
├── hindsight.exe
└── BatchExamples/
    ├── DFIRBatch.reb
    └── RECmd_Batch_MC.reb
```
