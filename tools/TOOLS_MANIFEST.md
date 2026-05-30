# Tools Directory Manifest

Drop these binaries directly into this `tools/` folder (no subdirectories needed).
The pipeline auto-detects which tools are present and skips agents whose tools
are missing — so partial installs work fine.

---

## Required for full agent coverage

### Eric Zimmerman's EZ Tools
Download from: https://ericzimmerman.github.io/

| Filename | Used by agent | Forensic value |
|---|---|---|
| `MFTECmd.exe` | prefetch_amcache_mft, usn_lnk_mru | $MFT records + USN Journal parsing |
| `AmcacheParser.exe` | prefetch_amcache_mft | Amcache.hve — every binary's SHA1 + first-seen timestamp |
| `PECmd.exe` | prefetch_amcache_mft | Prefetch (.pf) execution evidence |
| `SrumECmd.exe` | prefetch_amcache_mft | SRUDB.dat — process-level network byte counts |
| `RECmd.exe` | usn_lnk_mru | MRU registry hive parsing |
| `LECmd.exe` | usn_lnk_mru | LNK shortcuts in Recent\ |
| `EvtxECmd.exe` | event_logs | Windows event logs (Security, System, etc.) |
| `SBECmd.exe` | shellbags | Shellbags — folder browsing including USB/network paths |
| `JLECmd.exe` | (optional) | Jump Lists full parse (App ID + recent files) |
| `WxTCmd.exe` | (optional) | Windows 10 ActivitiesCache.db |
| `AppCompatCacheParser.exe` | (optional) | ShimCache program execution evidence |

Also drop the **RECmd batch file** `DFIRBatch.reb` (or `RECmd_Batch_MC.reb`) into
`tools/` or `tools/BatchExamples/` — without it RECmd doesn't know what to extract.

---

## Threat-Hunting (highly recommended)

### Hayabusa
Download from: https://github.com/Yamato-Security/hayabusa/releases

| Filename | Used by agent | Forensic value |
|---|---|---|
| `hayabusa.exe` | event_logs | Sigma-rule threat hunt across all parsed EVTX |

After dropping `hayabusa.exe`, run `hayabusa update-rules` once to fetch the
public Sigma rule pack. The pipeline will use whatever rules are present.

### Chainsaw (alternative to Hayabusa)
Download from: https://github.com/WithSecureLabs/chainsaw/releases

| Filename | Used by agent | Forensic value |
|---|---|---|
| `chainsaw.exe` | event_logs (alt) | Sigma + custom-rule event log hunting |

---

## Browser History

**No tool required** — the pipeline now uses native Python `sqlite3` to parse
Chrome / Edge `History`, `Cookies`, `Login Data` directly. The old Hindsight
dependency is gone.

If you still want Hindsight's xlsx output (cosmetic only), drop:

| Filename | Used by | Notes |
|---|---|---|
| `hindsight.exe` | (legacy) | Replaced by native parser; not required |

---

## Quick-install one-liner

After downloading the EZ Tools archive from https://ericzimmerman.github.io/,
extract everything to `tools/`. The auto-discovery accepts a flat dump.

For Hayabusa, download the latest release ZIP, extract, and copy `hayabusa.exe`
plus the `rules/` directory to `tools/`. Run `hayabusa update-rules` once.

---

## What runs without ANY tool

These agents work with pure Python and the Windows `esentutl.exe` (built in):

- **registry** (uses `python-registry` library)
- **pca_jumplists_wer** (Program Compatibility Assistant, Scheduled Task XML, WER, Jump Lists summary)
- **usn_lnk_mru** browsers sub-module (native Python sqlite3)

So you get meaningful output even with an empty `tools/` directory — the
deterministic investigation engine and comprehensive evidence report still work.

---

## Verify your setup

Run the doctor command:

```
python main.py doctor
```

It reports which tools are present and which are missing.
