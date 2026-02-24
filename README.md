# 🛡️ Sentinel Activity Viewer v4.2 — Forensic Maling Catcher

## Zero Escape Architecture | 37 Categories | 100% Detection Target

### What's New in v4.2

**Architecture:**
- Triple Injection System (CDP + addInitScript + per-target)
- Adaptive Timeout: 60s default → up to 120s with automatic extension
- Enhanced Deduplication: multi-factor key with 50ms sliding window
- Final Flush + Grace Period: no events lost at scan end

**Detection:**
- 37 detection categories (31 fixed + 6 new)
- WebAssembly fingerprinting detection (9 API hooks)
- Keyboard Layout API detection (6 API hooks)
- Device Sensor API detection (11 API hooks)
- Visualization/GPU probing detection (7 API hooks)
- Device Info harvesting detection (8 API hooks)
- Enhanced Clipboard detection (7 API hooks)

**Bug Fixes:**
- [BUG-01] hookFn parameter order fixed — category/risk no longer swapped
- [BUG-02] All 37 categories produce events (14 ghost hooks fixed)
- [BUG-03/10] hashStr full FNV-1a incremental (no truncation)
- [BUG-04] Timeout 30s → 60s default
- [BUG-05] Dedup key enhanced with argHash + seqCounter
- [BUG-06] Cross-origin iframe injection via CDP Target.setAutoAttach
- [BUG-07] Final flush mechanism before browser close
- [BUG-08] Worker content monitoring
- [BUG-09] Anti-detection shield WeakMap + freeze
- [BUG-10] hashStr processes entire string

**Stealth:**
- CreepJS lie detection countermeasures
- CDP detection cleanup
- Error.stack sanitization (removes Sentinel frames)
- WebGL vendor/renderer consistency

**Analysis:**
- Cross-category correlation (FPv5 41-source sequence matching)
- Temporal slow-probe detection
- Worker event correlation
- Cross-frame fingerprinting detection
- Coverage matrix in reports

### Installation

```bash
npm install
```

### Usage

```bash
# Quick scan (stealth mode, default)
node index.js https://browserscan.net

# Observe mode (no stealth plugins)
node index.js https://browserscan.net --observe

# Dual mode (compare stealth vs observe)
node index.js https://browserscan.net --dual-mode

# Custom timeout
node index.js https://browserscan.net --timeout=90000

# Headless mode
node index.js https://browserscan.net --headless

# Full options
node index.js https://example.com --stealth --timeout=60000 --headless --cdp
```

### Output

Reports are saved to `./output/` directory:
- `sentinel_*_report.json` — Full forensic data
- `sentinel_*_report.html` — Interactive dashboard
- `sentinel_*_context.json` — Frame context map

### Architecture

```
Layer 1: CDP Injection (Page.addScriptToEvaluateOnNewDocument)
Layer 2: addInitScript Backup  
Layer 3: Per-Target CDP (cross-origin iframes + workers)
Layer 4: Anti-Detection Shield (toString, descriptors, stack sanitization)
Layer 5: Core + Extended Hooks (37 categories, tiered value capture)
Layer 6: Behavior Correlation (bursts, slow-probes, cross-category, attribution)
Layer 7: 1H5W Forensic Reporting (JSON + HTML dashboard)
```

### File Structure

```
sentinel_v42/
├── index.js                          # Main orchestrator
├── package.json                      # Dependencies
├── README.md                         # This file
├── hooks/
│   ├── api-interceptor.js            # 37-category forensic hooks
│   ├── anti-detection-shield.js      # WeakMap-based stealth shield
│   └── stealth-config.js             # CreepJS countermeasures
├── lib/
│   ├── correlation-engine.js         # Behavior analysis engine
│   └── signature-db.js               # FPv5/CreepJS/WASM signatures
├── reporters/
│   └── report-generator.js           # 1H5W report generator
└── output/                           # Generated reports
```

### Detection Coverage

- **FingerprintJS v5**: 41/41 entropy sources covered
- **CreepJS**: 40/40 categories covered  
- **WebAssembly FP**: Full coverage (compile, instantiate, Memory, Table)
- **Cross-origin iframes**: CDP auto-attach coverage
- **Web Workers**: Constructor interception + CDP attachment

### Version

v4.2.0 — Zero Escape Architecture
