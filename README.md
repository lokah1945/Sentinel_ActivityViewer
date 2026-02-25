# 🛡️ Sentinel v4.6 — Ghost Protocol Forensic Catcher

> "Ibaratnya maling yang stealth, kita lebih stealth lagi"

## What's New in v4.6

### Key Improvements over v4.5
| Feature | v4.5 | v4.6 |
|---------|------|------|
| Sub-frame monitoring | 0 checked | Recursive auto-attach (ALL nested iframes) |
| Worker events | 0 captured | Full worker pipeline (dedicated/shared/service) |
| about:blank handling | Skip all | Smart triage (check for scripts before skipping) |
| Global visibility | `__SENTINEL_*` enumerable | Non-enumerable (Quiet Mode) |
| HTML report | `vc is not defined` bug | Fixed + Target Graph Inventory |
| Categories | 37 | 42 (Blob URL, SharedArrayBuffer, performance.now, postMessage, message listener) |
| Injection layers | L1-L4 | L1-L6 (+ recursive auto-attach + worker pipeline) |
| Console output | Sentinel logs visible | Ghost Protocol (zero sentinel console output) |
| Chrome polyfill | Basic chrome.runtime | + chrome.csi + chrome.loadTimes + plugins |

### Architecture
```
index.js                    — Main orchestrator (8-step pipeline)
├── hooks/
│   ├── anti-detection-shield.js  — Function.toString + descriptor protection
│   ├── stealth-config.js         — Ghost Protocol automation cleanup
│   └── api-interceptor.js        — 42 categories, 220+ hooks
├── lib/
│   ├── target-graph.js           — NEW: Recursive auto-attach orchestrator
│   ├── correlation-engine.js     — Burst/slow-probe/cross-frame detection
│   └── signature-db.js           — FingerprintJS/CreepJS pattern matching
└── reporters/
    └── report-generator.js       — JSON + HTML + Context reports
```

## Installation
```bash
npm install
```

## Usage
```bash
# Quick scan
node index.js https://www.browserscan.net

# Show browser window
node index.js https://www.browserscan.net --no-headless

# Custom timeout
node index.js https://www.browserscan.net --timeout=45000

# Dual mode (observe vs stealth comparison)
node index.js https://www.browserscan.net --dual-mode

# Observe only (no automation cleanup)
node index.js https://www.browserscan.net --observe

# Verbose (show target graph debug info)
node index.js https://www.browserscan.net --verbose
```

## Run Tests
```bash
node test-injection.js
```

## Zero Spoofing Philosophy
Sentinel v4.6 does NOT spoof anything:
- ❌ No fake User-Agent
- ❌ No fake locale/timezone
- ❌ No fake plugins/WebGL
- ❌ No fake screen resolution
- ✅ Only removes automation markers (navigator.webdriver, __playwright)
- ✅ Adds chrome.runtime polyfill (real Chrome always has it)
- ✅ Non-enumerable globals (scripts can't easily find us)

## Ghost Protocol
v4.6 "Ghost Protocol" means:
1. **No console.log** from sentinel code (scripts can't detect us via console monitoring)
2. **Non-enumerable globals** (`Object.keys(window)` won't show sentinel variables)
3. **Persistent context** (not flagged as incognito)
4. **Zero spoofing** (no fingerprint mismatches to trigger bot detection)
5. **Comprehensive polyfills** (chrome.runtime, chrome.csi, chrome.loadTimes, plugins)

## License
MIT
