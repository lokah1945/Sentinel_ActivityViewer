# 🛡️ Sentinel v4.1 — Forensic Maling Catcher

**7-Layer Architecture | 31 API Categories | 1H5W Framework**

Detects and forensically analyzes fingerprinting scripts on any website.

## What's Fixed in v4.1 (from v4.0)

v4.0 captured **0 events** in both stealth and observe modes due to cascading failures in the injection pipeline. v4.1 fixes all root causes:

| Bug | v4.0 Problem | v4.1 Fix |
|-----|-------------|----------|
| **Script injection** | CDP `Page.addScriptToEvaluateOnNewDocument` without `Page.enable` | Uses `page.addInitScript()` as primary (proven in v3) |
| **Shield crash** | `Object.getOwnPropertyDescriptor` override broke all getter hooks | WeakMap-based shield, no global override |
| **Error.prepareStackTrace** | Crashed before V8 init, killed entire IIFE | Removed global override entirely |
| **Events emptied** | Push telemetry `splice()` removed events from `__SENTINEL_DATA__` | Uses `slice()` — events stay readable |
| **Cascading failure** | One hook crash killed all subsequent hooks | Every hook in independent `try/catch` |
| **toString cache key** | `target.toString()` on prototypes after override → crash | WeakMap keyed on function references |

## Quick Start

```bash
npm install
node index.js --dual-mode
```

## Usage

```bash
# Interactive mode
node index.js

# Quick scan (stealth mode is default)
node index.js browserscan.net

# Observe mode (no stealth — raw behavior)
node index.js browserscan.net --observe

# Run BOTH modes and compare
node index.js browserscan.net --dual-mode

# Custom timeout
node index.js browserscan.net --timeout=45000

# Headless mode
node index.js browserscan.net --headless
```

## Architecture (7 Layers)

1. **Layer 1**: Script Injection via `addInitScript` (main world)
2. **Layer 2**: Anti-Detection Shield (toString protection via WeakMap)
3. **Layer 3**: Core Hooks — 19 categories with value capture
4. **Layer 4**: Extended Hooks — 12 new vectors (speech, client-hints, intl, etc.)
5. **Layer 5**: Exfiltration Monitor (fetch, XHR, beacon, WebSocket, image pixel)
6. **Layer 6**: Behavior Correlation (burst detection, library attribution, entropy)
7. **Layer 7**: 1H5W Forensic Reporting (JSON + HTML + context map)

## 31 API Categories

| # | Category | Risk | What it catches |
|---|----------|------|-----------------|
| 1 | canvas | HIGH | toDataURL, getImageData, fillText, isPointInPath |
| 2 | webgl | HIGH | getParameter, getExtension, getShaderPrecisionFormat |
| 3 | audio | CRITICAL | OfflineAudioContext.startRendering, oscillator, compressor |
| 4 | font-detection | HIGH | measureText, getBoundingClientRect, offsetWidth/Height |
| 5 | fingerprint | MEDIUM | navigator props (userAgent, platform, languages, etc.) |
| 6 | permissions | HIGH | permissions.query |
| 7 | storage | MEDIUM | localStorage, cookies, IndexedDB |
| 8 | screen | MEDIUM | Screen dimensions, devicePixelRatio, matchMedia |
| 9 | network | MEDIUM | fetch, XMLHttpRequest |
| 10 | webrtc | CRITICAL | RTCPeerConnection, createOffer |
| 11 | perf-timing | MEDIUM | performance.getEntries, performance.now |
| 12 | media-devices | HIGH | enumerateDevices |
| 13 | dom-probe | MEDIUM | createElement (canvas/iframe/audio) |
| 14 | clipboard | CRITICAL | clipboard.readText/writeText |
| 15 | geolocation | CRITICAL | getCurrentPosition, watchPosition |
| 16 | service-worker | CRITICAL | serviceWorker.register |
| 17 | hardware | HIGH | getBattery, getGamepads |
| 18 | math-fingerprint | MEDIUM | Math.acos, expm1, log1p, etc. (19 functions) |
| 19 | fingerprint (intl) | MEDIUM | Intl.DateTimeFormat.resolvedOptions |
| 20 | speech | HIGH | speechSynthesis.getVoices |
| 21 | client-hints | HIGH | getHighEntropyValues |
| 22 | intl-fingerprint | MEDIUM | Intl.ListFormat/NumberFormat/Collator |
| 23 | css-fingerprint | MEDIUM | CSS.supports |
| 24 | property-enum | HIGH | Object.keys/getOwnPropertyNames on navigator/screen |
| 25 | offscreen-canvas | HIGH | new OffscreenCanvas |
| 26 | exfiltration | HIGH | sendBeacon, img.src tracking, WebSocket |
| 27 | honeypot | CRITICAL | Planted trap properties |
| 28 | credential | CRITICAL | credentials.get/create |
| 29 | dom-probe-mo | LOW | MutationObserver |
| 30 | dom-probe-io | LOW | IntersectionObserver |
| 31 | system | INFO | BOOT_OK coverage proof |

## Output

Reports are saved to `./output/`:
- `*_report.json` — Full forensic data with correlation results
- `*_report.html` — Interactive HTML dashboard
- `*_context-map.json` — Frame-by-frame coverage

## License

MIT
