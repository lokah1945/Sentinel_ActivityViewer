# Sentinel Activity Viewer — V4.3

**Zero Escape Architecture — Forensic Browser Fingerprint Detector**

## Overview

Sentinel v4.3 is a Playwright-based browser fingerprinting detection tool that intercepts, monitors, and reports on all JavaScript API calls used for browser fingerprinting. It provides comprehensive forensic analysis with 1H5W (Who/What/When/Where/Why/How) methodology.

### Version History
| Version | Key Changes |
|---------|-------------|
| v3 | Foundation — 1,142 events, 12/18 categories, basic observe/stealth |
| v4 | 7-layer architecture, 31 categories, CDP injection, BOOT_OK protocol |
| v4.1 | Forensic analysis, correlation engine |
| v4.2 | 37 categories, triple injection, adaptive timeout |
| v4.2.1 | Bug fixes (7 bugs patched) |
| **v4.3** | **Clean rebuild. Fixes Bug #8 (descriptor cache) that broke Vue/Nuxt sites** |

## Critical Fix: Bug #8 (Descriptor Cache)

v4.2.1's anti-detection-shield used `_descCache["" + prop]` — an unqualified property name as cache key. This caused `Object.getOwnPropertyDescriptor(anyObject, prop)` to return **wrong cached descriptors** for ANY object, breaking Vue 3 / Nuxt 3 reactivity systems.

**Symptom**: "500 Couldn't resolve component 'default'" error on browserscan.net (Nuxt 3 site).

**Fix**: WeakMap-based target-qualified descriptor cache. Key format = `targetId:prop`.

## Architecture

```
Layer 1: Injection       — CDP / addInitScript (either/or, not both)
Layer 2: Anti-Detection  — WeakMap descriptor cache, Error stack cleanup
Layer 3: API Intercept   — 200+ API hooks, non-destructive push, BOOT_OK
Layer 4: Stealth Config  — Counter-fingerprinting measures
Layer 5: Correlation     — Burst detection, library attribution, slow-probe
Layer 6: Signature DB    — FPv5, CreepJS, custom pattern matching
Layer 7: Reporting       — JSON + HTML forensic report, 1H5W, coverage matrix
```

## File Structure

```
sentinel-activity-viewer/
├── package.json
├── .gitignore
├── README.md
├── index.js                        # Main entry point
├── hooks/
│   ├── anti-detection-shield.js    # WeakMap descriptor cache (Bug #8 fix)
│   ├── api-interceptor.js          # 200+ API hooks, 37 categories
│   └── stealth-config.js           # Counter-fingerprinting
├── lib/
│   ├── signature-db.js             # FPv5/CreepJS signatures
│   └── correlation-engine.js       # Burst/attribution/slow-probe
└── reporters/
    └── report-generator.js         # JSON + HTML forensic report
```

## Installation

```bash
npm install
```

## Usage

### Observe Mode (Monitor Only)
```bash
node index.js --url https://browserscan.net --mode observe
```

### Stealth Mode (Monitor + Counter-Fingerprint)
```bash
node index.js --url https://browserscan.net --mode stealth
```

### Options
| Flag | Description | Default |
|------|-------------|---------|
| `--url` | Target URL to analyze | (required) |
| `--mode` | `observe` or `stealth` | `observe` |
| `--timeout` | Base timeout in ms | `60000` |
| `--max-timeout` | Maximum adaptive timeout | `120000` |
| `--output` | Output directory | `./output` |
| `--headless` / `--no-headless` | Browser visibility | `true` |

## Output

Reports are saved to the `output/` directory:
- `sentinel_<timestamp>_report.json` — Full structured data
- `sentinel_<timestamp>_report.html` — Visual forensic report
- `sentinel_<timestamp>_context.json` — Frame/injection context

## Categories Monitored (37)

canvas, webgl, audio, font-detection, fingerprint, screen, storage, network, perf-timing, media-devices, dom-probe, clipboard, geolocation, service-worker, hardware, exfiltration, webrtc, math-fingerprint, permissions, speech, client-hints, intl-fingerprint, css-fingerprint, property-enum, offscreen-canvas, honeypot, credential, system, encoding, worker, webassembly, keyboard-layout, sensor-apis, visualization, device-info, battery, bluetooth

## License

ISC
