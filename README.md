# SENTINEL v7.0.0 — Hybrid Dual-Telemetry Forensic Engine

> **PURE NEW CONCEPT** — No backward compatibility. Full rewrite combining the best of v6.4 (CDP/persistent/rebrowser) and v5.0.0/v6.1 (hook layer/push telemetry).

## Architecture

**12-Layer Pipeline:**

| Layer | Component | Source |
|-------|-----------|--------|
| L1 | Persistent Browser Launch | v6.4 |
| L2 | Stealth Plugin + rebrowser patches | v6.4 |
| L3 | addInitScript Injection (Shield + Interceptor) | v5.0/v6.1 RESTORED |
| L4 | CDP Session + Runtime.addBinding | v6.1 |
| L5 | Push Telemetry Receiver (500ms) | v6.1 RESTORED |
| L6 | TargetGraph Recursive Auto-Attach | v6.4 |
| L7 | Worker Pipeline | v6.4 |
| L8 | Frame Lifecycle Handlers | v6.1 RESTORED |
| L9 | CDP Domain Collectors | v6.4 |
| L10 | Bidirectional Network Capture | v6.1 RESTORED |
| L11 | Parallel Collection + Dedup + Merge | NEW |
| L12 | Unified Report (JSON + HTML + CTX) | v6.4 Enhanced |

## 42 Detection Categories

canvas, webgl, audio, font-detection, fingerprint, screen, storage, network,
perf-timing, media-devices, dom-probe, clipboard, geolocation, service-worker,
hardware, exfiltration, webrtc, math-fingerprint, permissions, speech,
client-hints, intl-fingerprint, css-fingerprint, property-enum, offscreen-canvas,
honeypot, credential, system, encoding, worker, webassembly, keyboard-layout,
sensor-apis, visualization, battery, event-monitoring, blob-url,
shared-array-buffer, postmessage-exfil, device-info, cross-frame-comm,
+ CDP categories (network-request, network-response, cookie-set, cookie-sent,
frame-lifecycle, security-state, browser-log, dom-mutation, library-detected, etc.)

## Quick Start

```bash
npm install
node index.js https://browserscan.net stealth 30000
node index.js https://example.com observe 15000
```

## Tests

```bash
npm test                  # 28 regression rules
npm run test:injection    # Injection content validation
npm run test:full         # All tests
```

## File Structure

```
sentinel-v7/
├── index.js                          # Main orchestrator (12-layer pipeline)
├── package.json
├── hooks/
│   ├── anti-detection-shield.js      # Shield + Quiet Mode + toString protection
│   ├── api-interceptor.js            # 42 categories, 110+ hooks, push telemetry
│   └── stealth-config.js             # Minimal stealth plugin config
├── lib/
│   ├── event-pipeline.js             # Unified dual-source pipeline
│   ├── cdp-observer-engine.js        # CDP domain collectors
│   ├── target-graph.js               # Recursive auto-attach
│   ├── correlation-engine.js         # Forensic analysis + burst detection
│   └── signature-db.js               # Library signature database
├── reporters/
│   └── report-generator.js           # JSON + HTML + CTX report output
└── tests/
    ├── test-regression.js            # 28 REG rules
    └── test-injection.js             # Script content validation
```

## Target Performance

| Version | Events | Categories | Coverage |
|---------|--------|------------|----------|
| v6.1 (stealth) | 1,799 | 22 | 52.4% |
| v6.4 (stealth) | 313 | 19 | 63.3%* |
| **v7.0 (target)** | **1,800+** | **35+** | **83%+** |

\* v6.4 redefined category basis to ~30 CDP-native categories
