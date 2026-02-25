# 🛡️ SENTINEL v6.0.0 — Dual-Layer Forensic Engine

**Patchright + CDP Collectors | Zero Spoofing | Zero Blind Spot | Zero Regression | INVISIBLE**

## Architecture

```
L1:  Persistent Browser Launch (Patchright — eliminates CDP leaks)
L2:  addInitScript injection (Shield → Stealth → Interceptor)
L3:  CDP Session + Push Telemetry + CDP Collectors (Network + Security)
L4:  TargetGraph (Recursive Auto-Attach)
L5:  Worker Pipeline
L6:  Frame Lifecycle Handlers (frameattached + framenavigated)
L7:  Navigate & Observe (human-like behavior)
L8:  Dual-Layer Network Capture (CDP primary + Playwright supplementary)
L9:  Parallel Collection (main + sub-frames + workers + CDP events)
L10: Unified Report Generation (JSON + HTML dark theme + CTX)
```

## What's New in v6.0.0

| Feature | v5.x | v6.0.0 |
|---------|------|--------|
| Browser Driver | Playwright (leaks Runtime.enable) | Patchright (zero CDP leaks) |
| Network Monitoring | Playwright request/response only | CDP Network.* + Playwright (dual-layer) |
| WebSocket Capture | In-page hook only | CDP frames (sent + received + created + closed) |
| TLS/Security | Not monitored | CDP Security.* (cert state, errors, protocol) |
| Cookie Tracking | In-page cookie hook only | CDP extra info (blocked cookies, SameSite, etc.) |
| Event Backbone | Batch collection | EventPipeline (real-time streaming + dedup) |
| Regression Rules | 25 rules | 32 rules (7 new for v6 architecture) |

## Quick Start

```bash
npm install
node index.js https://example.com
```

## CLI Options

```
node index.js <URL> [options]

Options:
  --no-headless     Show browser window
  --dual-mode       Run observe → stealth (double scan)
  --observe         Observe mode (no stealth)
  --verbose         Detailed logging
  --timeout=60000   Navigation timeout (ms)
  --wait=30000      Scan wait time (ms)
  --output=./output Output directory
  --locale=en-US    Browser locale
  --timezone=...    Browser timezone
```

## Testing

```bash
npm test           # 32-rule regression gate
npm run test:stress  # 1000-iteration stress test
npm run test:full    # Both tests
node tests/test-injection.js https://browserscan.net  # Live injection diagnostic
```

## File Structure

```
sentinel-v6.0.0/
├── index.js                          # Main orchestrator (472 lines)
├── package.json
├── hooks/
│   ├── anti-detection-shield.js      # Shield + Quiet Mode (195 lines)
│   ├── stealth-config.js             # Minimal stealth (73 lines)
│   └── api-interceptor.js            # 42 categories, 110+ hooks (906 lines)
├── collectors/
│   ├── cdp-network-collector.js      # CDP Network.* collector (335 lines)
│   └── cdp-security-collector.js     # CDP Security.* collector (71 lines)
├── lib/
│   ├── target-graph.js               # Recursive auto-attach (265 lines)
│   ├── correlation-engine.js         # Burst/entropy analysis (156 lines)
│   ├── signature-db.js               # Library fingerprints (130 lines)
│   └── event-pipeline.js             # Real-time event streaming (79 lines)
├── reporters/
│   └── report-generator.js           # JSON + HTML + CTX reports (331 lines)
└── tests/
    ├── test-regression.js            # 32-rule regression gate (241 lines)
    ├── test-stress.js                # 1000-iteration stress test (140 lines)
    └── test-injection.js             # Live injection diagnostic (112 lines)
```

## 42 Monitored Categories

canvas, webgl, audio, font-detection, fingerprint, screen, storage, network,
perf-timing, media-devices, dom-probe, clipboard, geolocation, service-worker,
hardware, exfiltration, webrtc, math-fingerprint, permissions, speech,
client-hints, intl-fingerprint, css-fingerprint, property-enum, offscreen-canvas,
honeypot, credential, system, encoding, worker, webassembly, keyboard-layout,
sensor-apis, visualization, battery, event-monitoring, blob-url,
shared-array-buffer, postmessage-exfil, performance-now, device-info, cross-frame-comm

## CDP Collector Categories (New in v6)

cdp-network, cdp-cookie, cdp-websocket, cdp-eventsource, cdp-security
