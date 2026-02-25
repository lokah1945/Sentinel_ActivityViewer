# 🛡️ SENTINEL v6.1.0 — Playwright Official + Plugin Stealth + CDP Collectors

**Zero Spoofing | Zero Blind Spot | Zero Regression | INVISIBLE**

## What Changed from v6.0.0

| Aspect | v6.0.0 | v6.1.0 |
|---|---|---|
| Browser Driver | Patchright (3rd party fork) | Official Playwright + playwright-extra |
| Stealth Method | Patchright internal patches | puppeteer-extra-plugin-stealth (12 evasions) |
| CDP Leak Fix | Patchright handles internally | Re-added console.debug wrap + CDP webdriver script |
| Runtime.enable | Patchright suppresses | Stealth plugin + defense-in-depth scripts |
| Stack Filter | Filters 'patchright' | Filters 'playwright-extra' |
| Regression Rules | 32 | 34 |

## Install

```bash
npm install
```

## Usage

```bash
# Default (stealth mode, headless, browserscan.net)
node index.js

# Custom target
node index.js https://example.com

# With visible browser
node index.js https://example.com --no-headless

# Verbose + dual mode
node index.js https://example.com --no-headless --dual-mode --verbose

# Custom timeout & wait
node index.js https://example.com --timeout=120000 --wait=60000
```

## Run Tests

```bash
npm test              # 34-rule regression gate
npm run test:stress   # 1000-iteration stress test
npm run test:full     # Both tests

# Live injection diagnostic
node tests/test-injection.js https://browserscan.net
```

## Architecture (10-Layer Pipeline)

```
L1:   Persistent Browser Launch (playwright-extra + stealth plugin)
L1.5: CDP webdriver cleanup (defense-in-depth)
L2:   addInitScript injection (Shield → Stealth → Interceptor)
L3:   CDP Session + Push Telemetry
L3.5: CDP Collectors (Network lifecycle + Security/TLS)
L4:   TargetGraph (Recursive Auto-Attach)
L5:   Worker Pipeline
L6:   Frame Lifecycle Handlers
L7:   Navigate & Observe (human-like behavior)
L8:   Dual-Layer Network Capture (CDP primary + Playwright supplementary)
L9:   Parallel Collection (main + sub-frames + workers + CDP events)
L10:  Unified Report Generation (JSON + HTML dark theme + CTX)
```

## File Structure

```
sentinel-v6.1.0/
├── index.js                     Main orchestrator (491 lines)
├── package.json                 Dependencies
├── README.md                    This file
├── hooks/
│   ├── anti-detection-shield.js Shield + Quiet Mode (201 lines)
│   ├── stealth-config.js        Stealth + console.debug fix (93 lines)
│   └── api-interceptor.js       42 categories, 110+ hooks (906 lines)
├── collectors/
│   ├── cdp-network-collector.js CDP Network.* monitoring (335 lines)
│   └── cdp-security-collector.js TLS/certificate monitoring (71 lines)
├── lib/
│   ├── target-graph.js          Recursive auto-attach (265 lines)
│   ├── correlation-engine.js    Burst/entropy analysis (156 lines)
│   ├── signature-db.js          Library fingerprints (130 lines)
│   └── event-pipeline.js        Real-time streaming (79 lines)
├── reporters/
│   └── report-generator.js      JSON + HTML + CTX (331 lines)
└── tests/
    ├── test-regression.js       34 rules (240 lines)
    ├── test-stress.js           1000 iterations (140 lines)
    └── test-injection.js        Live diagnostic (103 lines)
```
