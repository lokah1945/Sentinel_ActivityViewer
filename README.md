# 🛡️ Sentinel Activity Viewer v6.2.0

> Official Playwright + rebrowser-patches + Stealth Plugin + CDP Deep Collectors

## What Changed from v6.1

**v6.1 Problem:** BrowserScan detected the browser as bot (Risk Score 100/100) in BOTH observe and stealth modes. The `puppeteer-extra-plugin-stealth` alone does NOT fix the `Runtime.Enable` CDP leak — which is the #1 detection vector used by BrowserScan, Cloudflare, and DataDome.

**v6.2 Solution:** Apply `rebrowser-patches` on top of official `playwright-core`. This patches the source code to prevent `Runtime.Enable` from being called automatically, eliminating the primary CDP detection signal.

### Architecture Stack

```
┌─────────────────────────────────────────────┐
│  playwright-extra (plugin framework)         │
├─────────────────────────────────────────────┤
│  playwright-core (official, PATCHED)         │
│  └── rebrowser-patches applied               │
│      ├── Runtime.Enable leak: FIXED          │
│      ├── sourceURL: FIXED (analytics.js)     │
│      └── utility world name: FIXED           │
├─────────────────────────────────────────────┤
│  puppeteer-extra-plugin-stealth             │
│  └── 12 evasion modules active               │
├─────────────────────────────────────────────┤
│  Sentinel Custom Layers                      │
│  ├── AntiDetectionShield (property cleanup)  │
│  ├── StealthHardener (UA hints, behavior)    │
│  ├── ApiInterceptor (42-cat JS hooks)        │
│  ├── CdpCollectorPipeline (network/sec/tgt)  │
│  ├── RecursiveFrameAttacher (deep iframes)   │
│  ├── EventPipeline (dedup + backpressure)    │
│  ├── ForensicEngine (5W1H analysis)          │
│  └── ReportGenerator (JSON + HTML)           │
└─────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Install
npm install

# 2. The postinstall script automatically:
#    - Applies rebrowser-patches to playwright-core
#    - Installs Chromium browser

# 3. Run
node index.js https://browserscan.net --dual-mode --no-headless

# With persistent profile:
node index.js https://browserscan.net --persist=./profiles/session1 --no-headless
```

## Manual Patch (if postinstall fails on Windows)

```powershell
# Make sure Git is installed (for patch command)
set PATH=%PATH%;C:\Program Files\Git\usr\bin\

# Apply patches
npx rebrowser-patches@latest patch --packageName playwright-core
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `<URL>` | Target URL to scan | (required) |
| `--dual-mode` | Run observe + stealth passes | off |
| `--no-headless` | Visible browser | headless |
| `--timeout=<ms>` | Navigation timeout | 60000 |
| `--wait=<ms>` | Post-load wait | 30000 |
| `--persist=<dir>` | Persistent profile dir | ephemeral |

## Environment Variables

| Variable | Values | Default |
|----------|--------|---------|
| `REBROWSER_PATCHES_RUNTIME_FIX_MODE` | `addBinding`, `alwaysIsolated`, `enableDisable`, `0` | `addBinding` |
| `REBROWSER_PATCHES_SOURCE_URL` | any filename, `0` to disable | `analytics.js` |

## Upgrade from v6.1

1. Replace `package.json`
2. Delete `node_modules`
3. `npm install`
4. Copy `lib/` folder
5. Replace `index.js`
6. Run `npm test` to verify

## Files

```
sentinel-v6.2.0/
├── index.js                          # Main entry point
├── package.json                      # Dependencies + postinstall patch
├── test-regression.js                # Regression tests
├── lib/
│   ├── anti-detection-shield.js      # Property cleanup + automation removal
│   ├── stealth-hardener.js           # UA hints, behavioral evasion
│   ├── api-interceptor.js            # 42-category JS API hooks
│   ├── cdp-collector-pipeline.js     # CDP Network/Security/Target collectors
│   ├── recursive-frame-attacher.js   # Deep iframe monitoring
│   ├── event-pipeline.js             # Central event bus + dedup
│   ├── forensic-engine.js            # 5W1H analysis engine
│   ├── report-generator.js           # JSON + HTML report output
│   └── browser-persistence.js        # Cross-session profile management
└── output/                           # Report output directory
```

## Why Not Patchright?

User requirement: full official Playwright with plugin support. `rebrowser-patches` achieves the same Runtime.Enable fix while keeping 100% official Playwright API + plugin ecosystem compatibility.
