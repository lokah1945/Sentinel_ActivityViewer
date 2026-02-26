# 🛡️ Sentinel Activity Viewer v6.3.0 — Pure Observer CCTV

> Zero Injection. Zero Spoofing. 100% Passive CDP Observation.

## Philosophy

Sentinel is a **CCTV security camera**, not a disguise.

- **ZERO injection** — not a single line of JavaScript is injected into any page
- **ZERO spoofing** — no UA override, no locale change, no viewport override, nothing
- **ZERO modification** — the browser behaves 100% like a normal browser
- **100% passive** — all monitoring via CDP event subscriptions from outside the page
- The "thief" (website fingerprinting/tracking your browser) has NO idea it's being watched

## What Changed from v6.1/v6.2

| Issue | v6.1 | v6.2 | v6.3 |
|-------|------|------|------|
| Runtime.Enable leak | ❌ Active | ✅ Fixed (rebrowser-patches) | ✅ Fixed (rebrowser-playwright-core) |
| Windows install | ✅ Works | ❌ `patch.exe not found` | ✅ npm alias, no patch needed |
| JS injection into page | ✅ Heavy (42 API hooks) | ✅ Heavy (42 API hooks) | ❌ ZERO injection |
| UA/locale spoofing | ✅ Yes | ✅ Yes | ❌ ZERO spoofing |
| Detection by website | ❌ Risk 100/100 | ❓ Untested | ✅ Pure CDP observation |
| Plugin support | ✅ playwright-extra | ✅ playwright-extra | ✅ playwright-extra |

### Key Fix: npm Alias (No patch.exe Required)

```json
{
  "playwright-core": "npm:rebrowser-playwright-core@^1.52.0"
}
```

This tells npm: "when code does `require('playwright-core')`, give it `rebrowser-playwright-core` instead." The Runtime.Enable fix is pre-applied — no `patch.exe` needed on Windows.

## Quick Start

```bash
# Install (works on Windows without Git/patch.exe)
npm install

# Run
node index.js https://browserscan.net --dual-mode --no-headless

# With persistent profile
node index.js https://example.com --persist=./profiles/session1 --no-headless

# Run regression tests
npm test
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  playwright-extra (plugin framework)                     │
├─────────────────────────────────────────────────────────┤
│  rebrowser-playwright-core (aliased as playwright-core)  │
│  └── Runtime.Enable: PRE-PATCHED at source level        │
│  └── sourceURL: analytics.js (no pptr: leak)            │
├─────────────────────────────────────────────────────────┤
│  puppeteer-extra-plugin-stealth                          │
│  └── Removes Chromium automation artifacts               │
│  └── Does NOT inject anything — just cleans up defaults  │
├─────────────────────────────────────────────────────────┤
│  Sentinel Observer Layers (ALL passive CDP)              │
│  ├── CdpObserverEngine (8 CDP domains)                   │
│  │   ├── Network.* (requests, responses, WS, cookies)   │
│  │   ├── Security.* (TLS, certificates)                  │
│  │   ├── Page.* (navigation, frames, downloads)          │
│  │   ├── Performance.* (metrics)                         │
│  │   ├── Console/Runtime (console.log, exceptions)       │
│  │   ├── Audits.* (mixed content, issues)                │
│  │   └── Log.* (browser-level logs)                      │
│  ├── FrameTreeWatcher (Target.setAutoAttach recursive)   │
│  ├── PageScopeWatcher (new tabs/popups auto-attach)      │
│  ├── EventPipeline (dedup + stats)                       │
│  ├── ForensicEngine (5W1H analysis)                      │
│  └── ReportGenerator (JSON + HTML)                       │
└─────────────────────────────────────────────────────────┘
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `<URL>` | Target URL | required |
| `--dual-mode` | Run observe + stealth | off |
| `--no-headless` | Visible browser | headless |
| `--no-stealth` | Disable stealth plugin | on |
| `--timeout=<ms>` | Nav timeout | 60000 |
| `--wait=<ms>` | Observation time | 30000 |
| `--persist=<dir>` | Persistent profile | ephemeral |

## Files

```
sentinel-v6.3.0/
├── index.js                          # Main orchestrator
├── package.json                      # npm alias config
├── test-regression.js                # Automated tests
├── lib/
│   ├── cdp-observer-engine.js        # 8 CDP domain observers
│   ├── frame-tree-watcher.js         # Recursive target/frame discovery
│   ├── page-scope-watcher.js         # Multi-tab monitoring
│   ├── event-pipeline.js             # Event bus + dedup
│   ├── forensic-engine.js            # 5W1H + threat analysis
│   └── report-generator.js           # JSON + HTML reports
└── output/                           # Report output
```

## Upgrade from v6.1/v6.2

1. Delete `node_modules/` and `package-lock.json`
2. Replace ALL files with v6.3
3. `npm install`
4. `npm test`
5. Done — no `patch.exe`, no manual steps
