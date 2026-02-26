# SENTINEL v7.1.0 — Hybrid Dual-Telemetry Forensic Engine

> **v7.1.0 FIXES**: Browser install chain, dependency resolution, auto-install fallback.

## Quick Start

```bash
npm install
node index.js https://browserscan.net --dual-mode --no-headless
```

## What v7.1.0 Fixes

### Error 1: `Cannot find module 'playwright/lib/transform/esmLoader'`
**Root Cause**: `rebrowser-playwright` internally requires `playwright` as a peer dependency. It patches playwright's ESM loader at `playwright/lib/transform/esmLoader`. Without `playwright` in `dependencies`, Node.js cannot resolve this path.

**Fix**: Added `playwright` and `playwright-core` to `dependencies` in `package.json`.

### Error 2: `Executable doesn't exist at .../chromium-1169/chrome-win/chrome.exe`
**Root Cause**: Version mismatch between `rebrowser-playwright` and `playwright` chromium registry.
- `rebrowser-playwright install chromium` downloads **chromium-1155** (its pinned revision)
- At runtime, path resolution goes through `playwright`'s registry which expects **chromium-1169**
- Result: the executable path points to a directory that doesn't exist

**Fix (3-layer defense)**:
1. `postinstall` now runs `scripts/install-browsers.js` which installs chromium for **BOTH** packages
2. `index.js` has `launchBrowserWithRetry()` — if browser not found, auto-installs then retries
3. Final fallback: detects system Chrome/Chromium/Edge as last resort

## CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--dual-mode` | off | Run observe + stealth passes sequentially |
| `--no-headless` | headless | Show visible browser window |
| `--no-stealth` | stealth on | Disable stealth plugin |
| `--timeout=<ms>` | 60000 | Navigation timeout |
| `--wait=<ms>` | 30000 | Post-load observation time |
| `--persist=<dir>` | auto-temp | Persistent browser profile |

## Examples

```bash
# Standard dual-mode (like v6.4)
node index.js https://browserscan.net --dual-mode --no-headless

# With custom timing
node index.js https://browserscan.net --dual-mode --no-headless --timeout=60000 --wait=30000

# Single stealth mode
node index.js https://example.com --no-headless

# With persistent profile
node index.js https://browserscan.net --persist=./profiles/session1 --no-headless

# Comparison mode (no stealth)
node index.js https://example.com --no-stealth --no-headless
```

## Manual Browser Install (if auto-install fails)

```bash
npx playwright install chromium
npx rebrowser-playwright install chromium
```

## Tests

```bash
npm test                  # 28 regression rules
npm run test:injection    # Script content validation
npm run test:full         # All tests
```

## Architecture: 12-Layer Pipeline

| Layer | Component | Source |
|-------|-----------|--------|
| L1 | persistentContext + auto-cleanup + auto-install-retry | v6.4 + v7.1.0 |
| L2 | Stealth plugin (17 evasions) + rebrowser-patches | v6.4 |
| L3 | addInitScript (shield + interceptor, 42 categories) | v5.0/v6.1 restored |
| L4 | CDP session + Runtime.addBinding | v6.1 |
| L5 | Push telemetry (500ms interval) | v6.1 restored |
| L6 | TargetGraph recursive auto-attach | v6.4 |
| L7 | Worker pipeline | v6.4 |
| L8 | Frame lifecycle handlers | v6.1 restored |
| L9 | CDP domains (7 domains) | v6.4 |
| L10 | Bidirectional network capture | v6.1 restored |
| L11 | Parallel collection + dedup + merge | v7.0.0 new |
| L12 | Unified report (JSON + HTML + CTX) | v7.0.0 new |
