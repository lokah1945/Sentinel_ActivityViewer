# 🛡️ Sentinel Activity Viewer v4.6.3

**Ghost Protocol Forensic Catcher — Maximum Detection Recovery**

Sentinel is a forensic monitoring tool that observes what scripts running in your browser
are doing — specifically, what fingerprinting and data exfiltration techniques they use.
Think of it as a security camera for your website: it watches the "thieves" (malicious
scripts) and reports exactly what they try to steal and how.

## Quick Start

```bash
npm install
node index.js https://browserscan.net --dual-mode --no-headless
```

## Usage

```bash
# Observe mode (no stealth patches — pure monitoring)
node index.js <url> --no-headless

# Stealth mode (remove automation artifacts + monitor)
node index.js <url> --stealth --no-headless

# Dual mode (run both, compare results)
node index.js <url> --dual-mode --no-headless

# With custom timeout
node index.js <url> --no-headless --timeout=60000

# Verbose output
node index.js <url> --no-headless --verbose
```

## What v4.6.3 Fixes

v4.6.2 had a **63% regression** in detection (553 events vs 1512 in v4.4.1).
v4.6.3 restores all lost detection capabilities:

- ✅ `frameattached` handler restored (late iframes now get hooks)
- ✅ `framenavigated` re-injection added
- ✅ `network` category fixed (was always SILENT)
- ✅ Stealth/interceptor conflict resolved
- ✅ Event listener monitoring restored (focus/blur/visibility)
- ✅ Sub-frame collection expanded to include about:blank
- ✅ Push telemetry 4x faster (500ms vs 2000ms)
- ✅ New hooks: Permissions, Gamepad, CSS.supports

## Architecture

```
index.js                    — Browser launch, navigation, collection pipeline
hooks/
  anti-detection-shield.js  — Protects sentinel hooks from tampering
  stealth-config.js         — Minimal automation artifact cleanup
  api-interceptor.js        — 42 sections, 200+ API hooks, 37 categories
lib/
  target-graph.js           — CDP auto-attach for iframes/workers
  correlation-engine.js     — Event correlation and pattern analysis
  signature-db.js           — Known fingerprinting signatures
reporters/
  report-generator.js       — JSON + HTML forensic reports
```

## Zero Spoofing Policy

Sentinel does NOT spoof any browser properties. It only **observes and reports**.
No User-Agent override, no Client Hints manipulation, no fingerprint spoofing.
