# Sentinel Activity Viewer v4.2.1

## Forensic Maling Catcher — Zero Escape Architecture

### Quick Start
```bash
npm install
npx playwright install chromium
node index.js https://browserscan.net
```

### Bug Fixes (v4.2.1 over v4.2.0)

| Bug | Description | Root Cause | Fix |
|-----|-------------|------------|-----|
| CRASH | `threats is not defined` in report-generator.js:517 | `threats` local to `generateReport()` but referenced in `generateHtml()` | Changed to `report.threats` |
| 0 EVENTS | No forensic events captured | Push telemetry **drained** `_sentinel.events` destructively | Non-destructive pointer-based push |
| 0 EVENTS | `__SENTINEL_FLUSH__` not defined | `finalFlush()` calls `window.__SENTINEL_FLUSH__()` but it was never created | Added to api-interceptor.js |
| INJECTION | `runImmediately: true` not in v4 working version | May cause double-execution or injection timing issues | Removed |
| STUCK | `waitForDebuggerOnStart: true` freezes child targets | Child frames paused waiting for debugger that never resumes | Changed to `false` |
| CDP | `cdpSession.send(method, params, sessionId)` fails | Playwright CDPSession.send does NOT support sessionId routing | Simplified Layer 3 |
| MERGE | Double-counting events from push + page eval | Both sources contain same events after non-destructive fix | Use page eval as primary, push as fallback |

### Architecture
- **37 Detection Categories** — Canvas, WebGL, Audio, Fonts, WebRTC, WASM, Sensors, etc.
- **Triple Injection** — CDP primary + addInitScript backup + per-target auto-attach
- **Adaptive Timeout** — 60s default, extends to 120s if activity detected
- **1H5W Forensic Framework** — WHO/WHAT/WHEN/WHERE/WHY/HOW for every event

### Modes
```bash
node index.js <url>                  # Stealth mode (default)
node index.js <url> --observe        # Observe mode (no stealth)
node index.js <url> --dual-mode      # Both modes comparison
node index.js <url> --headless       # Headless mode
node index.js <url> --timeout=90000  # Custom timeout
```
