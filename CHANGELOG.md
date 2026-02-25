# Sentinel v4.6.3 — CHANGELOG

## Maximum Detection Recovery Release

### Problem Statement
v4.6.2 detected only **553 events** on BrowserScan, down from **~1512 events** in v4.4.1.
This was a 63% regression in detection capability caused by several code regressions
accumulated across versions v4.5 → v4.6.2.

### Root Causes Identified (Cross-Version Audit v3.0 → v4.6.2)

| # | Bug | Introduced In | Impact |
|---|-----|---------------|--------|
| 1 | `frameattached` handler removed | v4.6.2 | Late-loading iframes (ads, analytics, sub-tests) never got hooks → hundreds of missed events |
| 2 | `framenavigated` handler missing | v4.5+ | Navigated sub-frames lost their hooks |
| 3 | Stealth permissions patch overwrites interceptor hook | v4.6 | `permissions` category always SILENT |
| 4 | `network` category never logged | v4.4+ | fetch/XHR/sendBeacon only log to `exfiltration`, not `network` |
| 5 | Section 27 (event listeners) deleted | v4.6 | focus/blur/visibilitychange/resize monitoring lost |
| 6 | Sub-frame collection too restrictive | v4.6.2 | about:blank/srcdoc frames with active scripts skipped |
| 7 | Push telemetry too slow (2000ms) | v4.6 | First-second burst events missed if frame destroyed early |
| 8 | Several v3 hooks never ported | v4.0+ | Battery API, CSS.supports, gamepad, behavioral events |

### Fixes Applied

1. **RESTORED `frameattached` handler** — Runs BEFORE `page.goto()`. All dynamically-created
   iframes now get shield+stealth+interceptor injection automatically.

2. **NEW `framenavigated` handler** — When a sub-frame navigates to a new URL, check if
   sentinel data exists and re-inject if missing.

3. **FIXED stealth/interceptor conflict** — Removed Permissions API wrapper from
   `stealth-config.js`. Permissions hook now lives in interceptor (section 40) where
   it can properly log to the `permissions` category.

4. **FIXED `network` category (was always SILENT)** — Added section 39 "Dual Network
   Category Logging" that wraps fetch/XHR.send/sendBeacon/Image.src to ALSO log to
   the `network` category alongside `exfiltration`.

5. **RESTORED section 27 Event Listeners** — Merged into expanded section 38 that now
   monitors: focus, blur, visibilitychange, resize, pagehide, pageshow, beforeunload,
   plus all sensor events (devicemotion, touch*, pointer*).

6. **EXPANDED sub-frame collection** — `shouldCollect` now returns `true` for ALL frames
   including about:blank (which BrowserScan uses for sandboxed fingerprinting).

7. **FASTER push telemetry** — Interval reduced from 2000ms to 500ms. Added immediate
   boot push to capture the critical first-second fingerprinting burst.

8. **NEW hooks from all versions consolidated:**
   - Section 40: Permissions API (permissions.query + result state)
   - Section 41: Gamepad API (navigator.getGamepads)
   - Section 42: CSS.supports (css-fingerprint category)
   - Image.src tracking (network category)

### Expected Results

| Metric | v4.6.2 | v4.6.3 Target |
|--------|--------|---------------|
| Total Events | ~553 | 1500+ |
| Categories ACTIVE | 17/37 | 25+/37 |
| Coverage | 45.9% | 70%+ |
| `network` category | SILENT (0) | ACTIVE (50+) |
| `permissions` category | SILENT (0) | ACTIVE |
| `system` category | 2 events | 10+ events |
| `css-fingerprint` | 4 events | 10+ events |
| Sub-frame collection | http-only | ALL frames |
| Push telemetry interval | 2000ms | 500ms |

### Zero Spoofing Policy (Unchanged)
- NO User-Agent override
- NO Client Hints manipulation
- NO fingerprint spoofing
- Detection ONLY — observe and report what attackers do
