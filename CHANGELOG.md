# Changelog

## v5.1.0 — Invisible Edition (2026-02-25)

### Anti-Bot Fix (Critical)
- **playwright-extra + puppeteer-extra-plugin-stealth**: 10+ evasion modules
- **outerWidth/outerHeight fix**: 160/28 → 1296/808 (prevents #1 bot indicator)
- **--window-size launch arg**: Matches viewport to window chrome size
- **Notification.permission consistency**: Prevents headless detection
- **connection.rtt fix**: 0 → 50 (prevents headless RTT detection)

### Human-Like Behavior
- Random mouse movements before scrolling
- Variable scroll speed with smooth behavior
- Random delays (±2 seconds) on all navigation
- Realistic think time between actions

### Architecture
- `require('playwright-extra')` replaces `require('playwright')`
- `chromium.use(StealthPlugin())` before any browser launch
- `page.setViewportSize()` explicit consistency enforcement

### Unchanged from v5.0.0
- 42 categories, 110+ hooks (api-interceptor.js)
- Anti-detection shield with WeakMap cache
- Recursive auto-attach (TargetGraph)
- Worker Pipeline
- Bidirectional network capture
- Correlation engine + Signature DB
- HTML report (dark theme)
- 25 regression rules
- 1000-iteration stress test
