# Changelog

## v5.1.0 — Invisible Edition (2026-02-25)

### Anti-Bot Fix (Critical)
- **CDP webdriver fix**: Page.addScriptToEvaluateOnNewDocument (earlier than addInitScript)
- **CDP leak patch**: console.debug behavior fix prevents Runtime.Enable detection
- **Removed playwright-extra**: Conflicts with persistent context native chrome objects
- **Removed outerHeight override**: Caused 788 vs 808 inconsistency across frames
- **Automation markers**: Added cdc_ ChromeDriver markers, DevTools $/$$ removal
- **--window-size=1296,808**: Realistic outer dimensions from OS, no JS override

### Human-Like Behavior
- Random mouse movements before and after scrolling
- Variable scroll speed with smooth behavior
- Random delays (±2 seconds) on all navigation
- Human-like think time between actions

### What Was Removed (from v5.1.0-beta)
- playwright-extra dependency (conflicts with native chrome objects)
- puppeteer-extra-plugin-stealth (overwrites real chrome.app/csi/loadTimes)
- outerWidth/outerHeight JS override (caused cross-frame inconsistency)
- Notification.permission polyfill (over-engineering)
- connection.rtt spoof (violates zero-spoof)
- Image constructor wrap (detectable)

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
- Plain playwright dependency only

## v5.0.0 — Unified Forensic Engine (2026-02-25)
- First unified engine from v3.0 through v4.6.3
- 42 categories, 110+ hook points
- 10-layer pipeline architecture
- 25 regression rules
- 1000-iteration stress test
