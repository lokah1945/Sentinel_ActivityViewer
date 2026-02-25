# Changelog — Sentinel Activity Viewer

## v5.0.0 — Unified Forensic Engine (2026-02-25)

### Philosophy
- **Feature Contract Matrix**: Every feature registered, none deleted without test proof
- **Append-Only Hook Policy**: Hooks only added, never removed without regression test
- **Automated Regression Gate**: 25 rules from real bugs v3.0-v4.6.3

### New from v4.6.3 baseline
- 10-layer unified pipeline (vs 8-layer in v4.6.x)
- `framenavigated` re-injection (first introduced in v4.6.3)
- Immediate boot push (50ms) + 500ms interval + final flush
- Per-target inventory record in coverage proof
- Smart triage for about:blank frames

### Merged from v4.6 Ghost Protocol
- Recursive Auto-Attach (TargetGraph) — CDP cascade for nested iframes
- Worker Pipeline — Network.enable + best-effort injection for workers
- Quiet Mode — non-enumerable globals, zero console, marker randomization
- 5 new categories: keyboard-layout, sensor-apis, visualization, blob-url, shared-array-buffer

### Merged from v4.5
- Bidirectional Network Capture (page.on request + response)
- Zero Spoofing philosophy (no fake UA/WebGL/TZ)
- Direction field on every event (call/response)
- Persistent context with auto-cleanup temp profile
- Value capture 500 chars

### Merged from v4.4.1
- smartHookGetter (prevents prototype shadow bug)
- hookGetterSetter (cookie read + write)
- Filtered property-enum (navigator/screen only)
- Filtered createElement (fingerprint tags only)

### Merged from v4.3
- WeakMap descriptor cache (target-qualified key — prevents Vue crash)
- Error.prepareStackTrace cleanup
- getOwnPropertyDescriptors (plural) protection

### Merged from v3
- Battery API hook (getBattery)
- matchMedia hook (CSS fingerprinting)
- isPointInPath canvas hook

### Bug Fixes Included
- Fix: vc is not defined (v4.5 HTML report crash)
- Fix: timeSpanMs = 0 (v4.4.1 wrong calculation)
- Fix: frameattached removed (v4.6.2 → dynamic iframes not monitored)
- Fix: Event listener monitoring removed (v4.6.2 section 27)
- Fix: Network dual-log silent (v4.6.2)
- Fix: Stealth permissions.query conflict (v4.6.2)
- Fix: about:blank skip too aggressive (v4.5)
- Fix: Prototype shadow → 95% hooks fail (v4.4.0)
- Fix: Variable naming mismatch → 2 events (v4.4.2-fail)
- Fix: Descriptor cache unqualified → Vue crash (v4.2.1)
- Fix: CDP-only injection → 0 events (v4.3)

### Test Suite
- 25 regression rules (each from a real historical bug)
- 1000-iteration stress test (script gen + report gen)
- Quick injection diagnostic

## Previous Versions
- v4.6.3: Maximum Detection Recovery (8 fixes)
- v4.6.x: Ghost Protocol (TargetGraph, Worker Pipeline, Quiet Mode)
- v4.5: Full Conversation Forensic Catcher (zero spoofing, network capture)
- v4.4.x: smartHookGetter, hookGetterSetter, filtered hooks
- v4.3: WeakMap cache, CDP-primary with addInitScript fallback
- v4.2.x: Enhanced shield, signature DB, correlation engine
- v4.0-4.1: CDP supplement, push telemetry, BOOT_OK protocol
- v3.0: Original — 12 categories, instance hooks, reliable detection
