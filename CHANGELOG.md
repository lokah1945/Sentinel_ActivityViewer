# Sentinel v4.6.2 — CHANGELOG

## v4.6.2 (2026-02-25) — "Anti-Incognito + Real GPU"

### 🔴 Root Cause of v4.6.1 Detection

BrowserScan detected Sentinel v4.6.1 as a **bot** and **incognito** because of 3 issues:

| Signal | v4.6.1 Status | Detection Impact |
|--------|--------------|-----------------|
| Storage Quota API | Ephemeral (newContext) = incognito behavior | BrowserScan flags Incognito: Yes |
| WebGL Renderer | SwiftShader software renderer | BrowserScan flags Bot: Yes |
| chrome.runtime | Polyfilled (inconsistent with real Chrome) | Fingerprint mismatch |
| chrome.csi/loadTimes | Polyfilled (removed in Chrome 64/117) | Anachronism = bot signal |
| plugins.length | Polyfilled (doesn't match real PluginArray) | Object shape mismatch |

### ✅ Fixes in v4.6.2

#### Fix 1: Persistent Context (Anti-Incognito)
- `launchPersistentContext()` is now ALWAYS used, not `browser.newContext()`
- Creates a real Chrome profile on disk in `os.tmpdir()/sentinel-profiles/`
- Storage API quota, FileSystem API, IndexedDB all behave like real browser
- Profile is automatically cleaned up after scan completes
- Terminal header now correctly shows `Persistent: true`

#### Fix 2: Real GPU Rendering (Anti-SwiftShader)
- Added `--use-gl=desktop` and `--enable-gpu` launch flags
- Forces Chromium to use the system's real GPU instead of SwiftShader
- WebGL renderer now shows real hardware (e.g., "ANGLE (NVIDIA, GeForce..." or "ANGLE (Intel, HD...")
- SwiftShader was the #1 bot detection signal on BrowserScan

#### Fix 3: Minimal Stealth Patches (Remove False Polyfills)
- REMOVED chrome.runtime polyfill — persistent context already has real `chrome.runtime`
- REMOVED chrome.app polyfill — persistent context already has it
- REMOVED chrome.csi polyfill — only Chrome pre-117 had this, Chrome 145 doesn't
- REMOVED chrome.loadTimes polyfill — deprecated since Chrome 64
- REMOVED plugins polyfill — `--use-gl=desktop` + persistent context gives real plugins
- KEPT navigator.webdriver removal (Playwright genuinely sets this)
- KEPT Playwright global markers removal
- KEPT Permissions API fix (real Playwright bug)

#### Fix 4: No User-Agent Override
- v4.6.2 does NOT set `userAgent` in browser launch options
- Chromium uses its natural UA string, which automatically matches:
  - `sec-ch-ua` header brand list
  - `navigator.userAgentData` API
  - WebGL vendor/renderer version
- This eliminates the "Different browser version" flag on BrowserScan

### 📁 Files Changed
- `index.js` — launchPersistentContext + GPU flags + no UA override
- `hooks/stealth-config.js` — removed 5 unnecessary polyfills
- `reporters/report-generator.js` — version bump to 4.6.2
- `package.json` — version bump to 4.6.2

### 📋 Files Unchanged (working correctly from v4.6.1)
- `hooks/anti-detection-shield.js` — Shield with WeakMap cache (working)
- `hooks/api-interceptor.js` — 37-category interceptor (working)
- `lib/target-graph.js` — Recursive auto-attach walker (working)
- `lib/correlation-engine.js` — Burst/attribution/slow-probe (working)
- `lib/signature-db.js` — FingerprintJS/CreepJS signatures (working)

### 🧪 Expected Results on BrowserScan

| Metric | v4.6.1 | v4.6.2 Expected |
|--------|--------|----------------|
| Incognito Mode | Yes ❌ | No ✅ |
| Bot Detection | Yes ❌ | No ✅ (if real GPU available) |
| WebGL Renderer | SwiftShader ❌ | Real GPU ✅ |
| Browser Version Match | Mismatch ❌ | Match ✅ |
| sec-ch-ua consistency | Chromium only ❌ | Full brand list ✅ |
| chrome.runtime | Polyfilled ❌ | Real (persistent) ✅ |

### ⚠️ Note on GPU
If your machine has NO dedicated GPU (e.g., a pure VPS/CI server):
- `--use-gl=desktop` may fall back to mesa/llvmpipe
- The WebGL renderer will still show as software rendering
- In that case, BrowserScan may still flag bot detection
- This is a hardware limitation, not a code issue
- Solution: run on a machine with a real GPU (even integrated Intel HD works)
