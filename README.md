# 🛡️ Sentinel Owner Mode

## Zero-Trust Browser Security Observatory (Chromium-Only, Playwright)

### Tujuan
Observability + kontrol zero-trust untuk SEMUA konteks eksekusi JS di browser:
- Main frame / nested iframe (depth tracking) / popup
- Dedicated Worker / Shared Worker / Service Worker
- Komunikasi antar konteks (postMessage / BroadcastChannel / MessagePort)
- Deteksi evasion (WASM, blob/data URL, dynamic iframe injection)
- Policy engine (audit mode vs lockdown mode)
- Report komprehensif (JSON + HTML visual dashboard)
- Artifacts: events.jsonl + session.har + trace.zip + context-map.json

### 3-Layer Defense Architecture
- **Layer A**: `addInitScript` — Inject bootstrap at document_start
- **Layer B**: CDP auto-attach — Inject into workers/targets via Chrome DevTools Protocol
- **Layer C**: Script route rewriting — Prepend bootstrap to ALL JS files fetched

### Quick Start
```bash
npm install
npx playwright install chromium

# Audit mode (observe only):
npm start -- "https://example.com" ./out

# Lockdown mode (observe + block dangerous APIs):
SENTINEL_MODE=lockdown npm start -- "https://example.com" ./out

# Headed mode (see the browser):
HEADLESS=0 npm start -- "https://example.com" ./out
```

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| SENTINEL_MODE | audit | `audit` or `lockdown` |
| HEADLESS | 1 | `0` to show browser window |
| WAIT_MS | 15000 | How long to observe (ms) |
| STACK_RATE | 1 | Stack trace sample rate (0-1) |

### Output Files
| File | Description |
|------|-------------|
| events.jsonl | Raw telemetry stream |
| report.json | Structured summary with risk scoring |
| report.html | Visual dashboard (open in browser) |
| context-map.json | All execution contexts with hierarchy |
| session.har | Full network recording |
| trace.zip | Playwright trace (view with `npx playwright show-trace`) |

### Hook Coverage (18 Categories, 70+ APIs)
1. Fingerprinting (navigator props, userAgentData)
2. Canvas/WebGL/Audio fingerprinting
3. Screen properties
4. Font detection
5. Permissions
6. Geolocation
7. Media devices (camera/mic/screen)
8. Clipboard
9. File pickers
10. Hardware (Bluetooth, USB, HID, Serial, WebGPU)
11. WebAuthn / Credentials
12. Payments + WebRTC
13. Network (fetch, XHR, WebSocket, EventSource)
14. Storage (cookies, localStorage, sessionStorage, IndexedDB, Cache API)
15. Service Worker registration
16. Sensors (Accelerometer, Gyroscope, etc.)
17. Performance timing (side-channel detection)
18. Wake Lock / Fullscreen

### Evasion Detection
- WASM compile/instantiate/streaming
- Blob URL creation & revocation
- Blob constructor (stealth code assembly)
- Dynamic iframe injection (MutationObserver)
- iframe src/srcdoc setter hooks
- Worker/SharedWorker blob/data URL constructors
- Hidden/0x0/tiny iframe detection

### Known Limitations (Honest)
- Some native properties are non-configurable (cannot be hooked)
- Service Worker update scripts may execute before injection
- Blob worker internal code cannot be rewritten via network routing
- We detect and log evasion *indicators* even when we can\'t fully intercept
