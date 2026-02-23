# 🛡️ Sentinel v4.0 — Forensic Maling Catcher

> **7-Layer Architecture | 31 API Categories | 1H5W Forensic Framework**

Sentinel v4 is a forensic browser activity viewer that detects, captures, and attributes fingerprinting activity on any website. Built as a complete upgrade from v3, it fixes all 6 critical bugs and adds 12+ new detection vectors.

## 🆕 What's New in v4

### Critical Bug Fixes
| Bug | v3 Problem | v4 Fix |
|-----|-----------|--------|
| Stealth 0 events | `addInitScript` race condition with isolated world | CDP `Page.addScriptToEvaluateOnNewDocument` in MAIN world |
| Cross-origin crash | `SecurityError` on `window.top` access | `try/catch` wrappers + CDP auto-attach for cross-origin frames |
| Data locked per-frame | `window.__SENTINEL_DATA__` only readable from same frame | `Runtime.addBinding` push-based telemetry + multi-frame collector |
| No value capture | Only counted API calls, never logged return values | Every hook captures actual return value |
| No stack trace | No caller identification | Stack sampling every N calls per API |
| No anti-detection | Hooks detectable by CreepJS/bots | Anti-Detection Shield with toString/descriptor spoofing |

### New Features
- **7-Layer Architecture**: CDP → Shield → Core Hooks → Extended Hooks → Exfil Monitor → Correlation → Reporting
- **31 API Categories**: 19 enhanced + 12 new (speech, client-hints, intl, CSS.supports, property-enum, offscreen-canvas, WebSocket, img exfil, mutation/intersection observers, gamepad, credentials, honeypot)
- **Value Capture**: Every hooked API logs its actual return value (forensic evidence)
- **Stack Sampling**: Periodic `Error.stack` capture to identify WHO is calling each API
- **1H5W Forensic Framework**: Every report answers WHO, WHAT, WHEN, WHERE, WHY, HOW
- **BOOT_OK Protocol**: Mandatory event per execution context proves monitoring coverage
- **Library Attribution**: Signature database identifies FingerprintJS, CreepJS, BotD, BrowserScan
- **Burst Detection**: Identifies fingerprinting bursts (50+ events in 1s window)
- **Entropy Calculation**: Shannon entropy for category/API/origin diversity
- **Exfiltration Monitor**: Tracks sendBeacon, WebSocket, tracking pixels, and data URLs
- **Honeypot Properties**: Planted trap properties that trigger on active fingerprinting probes
- **Anti-Detection Shield**: toString spoofing, descriptor caching, stack trace cleanup

## 📦 Installation

```bash
git clone https://github.com/lokah1945/Sentinel_ActivityViewer.git
cd Sentinel_ActivityViewer
npm install
```

## 🚀 Usage

```bash
# Interactive mode
node index.js

# Quick scan (stealth mode — default)
node index.js https://browserscan.net

# Observe mode (no stealth, more detectable)
node index.js https://browserscan.net --observe

# Dual mode — runs both and compares
node index.js https://browserscan.net --dual-mode

# Custom timeout
node index.js https://browserscan.net --timeout=60000

# Headless mode
node index.js https://browserscan.net --headless
```

## 📊 Output Files

Each scan generates 3 files in `output/`:

| File | Format | Content |
|------|--------|---------|
| `*_report.json` | JSON | Full forensic data: events, values, correlation, 1H5W |
| `*_report.html` | HTML | Interactive dashboard with timeline, tabs, charts |
| `*_context-map.json` | JSON | Frame coverage proof with BOOT_OK status |

## 🏗️ Architecture

```
Layer 7: 1H5W Forensic Report   ← reporters/report-generator.js
Layer 6: Behavior Correlation    ← lib/correlation-engine.js + lib/signature-db.js
Layer 5: Exfiltration Monitor    ← hooks/api-interceptor.js (network hooks)
Layer 4: Extended Hooks (12)     ← hooks/api-interceptor.js (new vectors)
Layer 3: Core Hooks (19)         ← hooks/api-interceptor.js (enhanced)
Layer 2: Anti-Detection Shield   ← hooks/anti-detection-shield.js
Layer 1: CDP Injection           ← index.js (Page.addScriptToEvaluateOnNewDocument)
```

## 🔍 31 Monitored Categories

| # | Category | Risk | What It Detects |
|---|----------|------|-----------------|
| 1 | canvas | HIGH | Canvas toDataURL/getImageData pixel fingerprint |
| 2 | webgl | HIGH | GPU vendor/renderer/precision fingerprint |
| 3 | audio | CRITICAL | AudioContext/OfflineAudioContext fingerprint |
| 4 | font-detection | HIGH | Installed font enumeration via measureText/BCR |
| 5 | fingerprint | HIGH | Navigator properties (userAgent, platform, etc.) |
| 6 | permissions | HIGH | Permission state probing |
| 7 | storage | MEDIUM | Cookie/localStorage/IndexedDB tracking |
| 8 | screen | MEDIUM | Display resolution/color depth |
| 9 | network | MEDIUM | Fetch/XHR network requests |
| 10 | webrtc | CRITICAL | WebRTC IP leak attempts |
| 11 | perf-timing | MEDIUM | Performance API timing attacks |
| 12 | math-fingerprint | MEDIUM | Math function precision differences |
| 13 | media-devices | CRITICAL | Camera/microphone enumeration |
| 14 | dom-probe | LOW | DOM element creation/mutation monitoring |
| 15 | clipboard | CRITICAL | Clipboard read/write access |
| 16 | geolocation | CRITICAL | Physical location tracking |
| 17 | service-worker | HIGH | Persistent background code |
| 18 | hardware | HIGH | Battery/gamepad/device probing |
| 19 | architecture | MEDIUM | CPU architecture detection |
| 20 | speech | HIGH | TTS voice fingerprinting |
| 21 | client-hints | CRITICAL | UA-CH high-entropy values |
| 22 | intl-fingerprint | MEDIUM | Intl API locale fingerprinting |
| 23 | css-fingerprint | MEDIUM | CSS.supports feature detection |
| 24 | property-enum | HIGH | Prototype inspection/lie detection |
| 25 | offscreen-canvas | HIGH | Worker-based canvas fingerprinting |
| 26 | exfiltration | CRITICAL | sendBeacon/WebSocket/pixel tracking |
| 27 | honeypot | CRITICAL | Planted trap property access |
| 28 | credential | CRITICAL | WebAuthn/passkey probing |
| 29 | system | INFO | BOOT_OK coverage proof events |
| 30 | dom-probe (MO) | LOW | MutationObserver monitoring |
| 31 | dom-probe (IO) | LOW | IntersectionObserver monitoring |

## 📋 1H5W Forensic Framework

Every generated report answers:

- **WHO** (👤): Which library/script is fingerprinting (via attribution engine)
- **WHAT** (📋): Total events, categories, specific APIs called + return values
- **WHEN** (⏱️): Precise timestamps, burst analysis, scan duration
- **WHERE** (📍): Origins, frames, coverage proof per execution context
- **WHY** (❓): Risk reasoning for each API call, threat severity
- **HOW** (🔧): Technical method used (e.g., "OfflineAudioContext + Oscillator + Compressor")

## 🔐 Anti-Detection Shield

The shield prevents fingerprinting libraries from detecting Sentinel's presence:

- **toString Spoofing**: Hooked functions return native `function X() { [native code] }` strings
- **Descriptor Caching**: `Object.getOwnPropertyDescriptor` returns original descriptors for hooked properties
- **Stack Cleanup**: Removes Sentinel/Playwright/Puppeteer frames from `Error.stack`
- **Property Integrity**: Function `.name` and `.length` preserved to match originals

## 📚 Library Attribution

Sentinel v4 identifies known fingerprinting libraries by matching API call patterns:

| Library | Detection Method |
|---------|-----------------|
| FingerprintJS v3-v5 | isPointInPath + audio + fonts + math + WebGL burst |
| CreepJS | toString probe + prototype inspection + offscreen canvas |
| BotD | webdriver + chrome.runtime + stack analysis |
| BrowserScan | Full parameter scan + media + WebRTC |
| ClientJS | Legacy userAgent + plugins + screen |

## 📄 License

MIT

---

**Sentinel v4** — *Tidak ada satu gerakan pun dari maling yang tidak terdeteksi* 🛡️
