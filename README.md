# 🛡️ Sentinel v3.0 — Maling Catcher

**Browser Activity Viewer with Stealth Mode** — Detects and reports all fingerprinting, tracking, and suspicious browser API activity from any website.

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Interactive mode (akan minta input URL)
npm start

# Quick scan dengan stealth (default)
node index.js browserscan.net

# Observe mode (tanpa stealth, deteksi mentah)
node index.js browserscan.net --observe

# Dual mode (jalankan kedua mode & bandingkan hasilnya)
node index.js browserscan.net --dual-mode

# Custom timeout (default 30s)
node index.js browserscan.net --timeout=45000

# Headless mode
node index.js browserscan.net --headless
```

## 🏗️ Architecture

```
sentinel_v3/
├── index.js                    # CLI entry point
├── package.json
├── hooks/
│   ├── stealth-config.js       # Stealth plugin + extra hardening
│   └── api-interceptor.js      # 18-category API hook engine
├── reporters/
│   └── report-generator.js     # JSON + HTML + Context Map generator
├── output/                     # Scan results saved here
└── README.md
```

## 🔍 18 Monitored Categories

| Category | APIs Hooked | Risk |
|----------|-------------|------|
| Canvas | toDataURL, toBlob, getImageData, fillText, isPointInPath | 🔴 HIGH |
| WebGL | getParameter, getExtension, getSupportedExtensions, getShaderPrecisionFormat, readPixels | 🔴 HIGH |
| Audio | OfflineAudioContext, createOscillator, createDynamicsCompressor, createAnalyser, baseLatency | 🔴 CRITICAL |
| Font Detection | measureText, document.fonts.check, getBoundingClientRect, offsetWidth | 🔴 HIGH |
| Fingerprint | userAgent, platform, languages, hardwareConcurrency, deviceMemory, plugins, matchMedia | 🔴 HIGH |
| Math Fingerprint | acos, acosh, asin, sinh, cos, tan, exp, expm1, log1p (15 functions) | 🟡 HIGH |
| Permissions | navigator.permissions.query | 🔴 HIGH |
| Storage | cookie get/set, localStorage, sessionStorage, indexedDB | 🟡 MEDIUM |
| Screen | width, height, colorDepth, pixelDepth, availWidth, devicePixelRatio | 🟡 MEDIUM |
| Network | fetch, XMLHttpRequest, sendBeacon | 🟡 MEDIUM |
| WebRTC | RTCPeerConnection | 🔴 CRITICAL |
| Performance | getEntries, getEntriesByType, performance.now | 🟡 MEDIUM |
| Media Devices | enumerateDevices | 🔴 CRITICAL |
| DOM Probe | createElement (canvas/iframe/audio/video) | 🟡 MEDIUM |
| Clipboard | readText, writeText | 🔴 CRITICAL |
| Geolocation | getCurrentPosition, watchPosition | 🔴 CRITICAL |
| Service Worker | register | 🔴 HIGH |
| Hardware | getBattery, timezone, architecture | 🟡 MEDIUM |

## 🥷 Stealth Mode

Stealth mode uses **17 evasion techniques** from `puppeteer-extra-plugin-stealth`:

- `chrome.app` / `chrome.csi` / `chrome.loadTimes` / `chrome.runtime`
- `navigator.webdriver` / `navigator.plugins` / `navigator.vendor` / `navigator.permissions` / `navigator.languages` / `navigator.hardwareConcurrency`
- `user-agent-override` / `media.codecs`
- `iframe.contentWindow` / `window.outerdimensions`
- `webgl.vendor` / `sourceurl` / `defaultArgs`

**Plus Extra Stealth Layer:**
- Deep webdriver property cleanup
- Permissions API spoofing
- Chrome runtime emulation
- Connection API spoofing
- Stack trace cleanup (removes playwright/puppeteer traces)
- Notification permission normalization

## 🔄 Dual Mode

Run `--dual-mode` to execute both STEALTH and OBSERVE scans, then compare:

```
  📊 DUAL MODE COMPARISON
  Metric                    STEALTH         OBSERVE
  ───────────────────────────────────────────────
  Risk Score                62              48
  Total Events              1247            869
  Categories                14              9
```

This reveals whether the target website **behaves differently** when it detects automation.

## 📊 Output

Each scan generates 3 files in `./output/`:
- `*_report.json` — Structured metrics, threats, risk score
- `*_report.html` — Visual dashboard with threat assessment
- `*_context-map.json` — Frame/origin hierarchy

## ⚠️ FingerprintJS v5 Detection

Sentinel v3 automatically detects the **FingerprintJS v5 signature** pattern:
- Canvas `isPointInPath` + audio fingerprinting + font detection + math fingerprinting
- Triggers a CRITICAL threat alert when detected

## License

MIT
