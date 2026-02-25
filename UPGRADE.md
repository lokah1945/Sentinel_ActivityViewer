# 🛡️ SENTINEL v5.1.0 — Upgrade from v5.0.0

## Instruksi Upgrade (3 Langkah)

### Langkah 1: Copy file baru ke folder v5.0.0

```bash
# Dari folder upgrade ini, copy ke folder Sentinel yang sudah ada:
cp package.json /path/to/SentinelActivityViewer/package.json
cp index.js /path/to/SentinelActivityViewer/index.js
cp hooks/stealth-config.js /path/to/SentinelActivityViewer/hooks/stealth-config.js
```

Atau manual:
- Replace `package.json` dengan yang baru
- Replace `index.js` dengan yang baru
- Replace `hooks/stealth-config.js` dengan yang baru

### Langkah 2: Install dependencies baru

```bash
cd /path/to/SentinelActivityViewer
npm install
```

Ini akan menginstall 2 package baru:
- `playwright-extra` — drop-in replacement untuk playwright dengan plugin support
- `puppeteer-extra-plugin-stealth` — 10+ evasion modules anti-bot

### Langkah 3: Jalankan

```bash
node index.js https://browserscan.net --dual-mode --no-headless
```

## Apa yang Berubah di v5.1?

### File yang BERUBAH (3 file):
1. **package.json** — Tambah `playwright-extra` + `puppeteer-extra-plugin-stealth`
2. **index.js** — Gunakan `playwright-extra`, stealth plugin, fix window size, human behavior
3. **hooks/stealth-config.js** — Fix outerWidth/outerHeight, Notification.permission, connection.rtt

### File yang TIDAK BERUBAH (12 file):
- hooks/api-interceptor.js (42 categories, 110+ hooks — UNCHANGED)
- hooks/anti-detection-shield.js (UNCHANGED)
- lib/target-graph.js (UNCHANGED)
- lib/correlation-engine.js (UNCHANGED)
- lib/signature-db.js (UNCHANGED)
- reporters/report-generator.js (UNCHANGED)
- tests/test-regression.js (UNCHANGED)
- tests/test-stress.js (UNCHANGED)
- tests/test-injection.js (UNCHANGED)
- CHANGELOG.md
- README.md
- .gitignore

## Root Cause Analysis: Kenapa v5.0 Terdeteksi Bot

### Bukti dari 4 scan report:

| Metric | Observe #1 | Stealth #1 | Observe #2 | Stealth #2 |
|--------|-----------|-----------|-----------|-----------|
| Events | 1868 | 1958 | 2297 | 1911 |
| Categories | 21/42 | 21/42 | 22/42 | 21/42 |
| Sub-frames | 14 | 19 | 19 | 17 |
| Network | 220 | 254 | 294 | 254 |

### 🚨 SMOKING GUN: outerWidth/outerHeight

```
screen.width = 1280      ✅ OK
screen.height = 720       ✅ OK
window.outerWidth = 160   ❌ CRITICAL! (seharusnya ~1296)
window.outerHeight = 28   ❌ CRITICAL! (seharusnya ~808)
```

**BrowserScan mengecek ini sebagai indikator bot #1.**
Browser headless/automation memiliki outerWidth/outerHeight = 0 atau sangat kecil.
Browser normal selalu punya outerWidth ≈ innerWidth + 16, outerHeight ≈ innerHeight + 88.

### Fix di v5.1:
1. `--window-size=1296,808` pada launch args (viewport + chrome decoration)
2. `page.setViewportSize()` explicit call
3. Stealth config fallback: override outerWidth/outerHeight jika < 400
4. **playwright-extra + stealth plugin** yang punya `window.outerdimensions` evasion

### Tambahan Anti-Bot dari Stealth Plugin:
- `chrome.app` — polyfill lengkap
- `chrome.csi` — consistent timing values
- `chrome.loadTimes` — navigation timing
- `iframe.contentWindow` — fix cross-origin detection
- `media.codecs` — simulate real codec support
- `navigator.plugins` — proper PluginArray/MimeTypeArray
- `source.url` — hide injected script source URLs
- `user-agent-override` — consistent UA across all APIs
- `webgl.vendor` — consistent renderer info
- `window.outerdimensions` — fix outerWidth/outerHeight

### Human-Like Behavior (baru di v5.1):
- Random mouse movements sebelum scroll
- Variable scroll speed
- Random delays (±2 detik) pada setiap aksi
- Smooth scroll behavior
