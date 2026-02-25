# 🛡️ SENTINEL v5.1.0 — Upgrade dari v5.0.0

## Perubahan dari v5.0.0

### 3 File yang BERUBAH:

1. **`package.json`** — Version bump ke 5.1.0 (dependency TETAP hanya `playwright`)
2. **`index.js`** — Tambah L1.5 CDP webdriver fix, human behavior, --window-size
3. **`hooks/stealth-config.js`** — Tambah CDP leak fix, hapus outerHeight override

### 12 File yang TIDAK BERUBAH:
- `hooks/api-interceptor.js` — 42 categories, 110+ hooks (UNCHANGED)
- `hooks/anti-detection-shield.js` — WeakMap cache, Quiet Mode (UNCHANGED)
- `lib/target-graph.js` — Recursive auto-attach (UNCHANGED)
- `lib/correlation-engine.js` — Burst/slow-probe analysis (UNCHANGED)
- `lib/signature-db.js` — Library attribution (UNCHANGED)
- `reporters/report-generator.js` — JSON + HTML + CTX (UNCHANGED)
- `tests/test-regression.js` — 25 rules (UNCHANGED)
- `tests/test-stress.js` — 1000 iterations (UNCHANGED)
- `tests/test-injection.js` — Quick diagnostic (UNCHANGED)

## Instruksi Upgrade

```bash
# 1. Copy 3 file ke folder SentinelActivityViewer yang sudah ada:
cp package.json /path/to/SentinelActivityViewer/package.json
cp index.js /path/to/SentinelActivityViewer/index.js
cp hooks/stealth-config.js /path/to/SentinelActivityViewer/hooks/stealth-config.js

# 2. HAPUS playwright-extra dan stealth jika pernah diinstall:
cd /path/to/SentinelActivityViewer
npm uninstall playwright-extra puppeteer-extra-plugin-stealth 2>/dev/null
npm install

# 3. Jalankan:
node index.js https://browserscan.net --dual-mode --no-headless
```

## Root Cause: Kenapa v5.1.0-beta (dengan playwright-extra) Masih Terdeteksi

### Bukti dari scan data v5.1.0-beta:

**VECTOR 1: outerHeight INCONSISTENCY**
```
main frame:  outerHeight = 788  (real dari OS)
sub-frames:  outerHeight = 808  (dari stealth-config.js override: 720+88)
```
BrowserScan mengecek outerHeight di SEMUA frames. Jika nilainya BERBEDA antara
main frame dan sub-frames, ini adalah sinyal bot. Browser normal SELALU memiliki
outerHeight yang SAMA di semua frames karena itu properti window.

**Root cause**: stealth-config.js v5.1.0-beta override outerHeight dengan 720+88=808,
tapi OS sudah memberikan nilai asli 788 (karena Windows taskbar). Override ini
KONFLIK dengan nilai asli → inconsistency → terdeteksi.

**Fix**: Hapus override. Trust real values dari --window-size.

**VECTOR 2: playwright-extra CONFLICTS dengan persistent context**
```
v5.0 blueprint: "Persistent context + --use-gl=desktop SUDAH menyediakan
chrome.runtime, chrome.csi, chrome.loadTimes yang ASLI. Tidak perlu polyfill."
```
playwright-extra stealth plugin menimpa chrome.app, chrome.csi, chrome.loadTimes
dengan POLYFILL PALSU. Ini MENGGANTIKAN objek asli yang sudah ada dari persistent
context → BrowserScan mendeteksi perbedaan antara polyfill dan objek native.

**Fix**: Hapus playwright-extra. Kembali ke plain playwright.

**VECTOR 3: CDP Runtime.Enable LEAK**
BrowserScan mendeteksi CDP via console.debug() behavior. Ketika Runtime.Enable aktif,
console.debug() memiliki side-effect yang berbeda dari browser normal.

**Fix**: Patch console.debug di stealth-config.js.

**VECTOR 4: navigator.webdriver TIMING**
addInitScript berjalan SETELAH beberapa deteksi awal BrowserScan.
Page.addScriptToEvaluateOnNewDocument berjalan LEBIH AWAL.

**Fix**: Gunakan CDP Page.addScriptToEvaluateOnNewDocument untuk webdriver fix.
