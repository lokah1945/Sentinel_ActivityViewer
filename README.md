# Sentinel Activity Viewer v4.4.2

**"Reliability + Coverage + Consistency" Release**

## Apa Itu Sentinel?

Sentinel adalah alat forensik browser yang mendeteksi dan mendokumentasikan aktivitas fingerprinting/tracking yang dilakukan oleh website terhadap pengunjung. Ibarat **satpam restoran** yang mengawasi dan mencatat apa yang dilakukan setiap "maling" (script fingerprinting) di dalam "restoran" (browser Anda).

## Apa yang Baru di v4.4.2?

### Bug Fixes dari v4.4.1
1. **CoverageProof** — Frame inventory sekarang menggunakan url/origin yang valid, bukan `undefined`
2. **timeSpanMs** — Menggunakan `max(ts)` bukan `last(events).ts`, sehingga durasi akurat
3. **InjectionStatus** — Flag injeksi yang sebenarnya dikirim ke report generator
4. **Anti-stuck [5/7]** — Evaluasi frame paralel dengan timeout, skip about:blank
5. **Push telemetry** — Data mengalir real-time ke Node.js via CDP binding
6. **Persistent context** — Opsi `--persistent` untuk menghindari deteksi "incognito"
7. **Auto-attach target (L3)** — Cross-origin iframe dan worker termonitor
8. **Final flush** — Event di detik-detik terakhir tidak hilang

### Arsitektur 7-Layer
| Layer | Komponen | Metode |
|-------|----------|--------|
| 1 | CDP Supplement | Push telemetry + auto-attach |
| 2 | Anti-Detection Shield | WeakMap descriptor cache + toString |
| 3 | API Interceptor | 200+ hooks, 37 kategori, smartHookGetter |
| 4 | Stealth Config | Automation marker cleanup (NO spoofing) |
| 5 | Correlation Engine | Burst/slow-probe/attribution/entropy |
| 6 | Signature DB | BrowserScan, FPv5, CreepJS, BotD, GA |
| 7 | Report Generator | JSON + HTML + Context Map + 1H5W |

## Instalasi

```bash
npm install
```

## Penggunaan

```bash
# Stealth mode (default — recommended)
node index.js https://browserscan.net

# Observe mode (tanpa stealth patches)
node index.js https://browserscan.net --observe

# No headless (tampilkan browser)
node index.js https://browserscan.net --no-headless

# Persistent context (anti-incognito)
node index.js https://browserscan.net --persistent

# Custom profile directory
node index.js https://browserscan.net --profile-dir=/path/to/profile

# Custom locale & timezone
node index.js https://browserscan.net --locale=id --timezone=Asia/Jakarta

# Custom timeout (90 detik)
node index.js https://browserscan.net --timeout=90000

# Dual mode (stealth vs observe comparison)
node index.js https://browserscan.net --dual-mode

# Test injection saja
node test-injection.js https://browserscan.net
```

## Output

Semua output disimpan di folder `output/`:
- `sentinel_<mode>_<timestamp>_report.json` — Laporan forensik lengkap
- `sentinel_<mode>_<timestamp>_report.html` — Dashboard HTML interaktif
- `sentinel_<mode>_<timestamp>_context.json` — Frame coverage & injection status

## Catatan Penting

- **Tidak ada spoofing** — Sentinel hanya mendeteksi & mencatat, tidak memalsukan fingerprint
- **Stealth = membersihkan artefak otomasi** (navigator.webdriver, cdc_, chrome.runtime) — bukan spoofing UA/WebGL
- **Persistent context** mengurangi flag "incognito" karena browser menyimpan data sesi ke disk
- Gunakan `--no-headless` untuk debugging visual
