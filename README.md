# 🛡️ Sentinel v4.4.1 — Zero Blind Spot Forensic Browser Activity Catcher

## Apa yang Baru di v4.4.1?

### Bug Kritis v4.4 yang Diperbaiki

v4.4 hanya menangkap **3-4 events** (seharusnya 786+). Root cause:

| Bug | Masalah | Perbaikan |
|-----|---------|-----------|
| **#1 CRITICAL** | Navigator hooks di PROTOTYPE di-shadow oleh stealth patches di INSTANCE | `smartHookGetter()` — deteksi otomatis apakah getter ada di prototype atau instance, hook yang benar |
| **#2** | Property-enum log SEMUA `Object.keys()` calls (noise) | Filter hanya navigator/screen targets (seperti v4.1) |
| **#3** | `document.cookie` hanya getter yang di-hook (setter terlewat) | `hookGetterSetter()` — getter + setter keduanya di-hook |
| **#4** | `createElement` log SEMUA tag elements (noise) | Filter hanya tag fingerprint-relevant: canvas, iframe, audio, video, etc. |
| **#5** | Shield tidak punya `hookGetterSetter()` | Ditambahkan method baru di anti-detection-shield |

### Arsitektur 7 Layer

1. **addInitScript PRIMARY** — metode terbukti dari v3/v4.1
2. **Anti-Detection Shield** — WeakMap descriptor cache + toString protection
3. **Stealth Config** — playwright-extra + custom patches
4. **API Interceptor** — 200+ hooks, 37 kategori, smart target detection
5. **CDP Supplement** — push telemetry + iframe auto-attach
6. **Correlation Engine** — burst/slow-probe/attribution detection
7. **Report Generator** — JSON + HTML + 1H5W forensic reports

## Instalasi

```bash
npm install
```

## Penggunaan

```bash
# Quick scan (stealth mode default)
node index.js https://browserscan.net

# Observe mode (tanpa stealth)
node index.js https://browserscan.net --observe

# Tampilkan browser
node index.js https://browserscan.net --no-headless

# Dual mode (bandingkan observe vs stealth)
node index.js https://browserscan.net --dual-mode --no-headless

# Custom timeout & locale
node index.js https://browserscan.net --timeout=60000 --locale=en-US --timezone=America/New_York
```

## Test Injection

```bash
node test-injection.js https://browserscan.net
```

## Target Expected Results

| Metric | v4.4 (broken) | v4.4.1 (fixed) | v4.1 (baseline) |
|--------|--------------|----------------|-----------------|
| Events | 3-4 | 500+ | 786 |
| Categories | 2-3/37 | 15+/37 | 17/31 |
| Coverage | 5-8% | 80%+ | 100% |
| BOOT_OK | 1 | 20+ | 20 |
| Risk Score | 4-6 | 80+ | 100 |

## Troubleshooting

**Jika events masih sedikit:**
1. Jalankan `node test-injection.js <url>` untuk verifikasi injection
2. Coba `--no-headless` untuk melihat browser
3. Periksa apakah site butuh interaksi manual (klik, scroll)
4. Tambah timeout: `--timeout=60000`

**Jika terdeteksi sebagai bot:**
1. Pastikan `puppeteer-extra-plugin-stealth` terinstall
2. Gunakan `--no-headless` (headless lebih mudah terdeteksi)
3. Coba locale yang sesuai: `--locale=id`
