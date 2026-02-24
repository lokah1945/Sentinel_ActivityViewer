# 🛡️ Sentinel Activity Viewer v4.4 — Zero Blind Spot

**Forensic Browser Fingerprint Detector** — Menangkap setiap "maling" yang bersembunyi di website.

## Perubahan dari v4.3

### Bug Kritis yang Diperbaiki
1. **Injection Method** — v4.3 menggunakan CDP sebagai primary injection yang gagal total (0 events). v4.4 kembali ke `addInitScript` yang terbukti bekerja di v3 dan v4.1.
2. **Anti-Detection Shield** — v4.3 export function reference, bukan string. CDP stringify gagal menyisipkan ke page context. v4.4 export template string langsung.
3. **runImmediately** — v4.3 set `false`, hooks menunggu navigasi berikutnya dan missed. v4.4 menggunakan addInitScript yang selalu berjalan sebelum page script.
4. **Stealth Plugin** — v4.3 menghapus playwright-extra. v4.4 mengembalikannya.
5. **Locale/Timezone** — v4.3 hardcode America/New_York. v4.4 default ke Asia/Jakarta.
6. **CDP Auto-attach** — v4.3 `waitForDebuggerOnStart: false`. v4.4 `true` untuk inject sebelum iframe jalan.

### Arsitektur v4.4
- **Layer 1**: `addInitScript` PRIMARY injection (proven)
- **Layer 2**: Anti-Detection Shield (WeakMap descriptor cache)
- **Layer 3**: API Interceptor (200+ hooks, 37 kategori)
- **Layer 4**: Stealth Config (playwright-extra + custom patches)
- **Layer 5**: CDP Supplement (push telemetry + iframe monitor)
- **Layer 6**: Correlation Engine
- **Layer 7**: Report Generator (JSON + HTML + 1H5W)

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

# Dual mode (compare stealth vs observe)
node index.js https://browserscan.net --dual-mode

# Custom locale & timezone
node index.js https://browserscan.net --locale=id --timezone=Asia/Jakarta

# Show browser window
node index.js https://browserscan.net --no-headless

# Custom timeout
node index.js https://browserscan.net --timeout=60000
```

## Test Injection

```bash
# Quick diagnostic — verifikasi injection bekerja
node test-injection.js https://browserscan.net
```

## Struktur File

```
├── index.js                    # Main entry point
├── test-injection.js           # Injection diagnostic test
├── hooks/
│   ├── anti-detection-shield.js  # Layer 2: Shield (WeakMap cache)
│   ├── stealth-config.js         # Layer 4: Anti-bot patches
│   └── api-interceptor.js        # Layer 3: 200+ API hooks
├── lib/
│   ├── correlation-engine.js     # Layer 6: Burst/attribution
│   └── signature-db.js           # Layer 7: FPv5/CreepJS patterns
├── reporters/
│   └── report-generator.js       # Layer 7: JSON + HTML reports
└── output/                       # Scan results
```
