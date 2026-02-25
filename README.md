# 🛡️ Sentinel v5.0.0 — Unified Forensic Engine

> **Zero Spoofing | Zero Blind Spot | Zero Regression**

Sentinel adalah alat forensik browser yang memantau dan merekam semua aktivitas fingerprinting yang dilakukan oleh website terhadap browser Anda. Versi 5.0.0 adalah unifikasi seluruh fitur dari v3.0 hingga v4.6.3.

## Fitur Utama

- **42 Kategori Deteksi** — Canvas, WebGL, Audio, Font, WebRTC, Math, Battery, dll
- **110+ Hook Points** — Monitoring komprehensif terhadap semua API browser
- **Bidirectional Network Capture** — Rekam request DAN response (full conversation)
- **Recursive Auto-Attach** — Monitor nested iframe dan worker secara otomatis
- **Worker Pipeline** — Tangkap aktivitas di Web Worker, Shared Worker, Service Worker
- **Quiet Mode** — Non-enumerable globals, zero console output, marker randomization
- **Zero Spoofing** — Tidak ada pemalsuan UA/WebGL/timezone, hanya cleanup marker otomasi
- **HTML Dashboard** — Report forensik dengan dark theme, 1H5W analysis, threat assessment
- **25 Regression Rules** — Test otomatis yang mencegah fitur hilang saat upgrade

## Instalasi

```bash
# Ekstrak ZIP
unzip sentinel-v5.0.0.zip
cd sentinel-v5.0.0

# Install dependencies (hanya playwright)
npm install
```

## Penggunaan

```bash
# Scan default (stealth mode, headless)
node index.js https://www.browserscan.net

# Tampilkan browser
node index.js https://www.browserscan.net --no-headless

# Dual mode (observe → stealth comparison)
node index.js https://www.browserscan.net --dual-mode --no-headless

# Observe mode
node index.js https://www.browserscan.net --observe --no-headless

# Verbose (debug target graph)
node index.js https://www.browserscan.net --verbose --no-headless

# Custom locale & timezone
node index.js https://www.browserscan.net --locale=id --timezone=Asia/Jakarta
```

## Test Suite

```bash
# Regression gate (25 rules dari bug historis v3-v4.6.3)
npm test

# Stress test (1000 iterasi)
npm run test:stress

# Injection diagnostic (butuh browser)
npm run test:injection

# Full test suite
npm run test:full
```

## Struktur File

```
sentinel-v5.0.0/
├── index.js                    # Main orchestrator (10-layer pipeline)
├── hooks/
│   ├── api-interceptor.js      # 42 kategori, 110+ hooks, smartHookGetter
│   ├── anti-detection-shield.js # Shield + Quiet Mode + WeakMap cache
│   └── stealth-config.js       # MINIMAL (<80 lines) automation cleanup
├── lib/
│   ├── target-graph.js         # Recursive auto-attach + Worker pipeline
│   ├── correlation-engine.js   # Burst/slow-probe/cross-frame analysis
│   └── signature-db.js         # FPv5/CreepJS/BotD pattern matching
├── reporters/
│   └── report-generator.js     # JSON + HTML + CTX unified report
├── tests/
│   ├── test-regression.js      # 25 regression rules
│   ├── test-stress.js          # 1000-iteration stress test
│   └── test-injection.js       # Quick browser diagnostic
├── package.json
├── CHANGELOG.md
└── README.md
```

## Output

Setelah scan, folder `./output` berisi:
- `sentinel-{mode}-{timestamp}-report.json` — Data forensik lengkap
- `sentinel-{mode}-{timestamp}-report.html` — Dashboard visual (dark theme)
- `sentinel-{mode}-{timestamp}-context.json` — Frame & injection metadata

## 3 Aturan Emas (Anti-Regresi)

1. **JANGAN PERNAH rewrite file dari nol** — Selalu mulai dari yang sudah bekerja
2. **JANGAN PERNAH hapus hook tanpa menambah test regression rule**
3. **JALANKAN `npm test` sebelum setiap deploy** — Semua 25 rule harus PASS

## Dependency

Hanya **playwright** — tidak ada playwright-extra atau puppeteer-extra-plugin-stealth.

## License

MIT
