# Sentinel Activity Viewer v4.4.2

**Surgical Fixes on v4.4.1 (WORKING — 1512 events captured)**

## Apa yang Berubah dari v4.4.1?

v4.4.2 adalah perbaikan **SURGICAL** di atas v4.4.1 yang sudah terbukti bekerja.
Semua kode interceptor, shield, dan stealth TIDAK DIUBAH — hanya bug reporting
dan stabilitas pipeline yang diperbaiki.

### Perbaikan:
1. **Persistent context** (`--persistent`) — hindari deteksi "incognito"
2. **Anti-stuck [5/7]** — evaluasi frame paralel dengan timeout 3 detik
3. **Final flush** — tidak ada event hilang di detik-detik terakhir
4. **Injection flags akurat** — L1/L2/L3 status benar di report
5. **Frame info proper** — url/origin valid, tidak ada null di unmonitored
6. **timeSpanMs fix** — menggunakan max(ts) bukan last event ts
7. **CoverageProof fix** — filter null/blank frames dari perhitungan

### Yang TIDAK Diubah (proven working):
- api-interceptor.js — 55 hookFn, 9 hookGetter, 5 smartHookGetter (200+ hooks)
- anti-detection-shield.js — WeakMap descriptor cache + toString protection
- stealth-config.js — all stealth patches identical to v4.4.1
- correlation-engine.js — burst/slow-probe/attribution analysis
- signature-db.js — 5 library signatures

## Instalasi

```bash
npm install
```

## Penggunaan

```bash
# Stealth mode (default)
node index.js https://browserscan.net

# Observe mode
node index.js https://browserscan.net --observe

# Non-headless (tampilkan browser)
node index.js https://browserscan.net --no-headless

# Persistent context (anti-incognito)
node index.js https://browserscan.net --persistent --no-headless

# Dual mode comparison
node index.js https://browserscan.net --dual-mode

# Custom timeout (45 detik)
node index.js https://browserscan.net --timeout=45000
```

## Expected Results

| Metric | v4.4.1 (baseline) | v4.4.2 (target) |
|--------|-------------------|-----------------|
| Events | 1,512 | 1,500+ |
| Categories | 19/37 | 19-25/37 |
| timeSpanMs | 0 (BUG) | ~25,000 (fixed) |
| Coverage | 50% (BUG) | 80-100% (fixed) |
| Injection flags | L1=false (BUG) | L1/L2/L3 accurate |
