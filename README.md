# 🛡️ Sentinel v4.5 — Full Conversation Forensic Catcher

## Philosophy: Pure CCTV Mode
Sentinel v4.5 is a **passive recording system** — like a CCTV camera in a restaurant.
It records everything that happens without interfering.

### What v4.5 Does
- **Records ALL API calls** that fingerprinting scripts ("maling") make (37 categories, 200+ hooks)
- **Records what browser ANSWERS** to each API call (return values captured)
- **Records ALL network traffic** — both requests AND responses with body previews
- **Generates forensic reports** with 1H5W framework (Who, What, When, Where, Why, How)

### What v4.5 Does NOT Do
- ❌ No User Agent spoofing
- ❌ No language/locale spoofing
- ❌ No platform spoofing
- ❌ No WebGL/Canvas spoofing
- ❌ No plugin/mimeType spoofing
- ❌ No stealth plugin (playwright-extra removed)
- ✅ Only removes automation markers (navigator.webdriver, __playwright)

## Installation
```bash
npm install
```

## Usage
```bash
# Quick scan (headless)
node index.js https://browserscan.net

# Show browser window
node index.js https://browserscan.net --no-headless

# Dual mode (observe vs stealth comparison)
node index.js https://browserscan.net --dual-mode --no-headless

# Custom timeout
node index.js https://browserscan.net --timeout=60000 --no-headless

# Observe only (no automation cleanup at all)
node index.js https://browserscan.net --observe --no-headless
```

## What Changed from v4.4.2

| Feature | v4.4.2 | v4.5 |
|---------|--------|------|
| Spoofing | UA, locale, timezone | **NONE** |
| stealth plugin | playwright-extra | **Removed** |
| Network capture | Not included | **Full bidirectional** |
| Value capture | 200 char, no direction | **500 char + call/response** |
| Browser profile | Ephemeral (incognito-like) | **Persistent + auto-cleanup** |
| Report sections | API events only | **API + Network Conversation** |
| timeSpanMs | Bug (last event ts) | **Fixed (max ts)** |
| Coverage | Bug (count about:blank) | **Fixed (HTTP frames only)** |

## Report Outputs
Each scan produces 3 files in `output/`:
- `*_report.json` — Full forensic data including network conversation
- `*_report.html` — Visual HTML report with all sections
- `*_context.json` — Frame/injection context metadata

## Architecture
```
index.js                    — Main scanner (pure Playwright, persistent context)
├── hooks/
│   ├── api-interceptor.js  — 200+ API hooks (UNCHANGED from v4.4.1)
│   ├── anti-detection-shield.js — Shield for hook protection
│   └── stealth-config.js   — Automation marker cleanup ONLY
├── reporters/
│   └── report-generator.js — Report with network conversation
└── lib/
    ├── correlation-engine.js — Burst/pattern correlation
    └── signature-db.js      — Known fingerprinting signatures
```
