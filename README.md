# SENTINEL v7.0.0 — Hybrid Dual-Telemetry Forensic Engine

> **PURE NEW CONCEPT** — No backward compatibility.

## Quick Start

```bash
npm install
node index.js https://browserscan.net --dual-mode --no-headless
node index.js https://example.com --no-headless
node index.js https://browserscan.net --dual-mode --no-headless --timeout=60000 --wait=30000
```

## CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--dual-mode` | off | Run observe + stealth passes sequentially |
| `--no-headless` | headless | Show visible browser window |
| `--no-stealth` | stealth on | Disable stealth plugin |
| `--timeout=<ms>` | 60000 | Navigation timeout |
| `--wait=<ms>` | 30000 | Post-load observation time |
| `--persist=<dir>` | auto-temp | Persistent browser profile |

## Tests

```bash
npm test                  # 28 regression rules
npm run test:injection    # Script content validation
npm run test:full         # All tests
```
