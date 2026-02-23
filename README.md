# Sentinel Owner Mode v2.0

Zero-Trust Browser Security Observatory — simplified single `index.js` entry.

## Quick Start

```bash
cd sentinel-owner-mode
npm install
npx playwright install chromium
node index.js
```

You will be prompted:

```
🛡️  Sentinel Owner Mode v2.0
   Zero-Trust Browser Security Observatory

🎯 Enter target website: example.com
```

The browser opens in **headful** mode, runs the security audit for ~30 seconds,
then closes automatically. Results are saved to `./output/`.

## Output Files

| File | Description |
|------|-------------|
| `output/events.jsonl` | Raw telemetry stream (one JSON object per line) |
| `output/report.json` | Machine-readable summary with risk scoring |
| `output/report.html` | Visual dashboard (open in any browser) |
| `output/context-map.json` | Execution context hierarchy |
| `output/session.har` | Full network recording |
| `output/trace.zip` | Playwright trace (view with `npx playwright show-trace`) |

## Environment Variables (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_MODE` | `audit` | `audit` or `lockdown` (lockdown blocks suspicious calls) |
| `WAIT_MS` | `30000` | How long to observe (milliseconds) |
| `STACK_RATE` | `1` | Stack trace sampling rate 0.0-1.0 |

## View Trace

```bash
npx playwright show-trace output/trace.zip
```

## License

MIT
