import path from "node:path";
import { runSentinel } from "./sentinel.js";
import type { PolicyConfig, RunOptions } from "./types.js";

const url = process.argv[2];
const outDir = process.argv[3] ? path.resolve(process.argv[3]) : path.resolve("out");

if (!url) {
  console.error(`
\ud83d\udee1\ufe0f Sentinel Owner Mode \u2014 Usage:

  npm start -- <url> [outputDir]

Examples:
  npm start -- "https://example.com" ./out
  SENTINEL_MODE=lockdown npm start -- "https://example.com" ./out
  HEADLESS=0 WAIT_MS=30000 npm start -- "https://example.com" ./out

Environment Variables:
  SENTINEL_MODE  = audit | lockdown   (default: audit)
  HEADLESS       = 1 | 0             (default: 1)
  WAIT_MS        = milliseconds      (default: 15000)
  STACK_RATE     = 0.0 - 1.0         (default: 1)
`);
  process.exit(1);
}

const mode = process.env.SENTINEL_MODE === "lockdown" ? ("lockdown" as const) : ("audit" as const);

const policy: PolicyConfig = {
  mode,
  stackSampleRate: Number(process.env.STACK_RATE || "1"),
  deny: {
    media: mode === "lockdown",
    webrtc: mode === "lockdown",
    clipboardRead: mode === "lockdown",
    filePickers: mode === "lockdown",
    hardware: mode === "lockdown",
    payments: mode === "lockdown",
    webauthn: false,
    geolocation: mode === "lockdown",
    notifications: mode === "lockdown",
  },
};

const opts: RunOptions = {
  headless: (process.env.HEADLESS || "1") !== "0",
  waitTime: Number(process.env.WAIT_MS || "15000"),
  policy,
};

runSentinel(url, outDir, opts).catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
