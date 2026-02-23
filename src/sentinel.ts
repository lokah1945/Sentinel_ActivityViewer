import fs from "node:fs";
import path from "node:path";
import {
  chromium,
  type Browser,
  type BrowserContext,
  type ConsoleMessage,
  type Page,
} from "playwright";
import { JsonlSink, nowIso } from "./sink.js";
import { generateBootstrap } from "./bootstrap.js";
import { installScriptRewriter } from "./rewriter.js";
import { CdpManager } from "./cdp-manager.js";
import { ContextMap, installFrameGuard } from "./frameguard.js";
import { buildReport, saveReport } from "./report.js";
import type { RunOptions } from "./types.js";

function parseAvConsole(msg: ConsoleMessage) {
  const text = msg.text();
  if (!text.startsWith("__AV__|")) return null;
  try {
    return JSON.parse(text.slice(7));
  } catch {
    return null;
  }
}

export async function runSentinel(url: string, outDir: string, opts: RunOptions) {
  fs.mkdirSync(outDir, { recursive: true });
  const startTime = nowIso();

  const pad46 = (s: string) => s.slice(0, 46).padEnd(46);

  console.log(`
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551  \ud83d\udee1\ufe0f  SENTINEL OWNER MODE \u2014 Zero-Trust Observatory       \u2551
\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563
\u2551  Target : ${pad46(url)} \u2551
\u2551  Mode   : ${pad46(opts.policy.mode.toUpperCase())} \u2551
\u2551  Output : ${pad46(outDir)} \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
`);

  const sink = new JsonlSink(path.join(outDir, "events.jsonl"));
  const map = new ContextMap();
  const onEvent = (ev: any) => sink.write(ev);

  const browser: Browser = await chromium.launch({ headless: opts.headless });
  const context: BrowserContext = await browser.newContext({
    recordHar: { path: path.join(outDir, "session.har"), content: "embed" },
  });

  await context.tracing.start({ screenshots: true, snapshots: true, sources: true });

  const bootstrap = generateBootstrap(opts.policy);

  // LAYER A: addInitScript - runs at document_start
  await context.addInitScript(bootstrap);

  // LAYER C: Script route rewriting - prepend to ALL JS
  await installScriptRewriter(context, bootstrap);

  // FrameGuard: Node-side context inventory
  installFrameGuard(context, map, onEvent);

  // Console transport
  context.on("page", (p) => {
    p.on("console", (msg) => {
      const ev = parseAvConsole(msg);
      if (ev) sink.write(ev);
    });
  });

  // Service Worker lifecycle
  context.on("serviceworker", (sw) => {
    sink.write({ ts: nowIso(), type: "sw:detected", url: sw.url() });
  });

  // Network telemetry
  context.on("request", (req) => {
    sink.write({
      ts: nowIso(),
      type: "net:request",
      url: req.url(),
      method: req.method(),
      resourceType: req.resourceType(),
      isNavigation: req.isNavigationRequest(),
      viaServiceWorker: !!req.serviceWorker(),
    });
  });

  context.on("response", (res) => {
    sink.write({
      ts: nowIso(),
      type: "net:response",
      url: res.url(),
      status: res.status(),
      fromServiceWorker: res.fromServiceWorker(),
    });
  });

  // LAYER B: CDP auto-attach - covers workers/hidden targets
  const cdp = new CdpManager(onEvent, bootstrap);
  await cdp.attach(browser);

  sink.write({ ts: nowIso(), type: "sentinel:start", url, mode: opts.policy.mode });

  const page: Page = await context.newPage();
  await page.goto(url, { waitUntil: "domcontentloaded" });

  console.log(`\u23f3 Observing for ${opts.waitTime / 1000}s...`);
  await page.waitForTimeout(opts.waitTime);

  // Stop tracing
  await context.tracing.stop({ path: path.join(outDir, "trace.zip") });

  // Save context map
  map.save(path.join(outDir, "context-map.json"));

  sink.write({ ts: nowIso(), type: "sentinel:done", url, events: sink.getCount() });

  await context.close();
  await browser.close();
  sink.close();

  // Build comprehensive report
  const report = buildReport(
    path.join(outDir, "events.jsonl"),
    url,
    startTime,
    opts.policy.mode,
    map
  );
  saveReport(outDir, report);

  console.log(`
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551  \u2705 SENTINEL COMPLETE                                    \u2551
\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563
\u2551  Events captured : ${String(report.meta.totalEvents).padEnd(37)} \u2551
\u2551  Duration        : ${String(report.meta.duration).padEnd(37)} \u2551
\u2551  FP Risk Score   : ${String(report.fingerprinting.riskScore + "/100").padEnd(37)} \u2551
\u2551  3rd Party       : ${String(report.networkSummary.thirdPartyDomains.length + " domains").padEnd(37)} \u2551
\u2551  Evasion signals : ${String(report.evasionIndicators.blobUrls + report.evasionIndicators.hiddenFrames + report.evasionIndicators.zeroSizeFrames).padEnd(37)} \u2551
\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563
\u2551  Output: ${outDir.slice(0, 48).padEnd(48)} \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
`);
}
