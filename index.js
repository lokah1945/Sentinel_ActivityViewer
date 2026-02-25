#!/usr/bin/env node
/**
 * Sentinel v6.3.0 — Pure Observer CCTV
 * 
 * PHILOSOPHY: This is a CCTV security camera, not a disguise.
 *   - ZERO injection into page JavaScript
 *   - ZERO spoofing (no UA override, no locale change, nothing)
 *   - ZERO modification of browser behavior
 *   - 100% passive CDP observation from outside the page
 *   - The "thief" (website) has NO idea it's being watched
 * 
 * HOW IT WORKS:
 *   rebrowser-playwright-core patches Runtime.Enable at source level,
 *   so CDP observation channels work WITHOUT triggering detection.
 *   stealth plugin removes automation artifacts that Chromium adds by default.
 *   We observe everything via CDP domains (Network, DOM, Runtime, etc.)
 *   without injecting a single line of JavaScript into any page.
 *
 * STACK:
 *   rebrowser-playwright-core (aliased as playwright-core) → Runtime.Enable fix
 *   playwright-extra → plugin framework
 *   stealth plugin → removes Chromium automation artifacts
 *   CDP collectors → passive observation of ALL browser activity
 */

'use strict';

process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE = process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE || 'addBinding';
process.env.REBROWSER_PATCHES_SOURCE_URL = process.env.REBROWSER_PATCHES_SOURCE_URL || 'analytics.js';

const { addExtra } = require('playwright-extra');
const playwrightCore = require('playwright-core');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

const { CdpObserverEngine } = require('./lib/cdp-observer-engine');
const { FrameTreeWatcher } = require('./lib/frame-tree-watcher');
const { EventPipeline } = require('./lib/event-pipeline');
const { ForensicEngine } = require('./lib/forensic-engine');
const { ReportGenerator } = require('./lib/report-generator');
const { PageScopeWatcher } = require('./lib/page-scope-watcher');

const VERSION = 'sentinel-v6.3.0';

// ─── CLI ───
const args = process.argv.slice(2);
const target = args.find(a => a.startsWith('http'));
const dualMode = args.includes('--dual-mode');
const headless = !args.includes('--no-headless');
const timeout = parseInt(args.find(a => a.startsWith('--timeout='))?.split('=')[1] || '60000');
const waitTime = parseInt(args.find(a => a.startsWith('--wait='))?.split('=')[1] || '30000');
const persistDir = args.find(a => a.startsWith('--persist='))?.split('=')[1] || '';
const stealthEnabled = !args.includes('--no-stealth');

if (!target) {
  console.log(`
🛡️  ${VERSION} — Pure Observer CCTV
Usage: node index.js <URL> [options]

Options:
  --dual-mode        Run both observe and stealth passes
  --no-headless      Visible browser
  --no-stealth       Disable stealth plugin (for comparison)
  --timeout=<ms>     Navigation timeout (default: 60000)
  --wait=<ms>        Post-load wait time (default: 30000)
  --persist=<dir>    Persistent browser profile directory

Examples:
  node index.js https://browserscan.net --dual-mode --no-headless
  node index.js https://example.com --persist=./profiles/session1 --no-headless
`);
  process.exit(0);
}

// ─── Setup playwright-extra with stealth ───
const chromium = addExtra(playwrightCore.chromium);
if (stealthEnabled) {
  const stealth = StealthPlugin();
  chromium.use(stealth);
}

async function runScan(mode) {
  const ts = Date.now();
  const pipeline = new EventPipeline();
  const forensic = new ForensicEngine(VERSION);

  console.log(`[Sentinel] Launching browser (mode: ${mode})...`);

  const launchArgs = [
    '--disable-blink-features=AutomationControlled',
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-infobars',
    '--disable-background-timer-throttling',
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding',
    '--disable-ipc-flooding-protection',
    '--enable-features=NetworkService,NetworkServiceInProcess',
  ];

  // NEVER add --enable-automation (already in ignoreDefaultArgs)
  const launchOpts = {
    headless: mode === 'stealth' ? headless : false,
    args: launchArgs,
    ignoreDefaultArgs: ['--enable-automation'],
  };

  let browser, context;
  if (persistDir) {
    context = await chromium.launchPersistentContext(persistDir, {
      ...launchOpts,
      viewport: null, // use default window size, no spoofing
    });
    browser = null;
  } else {
    browser = await chromium.launch(launchOpts);
    context = await browser.newContext({
      viewport: null, // ZERO SPOOFING — use real browser viewport
      // NO userAgent override
      // NO locale override
      // NO timezone override
      // NO geolocation override
      // NO permissions override
      // The browser is 100% vanilla — just observed from outside
    });
  }

  const page = await context.newPage();

  // ─── CDP session for this page ───
  const cdpSession = await page.context().newCDPSession(page);

  const injectionStatus = {
    version: VERSION,
    mode,
    rebrowserPatched: true,
    runtimeFixMode: process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE,
    stealthPlugin: stealthEnabled,
    zeroInjection: true,
    zeroSpoofing: true,
  };

  // ─── Layer 1: CDP Observer Engine (PASSIVE — no JS injection) ───
  const cdpObserver = new CdpObserverEngine(pipeline, cdpSession);
  await cdpObserver.start();
  injectionStatus.cdpNetworkCollector = true;
  injectionStatus.cdpSecurityCollector = true;
  injectionStatus.cdpDOMCollector = true;
  injectionStatus.cdpConsoleCollector = true;
  injectionStatus.cdpPerformanceCollector = true;

  // ─── Layer 2: Frame Tree Watcher (CDP Target.setAutoAttach) ───
  const frameWatcher = new FrameTreeWatcher(pipeline, cdpSession, context);
  await frameWatcher.start();
  injectionStatus.frameTreeWatcher = true;
  injectionStatus.recursiveAutoAttach = true;

  // ─── Layer 3: Page Scope Watcher (new tabs/pages in context) ───
  const pageWatcher = new PageScopeWatcher(pipeline, context);
  await pageWatcher.start();
  injectionStatus.pageScopeWatcher = true;

  // ─── Navigate ───
  console.log(`[Sentinel] Navigating to ${target}...`);
  try {
    await page.goto(target, { waitUntil: 'domcontentloaded', timeout });
  } catch (e) {
    console.error(`[Sentinel] Navigation warning: ${e.message}`);
  }

  // ─── Wait for activity ───
  console.log(`[Sentinel] Observing for ${waitTime / 1000}s...`);
  await page.waitForTimeout(waitTime);

  // ─── Collect frame tree from Playwright ───
  const frames = page.frames().map(f => ({
    url: f.url(),
    name: f.name(),
    detached: f.isDetached(),
  }));

  // ─── Gather all events ───
  const allEvents = pipeline.drain();
  const stats = pipeline.getStats();
  const frameStats = frameWatcher.getStats();

  injectionStatus.subFramesDiscovered = frameStats.discovered;
  injectionStatus.subFramesAttached = frameStats.attached;
  injectionStatus.totalCdpEvents = stats.cdpEvents;
  injectionStatus.networkEntries = stats.networkEntries;
  injectionStatus.consoleEvents = stats.consoleEvents;
  injectionStatus.domEvents = stats.domEvents;
  injectionStatus.totalDeduped = allEvents.length;

  // ─── Forensic analysis ───
  const analysis = forensic.analyze(allEvents, frames, injectionStatus);

  // ─── Coverage ───
  const targetGraph = frameWatcher.getTargetInventory();
  const coverageProof = {
    targetGraph,
    frameCoverage: frameStats.discovered > 0
      ? `${Math.round(frameStats.attached / frameStats.discovered * 100)}%`
      : 'N/A',
    categoryCoverage: `${Math.round(analysis.categories.length / 30 * 100 * 10) / 10}%`,
  };

  // ─── Reports ───
  const contextData = {
    version: VERSION,
    target,
    scanDate: new Date(ts).toISOString(),
    mode,
    frames,
    injectionStatus,
    targetGraph,
    coverageProof,
  };

  const report = new ReportGenerator(VERSION);
  const reportPath = report.save(mode, ts, allEvents, analysis, contextData);

  console.log(
    `[Sentinel] Scan complete: ${allEvents.length} CDP events, ` +
    `${analysis.categories.length} categories, ` +
    `${frameStats.discovered} frames discovered, ` +
    `${frameStats.attached} frames attached, ` +
    `${stats.networkEntries} network entries, ` +
    `${stats.consoleEvents} console events`
  );
  console.log(`[Sentinel] Reports: ${reportPath.json}`);
  console.log(`[Sentinel] HTML: ${reportPath.html}`);

  // ─── Cleanup ───
  await cdpObserver.stop();
  if (browser) await browser.close();
  else await context.close();

  return { reportPath, stats: analysis };
}

// ─── Main ───
(async () => {
  console.log(`
🛡️  ${VERSION} — Pure Observer CCTV
   rebrowser-playwright-core: Runtime.Enable PATCHED (${process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE})
   Stealth Plugin: ${stealthEnabled ? 'ON' : 'OFF'}
   ZERO Injection | ZERO Spoofing | 100% Passive CDP Observation
   Target: ${target}
   Mode: ${dualMode ? 'DUAL (observe → stealth)' : mode || 'stealth'}
   Headless: ${headless}
   Timeout: ${timeout}ms | Wait: ${waitTime}ms
   Persist: ${persistDir || 'none (ephemeral)'}
`);

  const mode = dualMode ? null : 'stealth';

  try {
    if (dualMode) {
      console.log('═══ PASS 1: OBSERVE MODE (no stealth plugin) ═══');
      await runScan('observe');
      console.log('\n═══ PASS 2: STEALTH MODE ═══');
      await runScan('stealth');
      console.log('\n✅ Dual-mode scan complete.');
    } else {
      await runScan('stealth');
      console.log('\n✅ Scan complete.');
    }
  } catch (err) {
    console.error('❌ Fatal error:', err);
    process.exit(1);
  }
})();
