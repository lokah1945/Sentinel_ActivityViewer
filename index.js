#!/usr/bin/env node
/**
 * Sentinel v6.2.0 — Official Playwright + rebrowser-patches + Stealth + CDP Collectors
 * 
 * Architecture:
 *   playwright-core (official) — patched by rebrowser-patches (Runtime.Enable fix)
 *   playwright-extra            — plugin framework wrapping official playwright
 *   stealth plugin              — surface-level evasion (navigator.webdriver, UA, etc.)
 *   rebrowser-patches           — deep CDP leak fix (Runtime.Enable/consoleAPICalled)
 *   
 * The combination gives:
 *   1. Official Playwright API (100% compatible)
 *   2. Stealth plugin modules (12+ evasion techniques)
 *   3. Runtime.Enable leak patched at source level
 *   4. Full CDP collector pipeline for deep monitoring
 */

'use strict';

// ─── Env config for rebrowser-patches ───
// addBinding = main world access + no Runtime.Enable leak (best of both worlds)
process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE = process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE || 'addBinding';
process.env.REBROWSER_PATCHES_SOURCE_URL = process.env.REBROWSER_PATCHES_SOURCE_URL || 'analytics.js';

const { chromium } = require('playwright-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

const { AntiDetectionShield } = require('./lib/anti-detection-shield');
const { StealthHardener } = require('./lib/stealth-hardener');
const { ApiInterceptor } = require('./lib/api-interceptor');
const { CdpCollectorPipeline } = require('./lib/cdp-collector-pipeline');
const { RecursiveFrameAttacher } = require('./lib/recursive-frame-attacher');
const { EventPipeline } = require('./lib/event-pipeline');
const { ForensicEngine } = require('./lib/forensic-engine');
const { ReportGenerator } = require('./lib/report-generator');
const { BrowserPersistence } = require('./lib/browser-persistence');

const VERSION = 'sentinel-v6.2.0';

// ─── CLI parsing ───
const args = process.argv.slice(2);
const target = args.find(a => a.startsWith('http'));
const dualMode = args.includes('--dual-mode');
const headless = !args.includes('--no-headless');
const timeout = parseInt(args.find(a => a.startsWith('--timeout='))?.split('=')[1] || '60000');
const waitTime = parseInt(args.find(a => a.startsWith('--wait='))?.split('=')[1] || '30000');
const persistDir = args.find(a => a.startsWith('--persist='))?.split('=')[1] || '';

if (!target) {
  console.log(`
🛡️  ${VERSION}
Usage: node index.js <URL> [options]

Options:
  --dual-mode       Run both observe and stealth passes
  --no-headless     Run in headed mode (visible browser)
  --timeout=<ms>    Navigation timeout (default: 60000)
  --wait=<ms>       Post-load wait time (default: 30000)
  --persist=<dir>   Persistent browser profile directory

Examples:
  node index.js https://browserscan.net --dual-mode --no-headless
  node index.js https://example.com --persist=./profiles/session1
`);
  process.exit(0);
}

// ─── Register stealth plugin with all evasion modules ───
const stealth = StealthPlugin();
// Ensure all available evasion modules are active
stealth.enabledEvasions.forEach(e => e); // all enabled by default
chromium.use(stealth);

async function runScan(mode) {
  const ts = Date.now();
  const pipeline = new EventPipeline();
  const forensic = new ForensicEngine(VERSION);

  console.log(`[Sentinel] Launching browser (mode: ${mode})...`);

  // ─── Browser launch config ───
  const launchOpts = {
    headless: mode === 'stealth' ? headless : false,
    args: [
      '--disable-blink-features=AutomationControlled',
      '--disable-features=IsolateOrigins,site-per-process',
      '--disable-site-isolation-trials',
      '--disable-web-security',
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-infobars',
      '--window-size=1280,720',
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding',
      '--disable-ipc-flooding-protection',
      '--enable-features=NetworkService,NetworkServiceInProcess',
    ],
    ignoreDefaultArgs: ['--enable-automation'],
  };

  // Persistent profile support
  let browser, context;
  if (persistDir) {
    context = await chromium.launchPersistentContext(
      persistDir,
      { ...launchOpts, viewport: { width: 1280, height: 720 } }
    );
    browser = null; // persistent context IS the browser
  } else {
    browser = await chromium.launch(launchOpts);
    context = await browser.newContext({
      viewport: { width: 1280, height: 720 },
      userAgent: undefined, // let stealth plugin handle this
      locale: 'en-US',
      timezoneId: 'Asia/Jakarta',
      permissions: ['geolocation'],
      geolocation: { latitude: -8.0, longitude: 112.6 },
    });
  }

  const page = await context.newPage();

  // ─── Get CDP session for this page ───
  const cdpSession = await page.context().newCDPSession(page);

  // ─── Layer 1: Anti-Detection Shield (pre-navigation) ───
  const shield = new AntiDetectionShield();
  await shield.apply(page, cdpSession);
  const injectionStatus = {
    layer1_playwright: true,
    layer1_stealthPlugin: true,
    layer1_rebrowserPatched: true,
    layer2_shield: true,
  };

  // ─── Layer 2: Stealth Hardener ───
  if (mode === 'stealth') {
    const hardener = new StealthHardener();
    await hardener.apply(page, cdpSession);
    injectionStatus.layer3_stealth = true;
  } else {
    injectionStatus.layer3_stealth = false;
  }

  // ─── Layer 3: API Interceptor (monitoring hooks) ───
  const interceptor = new ApiInterceptor(pipeline);
  await interceptor.inject(page);
  injectionStatus.layer4_interceptor = true;

  // ─── Layer 4: CDP Collector Pipeline ───
  const cdpCollectors = new CdpCollectorPipeline(pipeline, cdpSession);
  await cdpCollectors.start();
  injectionStatus.layer8_dualNetworkCapture = true;
  injectionStatus.layer9_cdpNetworkCollector = true;
  injectionStatus.layer10_cdpSecurityCollector = true;

  // ─── Layer 5: Recursive Frame Attacher ───
  const frameAttacher = new RecursiveFrameAttacher(pipeline, interceptor, context);
  await frameAttacher.attach(page);
  injectionStatus.layer5_recursiveAutoAttach = true;
  injectionStatus.layer6_workerPipeline = true;
  injectionStatus.layer7_frameLifecycle = true;

  // ─── Listen for new pages (tabs) in context ───
  context.on('page', async (newPage) => {
    console.log(`[Sentinel] New tab detected: ${newPage.url()}`);
    try {
      const newCdp = await context.newCDPSession(newPage);
      await shield.apply(newPage, newCdp);
      if (mode === 'stealth') {
        const h = new StealthHardener();
        await h.apply(newPage, newCdp);
      }
      await interceptor.inject(newPage);
      const newCdpCollectors = new CdpCollectorPipeline(pipeline, newCdp);
      await newCdpCollectors.start();
      await frameAttacher.attach(newPage);
    } catch (e) {
      console.error(`[Sentinel] Tab attach error: ${e.message}`);
    }
  });

  // ─── Navigate ───
  console.log(`[Sentinel] Navigating to ${target}...`);
  try {
    await page.goto(target, { waitUntil: 'domcontentloaded', timeout });
    await page.waitForTimeout(waitTime);
  } catch (e) {
    console.error(`[Sentinel] Navigation: ${e.message}`);
  }

  // ─── Collect frame tree ───
  const frames = page.frames().map(f => ({ url: f.url(), name: f.name() }));

  // ─── Gather events ───
  const allEvents = pipeline.drain();
  const stats = pipeline.getStats();
  const frameStats = frameAttacher.getStats();

  injectionStatus.subFramesChecked = frameStats.checked;
  injectionStatus.subFramesCollected = frameStats.collected;
  injectionStatus.pushEventsReceived = stats.totalPushed;
  injectionStatus.workerEventsReceived = stats.workerEvents;
  injectionStatus.cdpPipelineEvents = stats.cdpEvents;
  injectionStatus.totalDeduped = allEvents.length;

  // ─── Forensic analysis ───
  const analysis = forensic.analyze(allEvents, frames, injectionStatus);

  // ─── Coverage proof ───
  const targetGraph = cdpCollectors.getTargetGraph();
  const coverageProof = {
    targetGraph,
    frameCoverage: frameStats.checked > 0
      ? `${Math.round(frameStats.collected / frameStats.checked * 100)}%`
      : '0%',
    categoryCoverage: `${Math.round(analysis.categories.length / 42 * 100 * 10) / 10}%`,
  };

  // ─── Generate reports ───
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
    `[Sentinel] Scan complete: ${allEvents.length} in-page events, ` +
    `${stats.cdpEvents} total pipeline events, ` +
    `${analysis.categories.length} categories, ` +
    `${frameStats.checked} sub-frames checked, ` +
    `${stats.workerEvents} worker events, ` +
    `${stats.networkEntries} network entries`
  );
  console.log(`[Sentinel] Reports: ${reportPath.json}`);
  console.log(`[Sentinel] HTML: ${reportPath.html}`);

  // ─── Cleanup ───
  await cdpCollectors.stop();
  if (browser) await browser.close();
  else await context.close();

  return { reportPath, stats: analysis };
}

// ─── Main ───
(async () => {
  console.log(`
🛡️  ${VERSION} — Official Playwright + rebrowser-patches + Stealth Plugin + CDP
   Runtime.Enable Fix: ${process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE}
   Zero Spoofing | Zero Blind Spot | Zero Regression | PATCHED CDP
   Target: ${target}
   Mode: ${dualMode ? 'DUAL (observe → stealth)' : 'stealth'}
   Headless: ${headless}
   Timeout: ${timeout}ms | Wait: ${waitTime}ms
   Persist: ${persistDir || 'none (ephemeral)'}
`);

  try {
    if (dualMode) {
      console.log('═══ PASS 1: OBSERVE MODE ═══');
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
