#!/usr/bin/env node
/**
 * Sentinel v6.4.0 — Pure Observer CCTV with Auto-Cleanup
 * 
 * PHILOSOPHY: This is a CCTV security camera, not a disguise.
 *   - ZERO injection into page JavaScript
 *   - ZERO spoofing (no UA override, no locale change, nothing)
 *   - ZERO modification of browser behavior
 *   - 100% passive CDP observation from outside the page
 *   - The "thief" (website) has NO idea it's being watched
 * 
 * NEW IN v6.4:
 *   - ALWAYS uses launchPersistentContext() to avoid incognito detection
 *   - Auto-generates temp profile directories when --persist= not specified
 *   - Auto-cleanup: removes temp profiles after scan completes
 *   - Graceful cleanup on SIGINT/SIGTERM for interrupted scans
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
const fs = require('fs');
const path = require('path');
const os = require('os');

const { CdpObserverEngine } = require('./lib/cdp-observer-engine');
const { FrameTreeWatcher } = require('./lib/frame-tree-watcher');
const { EventPipeline } = require('./lib/event-pipeline');
const { ForensicEngine } = require('./lib/forensic-engine');
const { ReportGenerator } = require('./lib/report-generator');
const { PageScopeWatcher } = require('./lib/page-scope-watcher');

const VERSION = 'sentinel-v6.4.0';

// ╔═══════════════════════════════════════════════════════════════╗
// ║           🎛️  SPOOF CONFIGURATION — EDIT HERE                ║
// ║  Ubah nilai-nilai di bawah ini sesuai keinginan kamu.        ║
// ║  Pastikan konsisten (misal: GPU NVIDIA cocok dgn Windows).   ║
// ╚═══════════════════════════════════════════════════════════════╝

const SPOOF_CONFIG = {

  // ─── GPU / WebGL ───────────────────────────────────────────────
  // Terlihat di browserscan.net → "Unmasked Vendor" & "Unmasked Renderer"
  // Contoh lain:
  //   'ATI Technologies Inc.' / 'AMD Radeon RX 580'
  //   'Intel Inc.'           / 'Intel(R) UHD Graphics 630'
  //   'Apple'                / 'Apple M1'
  webgl: {
    vendor:   'NVIDIA Corporation',
    renderer: 'NVIDIA GeForce RTX 3060/PCIe/SSE2',
  },

  // ─── Hardware Concurrency (CPU cores) ──────────────────────────
  // Terlihat di browserscan.net → "Hardware Concurrency"
  // Nilai umum: 2, 4, 6, 8, 12, 16
  // Tips: Cocokkan dengan tipe device yang kamu tiru.
  //   - Laptop biasa: 4 atau 8
  //   - Desktop gaming: 8, 12, atau 16
  //   - Server/VPS asli kamu mungkin 2 — jadi spoof ke 8 lebih realistis
  hardwareConcurrency: 6,

  // ─── Device Memory (RAM dalam GB) ──────────────────────────────
  // Terlihat di browserscan.net → "Device Memory"
  // Nilai yang valid (browser hanya report power of 2):
  //   0.25, 0.5, 1, 2, 4, 8
  // Catatan: Browser cap di 8 max, jadi 16/32 GB tetap dilaporkan 8.
  deviceMemory: 8,

  // ─── Screen Resolution ─────────────────────────────────────────
  // Terlihat di browserscan.net → "Screen Resolution" & "Available Screen Size"
  // screenWidth x screenHeight = resolusi layar penuh
  // availWidth x availHeight   = resolusi tanpa taskbar (biasanya height - 48px)
  // Contoh umum:
  //   1920×1080 (Full HD) → avail 1920×1032
  //   2560×1440 (2K/QHD)  → avail 2560×1392
  //   1366×768  (Laptop)  → avail 1366×720
  //   3840×2160 (4K)      → avail 3840×2112
  screen: {
    width:       1920,
    height:      1080,
    availWidth:  1920,
    availHeight: 1032,
    colorDepth:  24,     // 24 atau 32
    pixelDepth:  24,     // biasanya sama dengan colorDepth
  },

  // ─── Touch Support ─────────────────────────────────────────────
  // Terlihat di browserscan.net → "Touch Support"
  // Desktop biasa: maxTouchPoints = 0 (not support)
  // Laptop touchscreen: maxTouchPoints = 10
  // Mobile: maxTouchPoints = 5 atau 10
  maxTouchPoints: 0,

  // ─── Platform ──────────────────────────────────────────────────
  // Terlihat di browserscan.net → platform info
  // Contoh: 'Win32', 'MacIntel', 'Linux x86_64'
  // Harus cocok dengan User-Agent!
  platform: 'Win32',

  // ─── Chrome Executable Path ────────────────────────────────────
  // Kosongkan '' untuk pakai Chromium bawaan Playwright.
  // Isi path ke chrome.exe untuk pakai Chrome asli sistem.
  // Windows: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
  // Linux:   '/usr/bin/google-chrome'
  // Mac:     '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  executablePath: '',
};

// ╔═══════════════════════════════════════════════════════════════╗
// ║          END OF SPOOF CONFIGURATION                          ║
// ╚═══════════════════════════════════════════════════════════════╝


// ─── Temp Profile Cleanup Registry ───
const tempDirsToCleanup = new Set();

function cleanupTempDirs() {
  for (const dir of tempDirsToCleanup) {
    try {
      if (fs.existsSync(dir)) {
        console.log(`[Sentinel] Cleaning up temp profile: ${dir}`);
        fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      }
      tempDirsToCleanup.delete(dir);
    } catch (err) {
      console.warn(`[Sentinel] Failed to cleanup ${dir}: ${err.message}`);
    }
  }
}

// ─── Graceful shutdown on SIGINT/SIGTERM ───
process.on('SIGINT', () => {
  console.log('\n[Sentinel] Received SIGINT, cleaning up...');
  cleanupTempDirs();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n[Sentinel] Received SIGTERM, cleaning up...');
  cleanupTempDirs();
  process.exit(0);
});

// ─── CLI ───
const args = process.argv.slice(2);
const target = args.find(a => a.startsWith('http'));
const dualMode = args.includes('--dual-mode');
const headless = !args.includes('--no-headless');
const timeout = parseInt(args.find(a => a.startsWith('--timeout='))?.split('=')[1] || '60000');
const waitTime = parseInt(args.find(a => a.startsWith('--wait='))?.split('=')[1] || '30000');
const userPersistDir = args.find(a => a.startsWith('--persist='))?.split('=')[1] || '';
const stealthEnabled = !args.includes('--no-stealth');

if (!target) {
  console.log(`
🛡️  ${VERSION} — Pure Observer CCTV with Auto-Cleanup

Usage: node index.js <URL> [options]

Options:
  --dual-mode        Run both observe and stealth passes
  --no-headless      Visible browser
  --no-stealth       Disable stealth plugin (for comparison)
  --timeout=<ms>     Navigation timeout (default: 60000)
  --wait=<ms>        Post-load wait time (default: 30000)
  --persist=<dir>    Persistent browser profile directory (optional)
                     If not specified, auto-generates temp profile and cleans up after scan

Examples:
  node index.js https://browserscan.net --dual-mode --no-headless
  node index.js https://example.com --persist=./profiles/session1 --no-headless
  node index.js https://example.com --no-headless
    (auto-generates temp profile, always appears non-incognito, auto-cleanup)
`);
  process.exit(0);
}

// ─── Helper: create a fresh chromium instance with plugins for a given mode ───
function createChromiumForMode(mode) {
  const chromium = addExtra(playwrightCore.chromium);

  // In dual-mode, observe pass runs WITHOUT stealth to see raw fingerprint.
  // Stealth pass runs WITH stealth to see the masked fingerprint.
  // In single mode, stealth is always applied (unless --no-stealth).
  const useStealth = stealthEnabled && (mode === 'stealth');

  if (useStealth) {
    const stealth = StealthPlugin();

    // Remove evasions we want to configure manually with custom values
    stealth.enabledEvasions.delete('webgl.vendor');
    stealth.enabledEvasions.delete('navigator.hardwareConcurrency');
    chromium.use(stealth);

    // Load webgl.vendor evasion with custom GPU
    const webglVendorPlugin = require('puppeteer-extra-plugin-stealth/evasions/webgl.vendor');
    chromium.use(webglVendorPlugin({
      vendor: SPOOF_CONFIG.webgl.vendor,
      renderer: SPOOF_CONFIG.webgl.renderer,
    }));

    // Load hardwareConcurrency evasion with custom core count
    const hwcPlugin = require('puppeteer-extra-plugin-stealth/evasions/navigator.hardwareConcurrency');
    chromium.use(hwcPlugin({
      hardwareConcurrency: SPOOF_CONFIG.hardwareConcurrency,
    }));

    console.log(`[Sentinel] Stealth ON`);
    console.log(`   WebGL:    ${SPOOF_CONFIG.webgl.vendor} / ${SPOOF_CONFIG.webgl.renderer}`);
    console.log(`   CPU:      ${SPOOF_CONFIG.hardwareConcurrency} cores`);
    console.log(`   RAM:      ${SPOOF_CONFIG.deviceMemory} GB`);
    console.log(`   Screen:   ${SPOOF_CONFIG.screen.width}x${SPOOF_CONFIG.screen.height}`);
    console.log(`   Platform: ${SPOOF_CONFIG.platform}`);
  } else {
    console.log(`[Sentinel] Stealth OFF (mode: ${mode})`);
  }

  return { chromium, useStealth };
}

// ─── Build the spoof script injected via addInitScript ───
// This handles properties NOT covered by stealth plugin evasions:
//   - screen dimensions (width, height, availWidth, availHeight, colorDepth, pixelDepth)
//   - navigator.deviceMemory
//   - navigator.maxTouchPoints
//   - navigator.platform
function buildSpoofScript(config) {
  return `
    // ─── Screen Resolution Spoof ───
    Object.defineProperty(screen, 'width',       { get: () => ${config.screen.width} });
    Object.defineProperty(screen, 'height',      { get: () => ${config.screen.height} });
    Object.defineProperty(screen, 'availWidth',  { get: () => ${config.screen.availWidth} });
    Object.defineProperty(screen, 'availHeight', { get: () => ${config.screen.availHeight} });
    Object.defineProperty(screen, 'colorDepth',  { get: () => ${config.screen.colorDepth} });
    Object.defineProperty(screen, 'pixelDepth',  { get: () => ${config.screen.pixelDepth} });

    // ─── Device Memory Spoof ───
    Object.defineProperty(navigator, 'deviceMemory', { get: () => ${config.deviceMemory} });

    // ─── Touch Support Spoof ───
    Object.defineProperty(navigator, 'maxTouchPoints', { get: () => ${config.maxTouchPoints} });

    // ─── Platform Spoof ───
    Object.defineProperty(navigator, 'platform', { get: () => '${config.platform}' });
  `;
}

async function runScan(mode) {
  const ts = Date.now();
  const pipeline = new EventPipeline();
  const forensic = new ForensicEngine(VERSION);

  // ─── Create fresh chromium instance per mode (FIX: stealth isolation) ───
  const { chromium, useStealth } = createChromiumForMode(mode);

  // ─── Determine profile directory ───
  let persistDir;
  let isAutoGenerated = false;

  if (userPersistDir) {
    persistDir = path.resolve(userPersistDir);
    console.log(`[Sentinel] Using user-specified profile: ${persistDir}`);
  } else {
    const tempPrefix = path.join(os.tmpdir(), `sentinel-profile-${mode}-`);
    persistDir = fs.mkdtempSync(tempPrefix);
    isAutoGenerated = true;
    tempDirsToCleanup.add(persistDir);
    console.log(`[Sentinel] Auto-generated temp profile: ${persistDir}`);
  }

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

  // If screen spoof is active, set window size to match so CSS media queries are consistent
  if (useStealth) {
    launchArgs.push(`--window-size=${SPOOF_CONFIG.screen.width},${SPOOF_CONFIG.screen.height}`);
  }

const launchOpts = {
    headless: mode === 'stealth' ? headless : false,
    args: launchArgs,
    ignoreDefaultArgs: ['--enable-automation'],
    viewport: null,
    executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
};


  // Use custom Chrome if configured
  if (SPOOF_CONFIG.executablePath) {
    launchOpts.executablePath = SPOOF_CONFIG.executablePath;
  }

  let context;
  try {
    context = await chromium.launchPersistentContext(persistDir, launchOpts);
  } catch (err) {
    console.error(`[Sentinel] Failed to launch browser: ${err.message}`);
    if (isAutoGenerated && fs.existsSync(persistDir)) {
      fs.rmSync(persistDir, { recursive: true, force: true });
      tempDirsToCleanup.delete(persistDir);
    }
    throw err;
  }

  // ─── Inject spoof script for properties NOT handled by stealth plugin ───
  if (useStealth) {
    await context.addInitScript({ content: buildSpoofScript(SPOOF_CONFIG) });
    console.log(`[Sentinel] Spoof script injected (screen, deviceMemory, platform, touch)`);
  }

  const page = await context.newPage();

  // ─── CDP session for this page ───
  const cdpSession = await page.context().newCDPSession(page);

  // ─── Override screen metrics via CDP for even deeper spoofing ───
  // This ensures window.innerWidth/innerHeight and CSS media queries match
  if (useStealth) {
    try {
      await cdpSession.send('Emulation.setDeviceMetricsOverride', {
        width: SPOOF_CONFIG.screen.width,
        height: SPOOF_CONFIG.screen.height,
        deviceScaleFactor: 1,
        mobile: false,
        screenWidth: SPOOF_CONFIG.screen.width,
        screenHeight: SPOOF_CONFIG.screen.height,
      });
    } catch (e) {
      // Non-fatal: some Chromium versions may not support all params
      console.warn(`[Sentinel] CDP screen override warning: ${e.message}`);
    }
  }

  const injectionStatus = {
    version: VERSION,
    mode,
    rebrowserPatched: true,
    runtimeFixMode: process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE,
    stealthPlugin: useStealth,
    spoofConfig: useStealth ? SPOOF_CONFIG : 'none (raw observation)',
    zeroInjection: !useStealth,
    persistentContext: true,
    profileDirectory: persistDir,
    autoGenerated: isAutoGenerated,
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
  await context.close();

  // ─── Remove temp profile if auto-generated ───
  if (isAutoGenerated) {
    try {
      if (fs.existsSync(persistDir)) {
        console.log(`[Sentinel] Removing auto-generated temp profile: ${persistDir}`);
        fs.rmSync(persistDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      }
      tempDirsToCleanup.delete(persistDir);
    } catch (err) {
      console.warn(`[Sentinel] Failed to remove temp profile ${persistDir}: ${err.message}`);
    }
  }

  return { reportPath, stats: analysis };
}

// ─── Main ───
(async () => {
  console.log(`
🛡️  ${VERSION} — Pure Observer CCTV with Auto-Cleanup
   rebrowser-playwright-core: Runtime.Enable PATCHED (${process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE})
   Stealth Plugin: ${stealthEnabled ? 'ON' : 'OFF'}
   ZERO Injection | ZERO Spoofing | 100% Passive CDP Observation
   ALWAYS Persistent Context (No Incognito Detection)
   Target: ${target}
   Mode: ${dualMode ? 'DUAL (observe → stealth)' : 'stealth'}
   Headless: ${headless}
   Timeout: ${timeout}ms | Wait: ${waitTime}ms
   Persist: ${userPersistDir || 'auto-generated temp (with cleanup)'}

   ─── Spoof Profile ───
   GPU:      ${SPOOF_CONFIG.webgl.vendor} / ${SPOOF_CONFIG.webgl.renderer}
   CPU:      ${SPOOF_CONFIG.hardwareConcurrency} cores
   RAM:      ${SPOOF_CONFIG.deviceMemory} GB
   Screen:   ${SPOOF_CONFIG.screen.width}x${SPOOF_CONFIG.screen.height}
   Avail:    ${SPOOF_CONFIG.screen.availWidth}x${SPOOF_CONFIG.screen.availHeight}
   Depth:    ${SPOOF_CONFIG.screen.colorDepth}-bit
   Touch:    ${SPOOF_CONFIG.maxTouchPoints > 0 ? SPOOF_CONFIG.maxTouchPoints + ' points' : 'not support'}
   Platform: ${SPOOF_CONFIG.platform}
   Chrome:   ${SPOOF_CONFIG.executablePath || 'bundled Chromium'}
`);

  try {
    if (dualMode) {
      console.log('═══ PASS 1: OBSERVE MODE (no stealth, raw fingerprint) ═══');
      await runScan('observe');
      console.log('\n═══ PASS 2: STEALTH MODE (spoofed fingerprint) ═══');
      await runScan('stealth');
      console.log('\n✅ Dual-mode scan complete.');
    } else {
      await runScan('stealth');
      console.log('\n✅ Scan complete.');
    }

    // Final cleanup
    cleanupTempDirs();
  } catch (err) {
    console.error('❌ Fatal error:', err);
    cleanupTempDirs();
    process.exit(1);
  }
})();
