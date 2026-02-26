#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.1.0 — HYBRID DUAL-TELEMETRY FORENSIC ENGINE
//  Main Orchestrator: 12-Layer Pipeline
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.1.0 (2026-02-26):
//   - FIX: Browser auto-install fallback when chromium not found
//   - FIX: package.json requires playwright + playwright-core as
//     peer deps for rebrowser-playwright (prevents esmLoader error)
//   - FIX: postinstall installs chromium for BOTH rebrowser-playwright
//     AND playwright to cover version mismatch in registry paths
//   - FIX: Graceful retry on launch failure with auto chromium install
//   - All v7.0.0-fix1 features preserved (--dual-mode, --no-headless, etc.)
//
// LAST HISTORY LOG:
//   v7.0.0-fix1: CLI restored (--dual-mode, --no-headless)
//   v7.0.0:      Hybrid dual-telemetry engine (hook + CDP)
//   v6.4.0:      CDP-only, persistentContext, auto-cleanup, --dual-mode
// ═══════════════════════════════════════════════════════════════

'use strict';

process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE = process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE || 'addBinding';
process.env.REBROWSER_PATCHES_SOURCE_URL = process.env.REBROWSER_PATCHES_SOURCE_URL || 'analytics.js';

var fs = require('fs');
var path = require('path');
var os = require('os');
var { execSync } = require('child_process');
var { addExtra } = require('playwright-extra');
var playwrightCore = require('rebrowser-playwright');
var StealthPlugin = require('puppeteer-extra-plugin-stealth');
var { getShieldScript } = require('./hooks/anti-detection-shield');
var { getInterceptorScript } = require('./hooks/api-interceptor');
var { EventPipeline } = require('./lib/event-pipeline');
var { CdpObserverEngine } = require('./lib/cdp-observer-engine');
var { TargetGraph } = require('./lib/target-graph');
var { CorrelationEngine } = require('./lib/correlation-engine');
var { ReportGenerator } = require('./reporters/report-generator');

var VERSION = 'sentinel-v7.1.0';
var CLEANUP_PROFILE = true;

// ═══════════════════════════════════════════
//  BROWSER AUTO-INSTALL HELPER (v7.1.0 NEW)
// ═══════════════════════════════════════════
function autoInstallChromium() {
  console.log('\n[AUTO-INSTALL] Chromium not found. Attempting auto-install...');

  var commands = [
    { cmd: 'npx rebrowser-playwright install chromium', label: 'rebrowser-playwright' },
    { cmd: 'npx playwright install chromium', label: 'playwright' }
  ];

  var success = false;
  for (var i = 0; i < commands.length; i++) {
    try {
      console.log('[AUTO-INSTALL] Trying: ' + commands[i].label + '...');
      execSync(commands[i].cmd, { stdio: 'inherit', timeout: 300000 });
      console.log('[AUTO-INSTALL] \u2713 ' + commands[i].label + ' install succeeded');
      success = true;
    } catch (e) {
      console.warn('[AUTO-INSTALL] \u26A0 ' + commands[i].label + ' failed');
    }
  }

  if (!success) {
    console.error('\n[AUTO-INSTALL] \u274C All install methods failed!');
    console.error('[AUTO-INSTALL] Please install manually:');
    console.error('  npx playwright install chromium');
    console.error('  npx rebrowser-playwright install chromium\n');
  }

  return success;
}

// ═══════════════════════════════════════════
//  TEMP PROFILE CLEANUP REGISTRY
// ═══════════════════════════════════════════
var tempDirsToCleanup = new Set();

function cleanupTempDirs() {
  tempDirsToCleanup.forEach(function(dir) {
    try {
      if (fs.existsSync(dir)) {
        console.log('[Sentinel] Cleaning up temp profile: ' + dir);
        fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      }
      tempDirsToCleanup.delete(dir);
    } catch (err) {
      console.warn('[Sentinel] Failed to cleanup ' + dir + ': ' + err.message);
    }
  });
}

process.on('SIGINT', function() {
  console.log('\n[Sentinel] Received SIGINT, cleaning up...');
  cleanupTempDirs();
  process.exit(0);
});

process.on('SIGTERM', function() {
  console.log('\n[Sentinel] Received SIGTERM, cleaning up...');
  cleanupTempDirs();
  process.exit(0);
});

// ═══════════════════════════════════════════
//  CLI ARGUMENT PARSING (v6.4 compatible)
// ═══════════════════════════════════════════
var args = process.argv.slice(2);
var target = args.find(function(a) { return a.startsWith('http'); }) || null;
var dualMode = args.indexOf('--dual-mode') !== -1;
var headless = args.indexOf('--no-headless') === -1;
var stealthEnabled = args.indexOf('--no-stealth') === -1;

var timeout = 60000;
var waitTime = 30000;
var userPersistDir = '';

for (var ai = 0; ai < args.length; ai++) {
  if (args[ai].startsWith('--timeout=')) timeout = parseInt(args[ai].split('=')[1]) || 60000;
  if (args[ai].startsWith('--wait='))    waitTime = parseInt(args[ai].split('=')[1]) || 30000;
  if (args[ai].startsWith('--persist=')) userPersistDir = args[ai].split('=')[1] || '';
}

if (!target) {
  console.log('\n\uD83D\uDEE1\uFE0F  ' + VERSION + ' \u2014 Hybrid Dual-Telemetry Forensic CCTV\n');
  console.log('Usage: node index.js <URL> [options]\n');
  console.log('Options:');
  console.log('  --dual-mode        Run both observe and stealth passes');
  console.log('  --no-headless      Visible browser');
  console.log('  --no-stealth       Disable stealth plugin (for comparison)');
  console.log('  --timeout=<ms>     Navigation timeout (default: 60000)');
  console.log('  --wait=<ms>        Post-load wait time (default: 30000)');
  console.log('  --persist=<dir>    Persistent browser profile directory\n');
  console.log('Examples:');
  console.log('  node index.js https://browserscan.net --dual-mode --no-headless');
  console.log('  node index.js https://example.com --persist=./profiles/session1 --no-headless');
  console.log('  node index.js https://browserscan.net --dual-mode --no-headless --timeout=60000 --wait=30000\n');
  process.exit(0);
}

// ═══════════════════════════════════════════
//  BROWSER LAUNCH WITH AUTO-INSTALL RETRY
// ═══════════════════════════════════════════
async function launchBrowserWithRetry(chromium, persistDir, launchOpts) {
  // Attempt 1: normal launch
  try {
    return await chromium.launchPersistentContext(persistDir, launchOpts);
  } catch (err) {
    var msg = err.message || '';

    // Check if it's a "browser not found" error
    if (msg.indexOf("Executable doesn't exist") !== -1 ||
        msg.indexOf('browserType.launch') !== -1 ||
        msg.indexOf('download new browsers') !== -1) {

      console.warn('[Sentinel] Browser not found, attempting auto-install...');

      // Auto-install chromium
      var installed = autoInstallChromium();

      if (installed) {
        // Attempt 2: retry after install
        console.log('[Sentinel] Retrying browser launch...');
        try {
          return await chromium.launchPersistentContext(persistDir, launchOpts);
        } catch (retryErr) {
          // If still fails, try with executablePath pointing to system Chrome
          console.warn('[Sentinel] Retry failed. Trying system Chrome/Chromium...');

          var systemChrome = findSystemChrome();
          if (systemChrome) {
            console.log('[Sentinel] Found system browser: ' + systemChrome);
            launchOpts.executablePath = systemChrome;
            return await chromium.launchPersistentContext(persistDir, launchOpts);
          }

          throw retryErr;
        }
      }
    }

    throw err;
  }
}

function findSystemChrome() {
  var candidates = [];

  if (process.platform === 'win32') {
    var programFiles = process.env['ProgramFiles'] || 'C:\\Program Files';
    var programFiles86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
    var localAppData = process.env['LOCALAPPDATA'] || '';

    candidates = [
      path.join(programFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(programFiles86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(localAppData, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(programFiles, 'Chromium', 'Application', 'chrome.exe'),
      path.join(localAppData, 'Chromium', 'Application', 'chrome.exe'),
      path.join(programFiles86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(programFiles, 'Microsoft', 'Edge', 'Application', 'msedge.exe')
    ];
  } else if (process.platform === 'darwin') {
    candidates = [
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'
    ];
  } else {
    candidates = [
      '/usr/bin/google-chrome',
      '/usr/bin/google-chrome-stable',
      '/usr/bin/chromium-browser',
      '/usr/bin/chromium',
      '/snap/bin/chromium'
    ];
  }

  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(candidates[i])) return candidates[i];
  }
  return null;
}

// ═══════════════════════════════════════════
//  SCAN FUNCTION (called per mode)
// ═══════════════════════════════════════════
async function runScan(mode) {
  var ts = Date.now();

  var persistDir;
  var isAutoGenerated = false;

  if (userPersistDir) {
    persistDir = path.resolve(userPersistDir);
    console.log('[Sentinel] Using user-specified profile: ' + persistDir);
  } else {
    var tempPrefix = path.join(os.tmpdir(), 'sentinel-profile-' + mode + '-');
    persistDir = fs.mkdtempSync(tempPrefix);
    isAutoGenerated = true;
    tempDirsToCleanup.add(persistDir);
    console.log('[Sentinel] Auto-generated temp profile: ' + persistDir);
  }

  // ─── L1: PIPELINE INITIALIZATION ───
  var pipeline = new EventPipeline({ maxBuffer: 100000 });
  console.log('[L1] Pipeline initialized');

  // ─── L2: STEALTH PLUGIN (conditional per mode) ───
  var chromium = addExtra(playwrightCore.chromium);
  var useStealthForThisMode = stealthEnabled && (mode === 'stealth');

  if (useStealthForThisMode) {
    var stealth = StealthPlugin();
    chromium.use(stealth);
    console.log('[L2] Stealth plugin loaded (17 evasions)');
  } else {
    console.log('[L2] Stealth plugin DISABLED (mode: ' + mode + ')');
  }

  // ─── L1: PERSISTENT BROWSER LAUNCH (REG-022 + v7.1.0 auto-install) ───
  var launchArgs = [
    '--disable-blink-features=AutomationControlled',
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-infobars',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-timer-throttling',
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding',
    '--disable-ipc-flooding-protection',
    '--disable-session-crashed-bubble',
    '--disable-features=TranslateUI',
    '--enable-features=NetworkService,NetworkServiceInProcess'
  ];

  var launchOpts = {
    headless: headless,
    args: launchArgs,
    ignoreDefaultArgs: ['--enable-automation'],
    viewport: null
  };

  console.log('[L1] Launching browser (mode: ' + mode + ', headless: ' + headless + ')...');

  var context;
  try {
    // v7.1.0: Use retry wrapper instead of direct launch
    context = await launchBrowserWithRetry(chromium, persistDir, launchOpts);
  } catch (err) {
    console.error('[Sentinel] Failed to launch browser: ' + err.message);
    if (isAutoGenerated && fs.existsSync(persistDir)) {
      fs.rmSync(persistDir, { recursive: true, force: true });
      tempDirsToCleanup.delete(persistDir);
    }
    throw err;
  }
  console.log('[L1] Browser launched (persistentContext)');

  var page = null;

  try {
    var pages = context.pages();
    page = pages.length > 0 ? pages[0] : await context.newPage();

    // ─── L3: addInitScript INJECTION (REG-001) ───
    await context.addInitScript({ content: getShieldScript() });
    console.log('[L3] Shield injected via addInitScript');

    await context.addInitScript({ content: getInterceptorScript({
      timeout: waitTime,
      maxEvents: 50000,
      pushInterval: 500
    }) });
    console.log('[L3] Interceptor injected (42 categories, 110+ hooks)');

    // ─── L4: CDP SESSION + RUNTIME BINDING ───
    var cdp = await context.newCDPSession(page);
    console.log('[L4] CDP session established');

    await cdp.send('Runtime.addBinding', { name: 'SENTINEL_PUSH' });
    console.log('[L4] SENTINEL_PUSH binding registered');

    // ─── L5: PUSH TELEMETRY RECEIVER ───
    cdp.on('Runtime.bindingCalled', function(params) {
      if (params.name === 'SENTINEL_PUSH') {
        try {
          var payload = JSON.parse(params.payload);
          if (payload.type === 'events' && Array.isArray(payload.events)) {
            pipeline.pushBatchHook(payload.events);
          }
        } catch (e) {
          console.warn('[L5] Push parse error: ' + e.message);
        }
      }
    });
    console.log('[L5] Push telemetry receiver active (500ms interval)');

    // ─── L9: CDP OBSERVER ENGINE (REG-026) ───
    var observer = new CdpObserverEngine(pipeline, cdp);
    await observer.start();
    console.log('[L9] CDP observer started (Network, Page, Security, Console, DOM, Performance, Runtime)');

    // ─── L6: TARGET GRAPH — Recursive Auto-Attach (REG-016) ───
    var targetGraph = new TargetGraph(pipeline, cdp, context);
    await targetGraph.start();
    console.log('[L6] TargetGraph started (recursive auto-attach)');

    // ─── L8: FRAME LIFECYCLE HANDLERS (REG-006, REG-007) ───
    page.on('frameattached', function(frame) {
      pipeline.pushPage({ cat: 'frame-lifecycle', api: 'frameattached-pw', risk: 'info', detail: 'PW frameattached: ' + (frame.url() || 'about:blank') });
    });
    page.on('framenavigated', function(frame) {
      pipeline.pushPage({ cat: 'frame-lifecycle', api: 'framenavigated-pw', risk: 'info', detail: 'PW framenavigated: ' + frame.url() });
    });
    page.on('framedetached', function(frame) {
      pipeline.pushPage({ cat: 'frame-lifecycle', api: 'framedetached-pw', risk: 'info', detail: 'PW framedetached' });
    });
    console.log('[L8] Frame lifecycle handlers registered');

    // ─── L10: BIDIRECTIONAL NETWORK CAPTURE ───
    page.on('request', function(req) {
      pipeline.pushPage({ cat: 'network-request', api: req.method(), risk: 'info', detail: req.method() + ' ' + req.url().slice(0, 300), meta: { type: req.resourceType(), url: req.url() } });
    });
    page.on('response', function(resp) {
      pipeline.pushPage({ cat: 'network-response', api: String(resp.status()), risk: resp.status() >= 400 ? 'high' : 'info', detail: resp.status() + ' ' + resp.url().slice(0, 300), meta: { status: resp.status(), url: resp.url() } });
    });
    console.log('[L10] Bidirectional network capture active');

    // ─── NAVIGATE TO TARGET ───
    console.log('\n[NAV] Navigating to ' + target + '...');
    try {
      await page.goto(target, { waitUntil: 'domcontentloaded', timeout: timeout });
    } catch (e) {
      console.warn('[NAV] Navigation warning: ' + e.message);
    }

    // ─── WAIT FOR ACTIVITY ───
    console.log('[NAV] Observing for ' + (waitTime / 1000) + 's...');
    await new Promise(function(resolve) { setTimeout(resolve, waitTime); });

    // ─── L5: Final flush (REG-021) ───
    try {
      await page.evaluate(function() {
        if (typeof window._SENTINEL_DATA !== 'undefined' && typeof window.SENTINEL_PUSH === 'function') {
          var lastIdx = window._SENTINEL_DATA._lastPushIndex || 0;
          var batch = window._SENTINEL_DATA.events.slice(lastIdx);
          if (batch.length > 0) {
            window.SENTINEL_PUSH(JSON.stringify({ type: 'events', count: batch.length, total: window._SENTINEL_DATA.events.length, events: batch, frame: window._SENTINEL_DATA.frameType, ts: Date.now() }));
          }
        }
      });
    } catch (e) {
      console.warn('[L5] Final flush warning: ' + e.message);
    }
    console.log('[L5] Final flush completed');
    await new Promise(function(resolve) { setTimeout(resolve, 500); });

    var pwFrames = page.frames().map(function(f) {
      return { url: f.url(), name: f.name(), detached: f.isDetached() };
    });

    // ─── L11: PARALLEL COLLECTION + MERGE (REG-018) ───
    var events = pipeline.drain();
    var pStats = pipeline.getStats();
    var frames = observer.getFrames();
    var tgStats = targetGraph.getStats();

    console.log('\n[L11] Collection complete:');
    console.log('  Total events (deduped): ' + events.length);
    console.log('  Hook events: ' + pStats.hookEvents);
    console.log('  CDP events: ' + pStats.cdpEvents);
    console.log('  Page events: ' + pStats.pageEvents);
    console.log('  Frames: ' + frames.length + ' (CDP) + ' + pwFrames.length + ' (PW)');
    console.log('  Targets: ' + tgStats.discovered + ' discovered, ' + tgStats.attached + ' attached');

    var engine = new CorrelationEngine(VERSION);
    var analysis = engine.analyze(events, frames.concat(pwFrames), pStats);
    console.log('  Categories detected: ' + analysis.categoryCount);
    console.log('  Risk score: ' + analysis.riskScore);

    var contextData = {
      version: VERSION,
      target: target,
      mode: mode,
      scanDate: new Date(ts).toISOString(),
      timeout: timeout,
      waitTime: waitTime,
      headless: headless,
      stealthEnabled: useStealthForThisMode,
      persistentContext: true,
      profileDirectory: persistDir,
      autoGenerated: isAutoGenerated,
      engine: 'hybrid-dual-telemetry',
      layers: {
        L1: 'persistentContext + auto-cleanup + auto-install-retry',
        L2: useStealthForThisMode ? 'stealth-plugin (17 evasions) + rebrowser-patches' : 'rebrowser-patches only (no stealth)',
        L3: 'addInitScript (shield + interceptor, 42 categories)',
        L4: 'CDP session + Runtime.addBinding',
        L5: 'Push telemetry (500ms interval)',
        L6: 'TargetGraph recursive auto-attach',
        L7: 'Worker pipeline (Network.enable per worker)',
        L8: 'Frame lifecycle handlers (frameattached/navigated)',
        L9: 'CDP domains (Network, Page, Security, Console, DOM, Performance, Runtime)',
        L10: 'Bidirectional network capture (page.on request/response)',
        L11: 'Parallel collection + dedup + merge',
        L12: 'Unified report (JSON + HTML + CTX)'
      },
      pipelineStats: pStats,
      targetGraphStats: tgStats,
      pwFrames: pwFrames,
      categoriesMonitored: 42,
      categoryCoverage: ((analysis.categoryCount / 42) * 100).toFixed(1) + '%'
    };

    var reporter = new ReportGenerator(VERSION);
    var paths = reporter.save(mode, ts, events, analysis, contextData);

    console.log('\n[L12] Reports generated:');
    console.log('  JSON: ' + paths.json);
    console.log('  HTML: ' + paths.html);
    console.log('  CTX:  ' + paths.context);

    console.log('\n' + '='.repeat(59));
    console.log('  SCAN COMPLETE [' + mode.toUpperCase() + ']');
    console.log('  Events: ' + events.length + ' (hook:' + pStats.hookEvents + ' + cdp:' + pStats.cdpEvents + ' + page:' + pStats.pageEvents + ')');
    console.log('  Categories: ' + analysis.categoryCount + '/42 (' + contextData.categoryCoverage + ')');
    console.log('  Risk Score: ' + analysis.riskScore + '/100');
    console.log('  Libraries: ' + analysis.libraryDetections.length);
    console.log('='.repeat(59));

    return { reportPath: paths, stats: analysis };

  } catch (err) {
    console.error('\n[ERROR] ' + err.message);
    console.error(err.stack);
  } finally {
    try { await context.close(); } catch (e) {}

    if (isAutoGenerated && CLEANUP_PROFILE) {
      try {
        if (fs.existsSync(persistDir)) {
          console.log('[CLEANUP] Removing auto-generated temp profile: ' + persistDir);
          fs.rmSync(persistDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
        }
        tempDirsToCleanup.delete(persistDir);
      } catch (e) {
        console.warn('[CLEANUP] Warning: ' + e.message);
      }
    }
  }
}

// ═══════════════════════════════════════════
//  MAIN EXECUTION
// ═══════════════════════════════════════════
(async function main() {
  console.log('\n' + '='.repeat(59));
  console.log('  ' + VERSION + ' — Hybrid Dual-Telemetry Forensic CCTV');
  console.log('  rebrowser-playwright: Runtime.Enable PATCHED (' + process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE + ')');
  console.log('  Target: ' + target);
  console.log('  Mode: ' + (dualMode ? 'DUAL (observe -> stealth)' : 'stealth'));
  console.log('  Headless: ' + headless);
  console.log('  Stealth: ' + (stealthEnabled ? 'ON' : 'OFF'));
  console.log('  Timeout: ' + timeout + 'ms | Wait: ' + waitTime + 'ms');
  console.log('  Persist: ' + (userPersistDir || 'auto-generated temp (with cleanup)'));
  console.log('='.repeat(59) + '\n');

  try {
    if (dualMode) {
      console.log('=== PASS 1: OBSERVE MODE (no stealth plugin) ===');
      await runScan('observe');
      console.log('\n=== PASS 2: STEALTH MODE ===');
      await runScan('stealth');
      console.log('\n\u2705 Dual-mode scan complete.');
    } else {
      await runScan('stealth');
      console.log('\n\u2705 Scan complete.');
    }

    cleanupTempDirs();
  } catch (err) {
    console.error('\u274C Fatal error: ' + err.message);
    console.error(err.stack);
    cleanupTempDirs();
    process.exit(1);
  }
})();
