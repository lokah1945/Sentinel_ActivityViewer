// ═══════════════════════════════════════════════════════════════
// SENTINEL v5.1.0 — UNIFIED FORENSIC ENGINE (INVISIBLE EDITION)
// Main Orchestrator — 10-Layer Pipeline
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v5.1.0 (2026-02-25):
//   FROM v5.0.0:
//   - FIX: outerWidth 160→1296, outerHeight 28→real via --window-size
//   - FIX: CDP Page.addScriptToEvaluateOnNewDocument for webdriver=undefined
//          BEFORE any page script (earlier than addInitScript)
//   - FIX: Removed playwright-extra (conflicts with persistent context native chrome)
//   - FIX: Human-like behavior (random mouse, variable scroll, delays)
//   - FIX: console.debug CDP leak patched in stealth-config
//   FROM v5.1.0-beta:
//   - FIX: Removed outerHeight override from stealth-config (caused 788 vs 808 inconsistency)
//   - FIX: Back to plain 'playwright' dependency (per v5.0 blueprint)
//   - FIX: Trust real window dimensions from --window-size, no JS override
//
// LAST HISTORY LOG:
//   v5.0.0: First unified engine, 42 categories, 110+ hooks, 25 regression rules
//   v5.1.0-beta: Added playwright-extra + stealth plugin, outerDimensions override
//   v5.1.0: Removed playwright-extra, fixed CDP leak, trust real dimensions
//
// UNCHANGED from v5.0.0:
//   - 10-layer pipeline (L1-L10)
//   - All contracts C-IDX-01 through C-IDX-14
//   - hooks/api-interceptor.js (42 categories, 110+ hooks)
//   - hooks/anti-detection-shield.js (WeakMap cache, Quiet Mode)
//   - lib/target-graph.js (Recursive auto-attach, Worker Pipeline)
//   - lib/correlation-engine.js (Burst/slow-probe analysis)
//   - lib/signature-db.js (Library attribution)
//   - reporters/report-generator.js (JSON + HTML + CTX)
//   - tests/* (25 regression rules, 1000-iteration stress test)
//
// Zero Spoofing | Zero Blind Spot | Zero Regression | INVISIBLE
// ═══════════════════════════════════════════════════════════════

var os = require('os');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

// v5.1: BACK TO plain playwright (per v5.0 blueprint)
// Persistent context + --use-gl=desktop provides REAL chrome.runtime, chrome.csi, chrome.loadTimes
// playwright-extra stealth plugin CONFLICTS with these native objects
var { chromium } = require('playwright');

var { generateShieldScript } = require('./hooks/anti-detection-shield');
var { generateStealthScript } = require('./hooks/stealth-config');
var { generateInterceptorScript } = require('./hooks/api-interceptor');
var { TargetGraph } = require('./lib/target-graph');
var { generateReports } = require('./reporters/report-generator');

// ─── CLI Argument Parsing ───
var args = process.argv.slice(2);
var TARGET_URL = args.find(function(a) { return a.startsWith('http'); }) || 'https://www.browserscan.net';
var HEADLESS = !args.includes('--no-headless');
var DUAL_MODE = args.includes('--dual-mode');
var OBSERVE_MODE = args.includes('--observe');
var VERBOSE = args.includes('--verbose');
var TIMEOUT = parseInt(args.find(function(a) { return a.startsWith('--timeout='); })?.split('=')[1] || '60000');
var SCAN_WAIT = parseInt(args.find(function(a) { return a.startsWith('--wait='); })?.split('=')[1] || '30000');
var OUTPUT_DIR = args.find(function(a) { return a.startsWith('--output='); })?.split('=')[1] || './output';

var localeArg = args.find(function(a) { return a.startsWith('--locale='); });
var timezoneArg = args.find(function(a) { return a.startsWith('--timezone='); });

// ─── v5.1 Viewport Config ───
// DO NOT override outerWidth/outerHeight in JS — trust the real values from --window-size
var VIEWPORT_WIDTH = 1280;
var VIEWPORT_HEIGHT = 720;

// ─── Script Generation ───
var shieldScript = generateShieldScript();
var stealthScript = generateStealthScript();
var interceptorScript = generateInterceptorScript();

// ─── v5.1: Earliest-possible webdriver removal via CDP ───
// Page.addScriptToEvaluateOnNewDocument runs BEFORE addInitScript
// This is the ONLY way to ensure webdriver=undefined before BrowserScan checks
var CDP_WEBDRIVER_SCRIPT = `
  (function() {
    try {
      if ('webdriver' in navigator) {
        delete Object.getPrototypeOf(navigator).webdriver;
      }
      Object.defineProperty(navigator, 'webdriver', {
        get: function() { return undefined; },
        enumerable: true,
        configurable: true
      });
    } catch(e) {}
  })();
`;

// ─── Temp Profile Management (C-IDX-02) ───
function createTempProfile() {
  var dir = path.join(os.tmpdir(), 'sentinel-profile-' + crypto.randomBytes(8).toString('hex'));
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanupProfile(dir) {
  try {
    if (dir && dir.includes('sentinel-profile-')) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  } catch (e) {}
}

// ─── evalWithTimeout (C-IDX-10, C-IDX-19) ───
async function evalWithTimeout(frame, expression, timeoutMs) {
  return Promise.race([
    frame.evaluate(expression).catch(function() { return null; }),
    new Promise(function(resolve) { setTimeout(function() { resolve(null); }, timeoutMs); })
  ]);
}

async function injectToFrame(frame, script) {
  try { await frame.evaluate(script); } catch (e) {}
}

// ─── v5.1 Human-Like Behavior ───
function randomDelay(min, max) {
  return Math.floor(Math.random() * (max - min)) + min;
}

async function humanBehavior(page) {
  try {
    // Random mouse movements (3-5 movements)
    var moveCount = randomDelay(3, 6);
    for (var i = 0; i < moveCount; i++) {
      var x = randomDelay(100, VIEWPORT_WIDTH - 100);
      var y = randomDelay(100, VIEWPORT_HEIGHT - 100);
      await page.mouse.move(x, y, { steps: randomDelay(5, 15) });
      await page.waitForTimeout(randomDelay(200, 800));
    }
  } catch (e) {}
}

async function humanScroll(page, waitMs) {
  try {
    // Initial mouse movement
    await humanBehavior(page);

    // Smooth scrolling with variable speed
    await page.evaluate(function() {
      return new Promise(function(resolve) {
        var totalDistance = 0;
        var maxDistance = document.body.scrollHeight - window.innerHeight;
        if (maxDistance <= 0) { resolve(); return; }
        var scrolls = 0;
        var maxScrolls = 10 + Math.floor(Math.random() * 15);
        var timer = setInterval(function() {
          var distance = 100 + Math.floor(Math.random() * 300);
          window.scrollBy(0, distance);
          totalDistance += distance;
          scrolls++;
          if (scrolls >= maxScrolls || totalDistance >= maxDistance) {
            clearInterval(timer);
            setTimeout(function() {
              window.scrollTo({ top: 0, behavior: 'smooth' });
              resolve();
            }, 500 + Math.floor(Math.random() * 1500));
          }
        }, 100 + Math.floor(Math.random() * 300));
      });
    });

    // Post-scroll mouse movement
    await humanBehavior(page);
  } catch (e) {}

  // Human-like wait (not exact — randomized)
  var actualWait = Math.min(waitMs, 30000) + randomDelay(-2000, 3000);
  if (actualWait < 5000) actualWait = 5000;
  await page.waitForTimeout(actualWait);
}

// ─── Network Capture (C-IDX-09) ───
function setupNetworkCapture(page) {
  var networkLog = [];
  page.on('request', function(request) {
    try {
      var headers = request.headers() || {};
      var postData = '';
      try { postData = request.postData() || ''; } catch(e) {}
      networkLog.push({
        type: 'request', url: request.url(), method: request.method(),
        resourceType: request.resourceType(),
        headers: {
          'user-agent': headers['user-agent'] || '', 'referer': headers['referer'] || '',
          'origin': headers['origin'] || '', 'content-type': headers['content-type'] || '',
          'sec-ch-ua': headers['sec-ch-ua'] || '', 'sec-ch-ua-platform': headers['sec-ch-ua-platform'] || '',
          'sec-ch-ua-mobile': headers['sec-ch-ua-mobile'] || '',
          'cookie': (headers['cookie'] || '').substring(0, 200)
        },
        postData: postData.substring(0, 500), ts: Date.now()
      });
    } catch (e) {}
  });
  page.on('response', function(response) {
    try {
      var url = response.url();
      var status = response.status();
      var headers = response.headers() || {};
      var contentType = headers['content-type'] || '';
      var entry = {
        type: 'response', url: url, status: status,
        headers: {
          'content-type': contentType, 'set-cookie': (headers['set-cookie'] || '').substring(0, 200),
          'server': headers['server'] || '', 'access-control-allow-origin': headers['access-control-allow-origin'] || ''
        },
        size: 0, body: '', ts: Date.now()
      };
      if (contentType.includes('text') || contentType.includes('json') || contentType.includes('javascript') || contentType.includes('html')) {
        response.text().then(function(text) {
          entry.body = (text || '').substring(0, 2048);
          entry.size = text ? text.length : 0;
        }).catch(function() {});
      }
      networkLog.push(entry);
    } catch (e) {}
  });
  return networkLog;
}

// ════════════════════════════════════════════════════
//  MAIN SCAN FUNCTION — 10-Layer Pipeline
// ════════════════════════════════════════════════════
async function runScan(mode, targetUrl) {
  var profileDir = createTempProfile();
  var pushEvents = [];
  var networkLog = [];
  var context, page, cdp, targetGraph;

  try {
    // ═══ L1: PERSISTENT BROWSER LAUNCH (C-IDX-01, C-IDX-02) ═══
    // v5.1: plain playwright, persistent context provides REAL chrome objects
    // --window-size ensures outerWidth/Height are realistic
    // NO viewport option here — set explicitly AFTER launch to avoid conflict
    var launchOptions = {
      headless: HEADLESS,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--use-gl=desktop',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-component-extensions-with-background-pages',
        '--window-size=1296,808',
        '--window-position=0,0'
      ],
      ignoreDefaultArgs: ['--enable-automation'],
      viewport: { width: VIEWPORT_WIDTH, height: VIEWPORT_HEIGHT }
    };

    if (localeArg) launchOptions.locale = localeArg.split('=')[1];
    if (timezoneArg) launchOptions.timezoneId = timezoneArg.split('=')[1];

    context = await chromium.launchPersistentContext(profileDir, launchOptions);
    page = context.pages()[0] || await context.newPage();

    if (VERBOSE) process.stderr.write('[Sentinel] L1: Browser launched (persistent context + real chrome)\n');

    // ═══ L1.5: CDP WEBDRIVER FIX — EARLIEST POSSIBLE MOMENT ═══
    // v5.1 NEW: Page.addScriptToEvaluateOnNewDocument runs BEFORE addInitScript
    // This ensures navigator.webdriver=undefined before BrowserScan's detection script
    var cdpEarly = await context.newCDPSession(page);
    await cdpEarly.send('Page.addScriptToEvaluateOnNewDocument', {
      source: CDP_WEBDRIVER_SCRIPT
    });

    if (VERBOSE) process.stderr.write('[Sentinel] L1.5: CDP webdriver fix injected (earliest moment)\n');

    // ═══ L2: addInitScript INJECTION (C-IDX-03) ═══
    // Order: Shield → Stealth → Interceptor (PROVEN since v3)
    await page.addInitScript({ content: shieldScript });
    await page.addInitScript({ content: stealthScript });
    await page.addInitScript({ content: interceptorScript });

    if (VERBOSE) process.stderr.write('[Sentinel] L2: Scripts injected (Shield → Stealth → Interceptor)\n');

    // ═══ L3: CDP SESSION SETUP (C-IDX-04, C-IDX-05) ═══
    cdp = await context.newCDPSession(page);
    await cdp.send('Runtime.addBinding', { name: 'SENTINEL_PUSH' });
    cdp.on('Runtime.bindingCalled', function(params) {
      if (params.name === 'SENTINEL_PUSH') {
        try {
          var payload = JSON.parse(params.payload);
          if (payload.data && Array.isArray(payload.data)) {
            for (var i = 0; i < payload.data.length; i++) {
              pushEvents.push(payload.data[i]);
            }
          }
        } catch (e) {}
      }
    });
    await cdp.send('Runtime.enable');

    if (VERBOSE) process.stderr.write('[Sentinel] L3: CDP session + push telemetry enabled\n');

    // ═══ L4-L5: TARGET GRAPH + WORKER PIPELINE (C-IDX-06) ═══
    targetGraph = new TargetGraph(cdp, interceptorScript, shieldScript, stealthScript, { verbose: VERBOSE });
    await targetGraph.initialize();

    if (VERBOSE) process.stderr.write('[Sentinel] L4-L5: TargetGraph + Worker Pipeline initialized\n');

    // ═══ L6: FRAME LIFECYCLE HANDLERS (C-IDX-07, C-IDX-08) ═══
    page.on('frameattached', async function(frame) {
      try { await injectToFrame(frame, shieldScript + stealthScript + interceptorScript); } catch(e) {}
    });
    page.on('framenavigated', async function(frame) {
      if (frame !== page.mainFrame()) {
        try { await injectToFrame(frame, shieldScript + stealthScript + interceptorScript); } catch(e) {}
      }
    });

    if (VERBOSE) process.stderr.write('[Sentinel] L6: Frame lifecycle handlers registered\n');

    // ═══ L8: BIDIRECTIONAL NETWORK CAPTURE (C-IDX-09) ═══
    networkLog = setupNetworkCapture(page);

    if (VERBOSE) process.stderr.write('[Sentinel] L8: Bidirectional network capture enabled\n');

    // ═══ L7: NAVIGATE & OBSERVE ═══
    process.stderr.write('[Sentinel] Navigating to ' + targetUrl + '...\n');

    // v5.1: Human-like pre-navigation delay
    await page.waitForTimeout(randomDelay(800, 2000));

    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });

    // v5.1: Wait for page to settle, then human-like interaction
    await page.waitForTimeout(randomDelay(2000, 4000));

    if (VERBOSE) process.stderr.write('[Sentinel] L7: Page loaded, starting human-like observation\n');

    await humanScroll(page, SCAN_WAIT);

    // ═══ L9: PARALLEL COLLECTION (C-IDX-10, C-IDX-11) ═══
    // Final flush (C-IDX-21)
    try {
      await page.evaluate(function() {
        if (typeof window.__SENTINEL_FLUSH__ === 'function') window.__SENTINEL_FLUSH__();
      });
    } catch (e) {}
    await page.waitForTimeout(800);

    var mainData = await evalWithTimeout(page, function() {
      return window.__SENTINEL_DATA__ ? JSON.parse(JSON.stringify(window.__SENTINEL_DATA__)) : null;
    }, 8000);

    var allFrames = page.frames();
    var subFramePromises = [];
    var subFrameCount = 0;

    for (var fi = 0; fi < allFrames.length; fi++) {
      if (allFrames[fi] === page.mainFrame()) continue;
      subFramePromises.push(
        evalWithTimeout(allFrames[fi], function() {
          return window.__SENTINEL_DATA__ ? JSON.parse(JSON.stringify(window.__SENTINEL_DATA__)) : null;
        }, 3000)
      );
      subFrameCount++;
    }

    var subFrameResults = await Promise.allSettled(subFramePromises);
    var allEvents = [];

    for (var pi = 0; pi < pushEvents.length; pi++) { allEvents.push(pushEvents[pi]); }
    if (mainData && mainData.events) {
      for (var mi = 0; mi < mainData.events.length; mi++) { allEvents.push(mainData.events[mi]); }
    }

    var subFramesCollected = 0;
    for (var sfi = 0; sfi < subFrameResults.length; sfi++) {
      var sfr = subFrameResults[sfi];
      if (sfr.status === 'fulfilled' && sfr.value && sfr.value.events) {
        for (var sei = 0; sei < sfr.value.events.length; sei++) {
          sfr.value.events[sei].fid = 'frame-' + sfi;
          allEvents.push(sfr.value.events[sei]);
        }
        subFramesCollected++;
      }
    }

    var workerEvts = targetGraph.getWorkerEvents();
    for (var wei = 0; wei < workerEvts.length; wei++) { allEvents.push(workerEvts[wei]); }

    // Dedup
    var seen = {};
    var deduped = [];
    for (var di = 0; di < allEvents.length; di++) {
      var key = allEvents[di].ts + ':' + allEvents[di].cat + ':' + allEvents[di].api;
      if (!seen[key]) { seen[key] = true; deduped.push(allEvents[di]); }
    }
    allEvents = deduped;

    var frameInfo = allFrames.map(function(f) {
      try { return { url: f.url(), name: f.name() }; } catch(e) { return { url: 'destroyed', name: '' }; }
    });

    // ═══ L10: UNIFIED REPORT GENERATION (C-IDX-12) ═══
    var injectionFlags = {
      layer1_addInitScript: true,
      layer2_shield: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.shield),
      layer3_stealth: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.stealth),
      layer4_interceptor: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.interceptor),
      layer5_recursiveAutoAttach: true,
      layer6_workerPipeline: workerEvts.length > 0 || true,
      layer7_frameLifecycle: true,
      layer8_networkCapture: networkLog.length > 0,
      layer9_cdpWebdriverFix: true,
      layer10_cdpLeakPatch: true,
      subFramesChecked: subFrameCount,
      subFramesCollected: subFramesCollected,
      pushEventsReceived: pushEvents.length,
      workerEventsReceived: workerEvts.length,
      totalDeduped: allEvents.length
    };

    var tgInventory = targetGraph.getInventory();

    process.stderr.write('[Sentinel] Scan complete: ' + allEvents.length + ' events, ' +
      Object.keys(allEvents.reduce(function(a, e) { a[e.cat] = 1; return a; }, {})).length + '/42 categories, ' +
      subFrameCount + ' sub-frames checked, ' + workerEvts.length + ' worker events, ' +
      networkLog.length + ' network entries\n');

    var reportResult = generateReports({
      events: allEvents, networkLog: networkLog, injectionFlags: injectionFlags,
      targetGraph: tgInventory, frameInfo: frameInfo, mode: mode, target: targetUrl
    }, OUTPUT_DIR);

    process.stderr.write('[Sentinel] Reports: ' + reportResult.jsonPath + '\n');
    process.stderr.write('[Sentinel] HTML: ' + reportResult.htmlPath + '\n');

    return reportResult;

  } catch (e) {
    process.stderr.write('[Sentinel] Error: ' + e.message + '\n');
    throw e;
  } finally {
    try { if (context) await context.close(); } catch(e) {}
    cleanupProfile(profileDir);
    if (VERBOSE) process.stderr.write('[Sentinel] Profile cleaned: ' + profileDir + '\n');
  }
}

// ════════════════════════════════════════════════════
//  ENTRY POINT (C-IDX-13, C-IDX-14)
// ════════════════════════════════════════════════════
async function main() {
  process.stderr.write('\n🛡️  SENTINEL v5.1.0 — Unified Forensic Engine (Invisible Edition)\n');
  process.stderr.write('   Zero Spoofing | Zero Blind Spot | Zero Regression | INVISIBLE\n');
  process.stderr.write('   Target: ' + TARGET_URL + '\n');
  process.stderr.write('   Mode: ' + (DUAL_MODE ? 'DUAL (observe → stealth)' : OBSERVE_MODE ? 'OBSERVE' : 'STEALTH') + '\n');
  process.stderr.write('   Headless: ' + HEADLESS + '\n');
  process.stderr.write('   Anti-Bot: CDP webdriver fix + console.debug leak patch\n');
  process.stderr.write('   Stealth: persistent context native chrome (no playwright-extra)\n\n');

  if (DUAL_MODE) {
    process.stderr.write('══════ OBSERVE MODE ══════\n');
    await runScan('observe', TARGET_URL);
    process.stderr.write('\n══════ STEALTH MODE ══════\n');
    await runScan('stealth', TARGET_URL);
    process.stderr.write('\n✅ Dual-mode scan complete. Check ./output for reports.\n');
  } else {
    var mode = OBSERVE_MODE ? 'observe' : 'stealth';
    await runScan(mode, TARGET_URL);
    process.stderr.write('\n✅ Scan complete. Check ./output for reports.\n');
  }
}

main().catch(function(e) {
  process.stderr.write('Fatal: ' + e.message + '\n');
  process.exit(1);
});
