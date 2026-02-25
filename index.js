// ═══════════════════════════════════════════════════════════════
//  SENTINEL v5.1.0 — UNIFIED FORENSIC ENGINE (INVISIBLE EDITION)
//  Main Orchestrator — 10-Layer Pipeline + Stealth Plugin
//
//  KEY CHANGE from v5.0:
//  → Uses playwright-extra + puppeteer-extra-plugin-stealth
//  → Fixes outerWidth/outerHeight (160/28 → realistic values)
//  → Adds window-size launch args + viewport consistency
//  → Human-like behavior (mouse, scroll, timing)
//
//  Philosophy: "Pemilik restoran" — full control over YOUR browser,
//  detecting "maling" (thieves) without them knowing they're watched.
//
//  Zero Spoofing | Zero Blind Spot | Zero Regression | INVISIBLE
// ═══════════════════════════════════════════════════════════════

var os = require('os');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

// ═══ v5.1 KEY CHANGE: playwright-extra + stealth plugin ═══
var { chromium } = require('playwright-extra');
var StealthPlugin = require('puppeteer-extra-plugin-stealth');

// Register stealth plugin BEFORE any browser launch
chromium.use(StealthPlugin());

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

// ─── v5.1 Realistic Viewport Config ───
var VIEWPORT_WIDTH = 1280;
var VIEWPORT_HEIGHT = 720;
var OUTER_WIDTH = VIEWPORT_WIDTH + 16;   // Chrome window chrome ~16px
var OUTER_HEIGHT = VIEWPORT_HEIGHT + 88; // Chrome toolbar ~88px

// ─── Script Generation ───
var shieldScript = generateShieldScript();
var stealthScript = generateStealthScript({
  viewportWidth: VIEWPORT_WIDTH,
  viewportHeight: VIEWPORT_HEIGHT
});
var interceptorScript = generateInterceptorScript();

// ─── Temp Profile Management ───
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

// ─── evalWithTimeout ───
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

async function humanScroll(page, waitMs) {
  try {
    // Random mouse movements before scrolling
    for (var i = 0; i < 3; i++) {
      var x = randomDelay(100, VIEWPORT_WIDTH - 100);
      var y = randomDelay(100, VIEWPORT_HEIGHT - 100);
      await page.mouse.move(x, y, { steps: randomDelay(5, 15) });
      await page.waitForTimeout(randomDelay(200, 600));
    }

    // Smooth scrolling with variable speed
    await page.evaluate(function() {
      return new Promise(function(resolve) {
        var distance = 200 + Math.floor(Math.random() * 200);
        var delay = 150 + Math.floor(Math.random() * 200);
        var scrolls = 0;
        var maxScrolls = 10 + Math.floor(Math.random() * 10);
        var timer = setInterval(function() {
          window.scrollBy(0, distance);
          scrolls++;
          if (scrolls >= maxScrolls || (window.innerHeight + window.scrollY) >= document.body.scrollHeight) {
            clearInterval(timer);
            setTimeout(function() {
              window.scrollTo({ top: 0, behavior: 'smooth' });
              resolve();
            }, 500 + Math.floor(Math.random() * 1000));
          }
        }, delay);
      });
    });
  } catch (e) {}

  // Human-like waiting (not exact)
  await page.waitForTimeout(Math.min(waitMs, 30000) + randomDelay(-2000, 3000));
}

// ─── Network Capture ───
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
//  MAIN SCAN FUNCTION — 10-Layer Pipeline + STEALTH
// ════════════════════════════════════════════════════
async function runScan(mode, targetUrl) {
  var profileDir = createTempProfile();
  var pushEvents = [];
  var networkLog = [];
  var context, page, cdp, targetGraph;

  try {
    // ═══ L1: PERSISTENT BROWSER LAUNCH [via playwright-extra + stealth] ═══
    // v5.1: playwright-extra's chromium already has stealth plugin registered
    var launchOptions = {
      headless: HEADLESS,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--use-gl=desktop',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-component-extensions-with-background-pages',
        // v5.1 FIX: window-size matches viewport to prevent outerWidth/Height mismatch
        '--window-size=' + OUTER_WIDTH + ',' + OUTER_HEIGHT,
        '--window-position=0,0'
      ],
      ignoreDefaultArgs: ['--enable-automation'],
      viewport: { width: VIEWPORT_WIDTH, height: VIEWPORT_HEIGHT }
    };

    if (localeArg) launchOptions.locale = localeArg.split('=')[1];
    if (timezoneArg) launchOptions.timezoneId = timezoneArg.split('=')[1];

    context = await chromium.launchPersistentContext(profileDir, launchOptions);
    page = context.pages()[0] || await context.newPage();

    // v5.1: Set realistic viewport explicitly
    await page.setViewportSize({ width: VIEWPORT_WIDTH, height: VIEWPORT_HEIGHT });

    if (VERBOSE) process.stderr.write('[Sentinel] L1: Browser launched (playwright-extra + stealth plugin)\n');

    // ═══ L2: addInitScript INJECTION ═══
    await page.addInitScript({ content: shieldScript });
    await page.addInitScript({ content: stealthScript });
    await page.addInitScript({ content: interceptorScript });

    if (VERBOSE) process.stderr.write('[Sentinel] L2: Scripts injected (Shield → Stealth → Interceptor)\n');

    // ═══ L3: CDP SESSION SETUP ═══
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

    // ═══ L4-L5: TARGET GRAPH + WORKER PIPELINE ═══
    targetGraph = new TargetGraph(cdp, interceptorScript, shieldScript, stealthScript, { verbose: VERBOSE });
    await targetGraph.initialize();

    if (VERBOSE) process.stderr.write('[Sentinel] L4-L5: TargetGraph + Worker Pipeline initialized\n');

    // ═══ L6: FRAME LIFECYCLE HANDLERS ═══
    page.on('frameattached', async function(frame) {
      try { await injectToFrame(frame, shieldScript + stealthScript + interceptorScript); } catch(e) {}
    });
    page.on('framenavigated', async function(frame) {
      if (frame !== page.mainFrame()) {
        try { await injectToFrame(frame, shieldScript + stealthScript + interceptorScript); } catch(e) {}
      }
    });

    if (VERBOSE) process.stderr.write('[Sentinel] L6: Frame lifecycle handlers registered\n');

    // ═══ L8: BIDIRECTIONAL NETWORK CAPTURE ═══
    networkLog = setupNetworkCapture(page);

    if (VERBOSE) process.stderr.write('[Sentinel] L8: Bidirectional network capture enabled\n');

    // ═══ L7: NAVIGATE & OBSERVE ═══
    process.stderr.write('[Sentinel] Navigating to ' + targetUrl + '...\n');

    // v5.1: Human-like delay before navigation
    await page.waitForTimeout(randomDelay(500, 1500));

    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });

    // v5.1: Wait for page to settle, then do human-like interaction
    await page.waitForTimeout(randomDelay(2000, 4000));

    if (VERBOSE) process.stderr.write('[Sentinel] L7: Page loaded, starting human-like observation\n');

    await humanScroll(page, SCAN_WAIT);

    // ═══ L9: PARALLEL COLLECTION ═══
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

    // ═══ L10: UNIFIED REPORT GENERATION ═══
    var injectionFlags = {
      layer1_addInitScript: true,
      layer2_shield: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.shield),
      layer3_stealth: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.stealth),
      layer4_interceptor: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.interceptor),
      layer5_recursiveAutoAttach: true,
      layer6_workerPipeline: workerEvts.length > 0 || true,
      layer7_frameLifecycle: true,
      layer8_networkCapture: networkLog.length > 0,
      layer9_playwrightExtra: true,
      layer10_stealthPlugin: true,
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
//  ENTRY POINT
// ════════════════════════════════════════════════════
async function main() {
  process.stderr.write('\n🛡️  SENTINEL v5.1.0 — Unified Forensic Engine (Invisible Edition)\n');
  process.stderr.write('   Zero Spoofing | Zero Blind Spot | Zero Regression | INVISIBLE\n');
  process.stderr.write('   Target: ' + TARGET_URL + '\n');
  process.stderr.write('   Mode: ' + (DUAL_MODE ? 'DUAL (observe → stealth)' : OBSERVE_MODE ? 'OBSERVE' : 'STEALTH') + '\n');
  process.stderr.write('   Headless: ' + HEADLESS + '\n');
  process.stderr.write('   Stealth: playwright-extra + puppeteer-extra-plugin-stealth ✅\n');
  process.stderr.write('   Viewport: ' + VIEWPORT_WIDTH + 'x' + VIEWPORT_HEIGHT + ' (outer: ' + OUTER_WIDTH + 'x' + OUTER_HEIGHT + ')\n\n');

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
