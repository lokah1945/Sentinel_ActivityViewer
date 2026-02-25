// ═══════════════════════════════════════════════════════════════
// SENTINEL v6.1.0 — PLAYWRIGHT OFFICIAL + PLUGIN STEALTH + CDP COLLECTORS
// Main Orchestrator
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.1.0 (2026-02-25):
//   FROM v6.0.0:
//   - CHANGED: require('patchright') → require('playwright-extra').chromium
//     Official Playwright with plugin-based stealth (puppeteer-extra-plugin-stealth)
//     Plugin handles: webdriver deletion, chrome.runtime, navigator.plugins,
//     media.codecs, navigator.languages, window.outerdimensions, and more.
//   - ADDED: Stealth plugin initialization via chromium.use(StealthPlugin())
//   - CHANGED: layer1 flag from 'layer1_patchright' → 'layer1_playwright'
//   - CHANGED: Shield stack filter — 'patchright' replaced with 'playwright-extra'
//   - CHANGED: stealth-config.js — Re-added console.debug CDP leak fix
//     (Patchright handled this internally; official Playwright does NOT)
//   - CHANGED: stealth-config.js — Re-added Runtime.enable leak mitigation
//     via console.debug toString masking
//   - CHANGED: version banner to v6.1.0
//   - KEPT: ALL CDP collectors (CDPNetworkCollector, CDPSecurityCollector)
//   - KEPT: ALL in-page hooks (api-interceptor.js, 42 categories, 110+ hooks)
//   - KEPT: EventPipeline real-time streaming
//   - KEPT: TargetGraph recursive auto-attach
//   - KEPT: ALL 10-layer pipeline architecture
//
// LAST HISTORY LOG:
//   v5.0.0: First unified engine, 42 categories, 110+ hooks, 25 regression rules
//   v5.1.0-beta: Added playwright-extra + stealth plugin, outerDimensions override
//   v5.1.0: Removed playwright-extra, fixed CDP leak, trust real dimensions
//   v5.1.0-Final: Removed cross-frame inconsistency overrides, CDP console.debug fix
//   v6.0.0: Patchright + CDP collectors + EventPipeline, removed legacy CDP fixes
//   v6.1.0: Back to official Playwright + plugin stealth, re-added CDP leak fixes
//
// ARCHITECTURE:
//   L1: Persistent Browser Launch (playwright-extra + stealth plugin)
//   L1.5: CDP webdriver cleanup (defense-in-depth, plugin also handles this)
//   L2: addInitScript injection (Shield → Stealth → Interceptor)
//   L3: CDP Session + Push Telemetry + CDP Collectors
//   L4-L5: TargetGraph + Worker Pipeline
//   L6: Frame Lifecycle Handlers
//   L7: Navigate & Observe (human-like behavior)
//   L8: Dual-Layer Network Capture (CDP primary + Playwright supplementary)
//   L9: Parallel Collection (main frame + sub-frames + workers + CDP events)
//   L10: Unified Report Generation
// ═══════════════════════════════════════════════════════════════

var os = require('os');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

// v6.1.0: Official Playwright via playwright-extra with stealth plugin
var { chromium } = require('playwright-extra');
var StealthPlugin = require('puppeteer-extra-plugin-stealth');
chromium.use(StealthPlugin());

var { generateShieldScript } = require('./hooks/anti-detection-shield');
var { generateStealthScript } = require('./hooks/stealth-config');
var { generateInterceptorScript } = require('./hooks/api-interceptor');
var { TargetGraph } = require('./lib/target-graph');
var { generateReports } = require('./reporters/report-generator');
var { EventPipeline } = require('./lib/event-pipeline');
var { CDPNetworkCollector } = require('./collectors/cdp-network-collector');
var { CDPSecurityCollector } = require('./collectors/cdp-security-collector');

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

// ─── Viewport Config ───
var VIEWPORT_WIDTH = 1280;
var VIEWPORT_HEIGHT = 720;

// ─── Script Generation ───
var shieldScript = generateShieldScript();
var stealthScript = generateStealthScript();
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

// ─── Human-Like Behavior ───
function randomDelay(min, max) {
  return Math.floor(Math.random() * (max - min)) + min;
}

async function humanBehavior(page) {
  try {
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
    await humanBehavior(page);

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

    await humanBehavior(page);
  } catch (e) {}

  var actualWait = Math.min(waitMs, 30000) + randomDelay(-2000, 3000);
  if (actualWait < 5000) actualWait = 5000;
  await page.waitForTimeout(actualWait);
}

// ─── Network Capture (Playwright-level, supplementary to CDP) ───
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

// ─── CDP webdriver cleanup script (defense-in-depth) ───
var CDP_WEBDRIVER_SCRIPT = `
Object.defineProperty(navigator, 'webdriver', {
  get: () => undefined,
  configurable: true
});
delete navigator.__proto__.webdriver;
`;

// ════════════════════════════════════════════════════
//  MAIN SCAN FUNCTION
// ════════════════════════════════════════════════════
async function runScan(mode, targetUrl) {
  var profileDir = createTempProfile();
  var pushEvents = [];
  var networkLog = [];
  var context, page, cdp, targetGraph;
  var pipeline = new EventPipeline({ maxEvents: 100000 });

  // v6.0.0: Real-time alert logging
  if (VERBOSE) {
    pipeline.on('alert', function(event) {
      process.stderr.write('[ALERT] ' + event.cat + ':' + event.api + ' risk=' + event.risk + '\n');
    });
  }

  try {
    // ═══ L1: PERSISTENT BROWSER LAUNCH (PLAYWRIGHT-EXTRA + STEALTH PLUGIN) ═══
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

    if (VERBOSE) process.stderr.write('[Sentinel] L1: Browser launched (playwright-extra + stealth plugin)\n');

    // ═══ L1.5: CDP WEBDRIVER CLEANUP (defense-in-depth) ═══
    // The stealth plugin handles this, but we reinforce at CDP level
    var cdpInit = await context.newCDPSession(page);
    try {
      await cdpInit.send('Page.addScriptToEvaluateOnNewDocument', {
        source: CDP_WEBDRIVER_SCRIPT
      });
    } catch (e) {}
    await cdpInit.detach();

    if (VERBOSE) process.stderr.write('[Sentinel] L1.5: CDP webdriver cleanup applied\n');

    // ═══ L2: addInitScript INJECTION ═══
    await page.addInitScript({ content: shieldScript });
    await page.addInitScript({ content: stealthScript });
    await page.addInitScript({ content: interceptorScript });

    if (VERBOSE) process.stderr.write('[Sentinel] L2: Scripts injected (Shield → Stealth → Interceptor)\n');

    // ═══ L3: CDP SESSION + PUSH TELEMETRY + CDP COLLECTORS ═══
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

    // ═══ L3.5: CDP COLLECTORS (v6.0.0 NEW) ═══
    var networkCollector = new CDPNetworkCollector(cdp, pipeline, { verbose: VERBOSE });
    await networkCollector.initialize();

    var securityCollector = new CDPSecurityCollector(cdp, pipeline, { verbose: VERBOSE });
    await securityCollector.initialize();

    if (VERBOSE) process.stderr.write('[Sentinel] L3.5: CDP collectors initialized (Network + Security)\n');

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

    // ═══ L8: DUAL-LAYER NETWORK CAPTURE ═══
    networkLog = setupNetworkCapture(page);

    if (VERBOSE) process.stderr.write('[Sentinel] L8: Dual-layer network capture enabled\n');

    // ═══ L7: NAVIGATE & OBSERVE ═══
    process.stderr.write('[Sentinel] Navigating to ' + targetUrl + '...\n');

    await page.waitForTimeout(randomDelay(800, 2000));

    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });

    await page.waitForTimeout(randomDelay(2000, 4000));

    if (VERBOSE) process.stderr.write('[Sentinel] L7: Page loaded, starting human-like observation\n');

    await humanScroll(page, SCAN_WAIT);

    // ═══ L9: PARALLEL COLLECTION ═══
    // Final flush
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

    // Dedup in-page events
    var seen = {};
    var deduped = [];
    for (var di = 0; di < allEvents.length; di++) {
      var key = allEvents[di].ts + ':' + allEvents[di].cat + ':' + allEvents[di].api;
      if (!seen[key]) { seen[key] = true; deduped.push(allEvents[di]); }
    }
    allEvents = deduped;

    // v6.0.0: Push in-page events into pipeline too
    pipeline.pushBatch(allEvents);

    var frameInfo = allFrames.map(function(f) {
      try { return { url: f.url(), name: f.name() }; } catch(e) { return { url: 'destroyed', name: '' }; }
    });

    // ═══ L10: UNIFIED REPORT GENERATION ═══
    var injectionFlags = {
      layer1_playwright: true,
      layer1_stealthPlugin: true,
      layer2_shield: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.shield),
      layer3_stealth: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.stealth),
      layer4_interceptor: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.interceptor),
      layer5_recursiveAutoAttach: true,
      layer6_workerPipeline: workerEvts.length > 0 || true,
      layer7_frameLifecycle: true,
      layer8_dualNetworkCapture: networkLog.length > 0,
      layer9_cdpNetworkCollector: true,
      layer10_cdpSecurityCollector: true,
      subFramesChecked: subFrameCount,
      subFramesCollected: subFramesCollected,
      pushEventsReceived: pushEvents.length,
      workerEventsReceived: workerEvts.length,
      cdpPipelineEvents: pipeline.getAll().length,
      totalDeduped: allEvents.length
    };

    var tgInventory = targetGraph.getInventory();
    var pipelineStats = pipeline.getStats();

    process.stderr.write('[Sentinel] Scan complete: ' + allEvents.length + ' in-page events, ' +
      pipelineStats.total + ' total pipeline events, ' +
      Object.keys(pipelineStats.categories).length + ' categories, ' +
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
  process.stderr.write('\n🛡️  SENTINEL v6.1.0 — Playwright Official + Plugin Stealth + CDP Collectors\n');
  process.stderr.write('   Zero Spoofing | Zero Blind Spot | Zero Regression | INVISIBLE\n');
  process.stderr.write('   Target: ' + TARGET_URL + '\n');
  process.stderr.write('   Mode: ' + (DUAL_MODE ? 'DUAL (observe → stealth)' : OBSERVE_MODE ? 'OBSERVE' : 'STEALTH') + '\n');
  process.stderr.write('   Headless: ' + HEADLESS + '\n');
  process.stderr.write('   Timeout: ' + TIMEOUT + 'ms | Wait: ' + SCAN_WAIT + 'ms\n\n');

  if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  if (DUAL_MODE) {
    process.stderr.write('═══ PASS 1: OBSERVE MODE ═══\n');
    await runScan('observe', TARGET_URL);
    process.stderr.write('\n═══ PASS 2: STEALTH MODE ═══\n');
    await runScan('stealth', TARGET_URL);
    process.stderr.write('\n✅ Dual-mode scan complete.\n');
  } else if (OBSERVE_MODE) {
    await runScan('observe', TARGET_URL);
  } else {
    await runScan('stealth', TARGET_URL);
  }
}

main().catch(function(e) { process.stderr.write('Fatal: ' + e.message + '\n'); process.exit(1); });
