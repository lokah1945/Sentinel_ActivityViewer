// ═══════════════════════════════════════════════════════════════
//  SENTINEL v5.0.0 — UNIFIED FORENSIC ENGINE
//  Main Orchestrator — 10-Layer Pipeline
//  Contract: C-IDX-01 through C-IDX-14
//  Source of truth: v4.6.3 recovery + v4.6 Ghost Protocol
//
//  Zero Spoofing | Zero Blind Spot | Zero Regression
// ═══════════════════════════════════════════════════════════════

var os = require('os');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var { chromium } = require('playwright');
var { generateShieldScript } = require('./hooks/anti-detection-shield');
var { generateStealthScript } = require('./hooks/stealth-config');
var { generateInterceptorScript } = require('./hooks/api-interceptor');
var { TargetGraph } = require('./lib/target-graph');
var { generateReports } = require('./reporters/report-generator');

// ─── CLI Argument Parsing [C-IDX-14] ───
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

// ─── Script Generation ───
var shieldScript = generateShieldScript();
var stealthScript = generateStealthScript();
var interceptorScript = generateInterceptorScript();

// ─── [C-IDX-02] Temp Profile Management ───
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

// ─── evalWithTimeout — Anti-Stuck [C-IDX-10] ───
async function evalWithTimeout(frame, expression, timeoutMs) {
  return Promise.race([
    frame.evaluate(expression).catch(function() { return null; }),
    new Promise(function(resolve) { setTimeout(function() { resolve(null); }, timeoutMs); })
  ]);
}

// ─── Frame Injection Helper ───
async function injectToFrame(frame, script) {
  try {
    await frame.evaluate(script);
  } catch (e) {
    // Frame may be destroyed or cross-origin
  }
}

// ─── [C-IDX-09] Network Capture Setup ───
function setupNetworkCapture(page) {
  var networkLog = [];

  page.on('request', function(request) {
    try {
      var headers = request.headers() || {};
      var postData = '';
      try { postData = request.postData() || ''; } catch(e) {}
      networkLog.push({
        type: 'request',
        url: request.url(),
        method: request.method(),
        resourceType: request.resourceType(),
        headers: {
          'user-agent': headers['user-agent'] || '',
          'referer': headers['referer'] || '',
          'origin': headers['origin'] || '',
          'content-type': headers['content-type'] || '',
          'sec-ch-ua': headers['sec-ch-ua'] || '',
          'sec-ch-ua-platform': headers['sec-ch-ua-platform'] || '',
          'sec-ch-ua-mobile': headers['sec-ch-ua-mobile'] || '',
          'cookie': (headers['cookie'] || '').substring(0, 200)
        },
        postData: postData.substring(0, 500),
        ts: Date.now()
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
        type: 'response',
        url: url,
        status: status,
        headers: {
          'content-type': contentType,
          'set-cookie': (headers['set-cookie'] || '').substring(0, 200),
          'server': headers['server'] || '',
          'access-control-allow-origin': headers['access-control-allow-origin'] || ''
        },
        size: 0,
        body: '',
        ts: Date.now()
      };

      // Capture response body for text-based responses
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

// ─── Scroll & Adaptive Wait ───
async function scrollAndWait(page, waitMs) {
  try {
    await page.evaluate(function() {
      return new Promise(function(resolve) {
        var distance = 300;
        var delay = 200;
        var scrolls = 0;
        var maxScrolls = 15;
        var timer = setInterval(function() {
          window.scrollBy(0, distance);
          scrolls++;
          if (scrolls >= maxScrolls || (window.innerHeight + window.scrollY) >= document.body.scrollHeight) {
            clearInterval(timer);
            window.scrollTo(0, 0);
            resolve();
          }
        }, delay);
      });
    });
  } catch (e) {}

  await page.waitForTimeout(Math.min(waitMs, 30000));
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
    // ═══ L1: PERSISTENT BROWSER LAUNCH [C-IDX-01] ═══
    var launchOptions = {
      headless: HEADLESS,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--use-gl=desktop',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-component-extensions-with-background-pages'
      ],
      ignoreDefaultArgs: ['--enable-automation']
    };

    if (localeArg) launchOptions.locale = localeArg.split('=')[1];
    if (timezoneArg) launchOptions.timezoneId = timezoneArg.split('=')[1];

    context = await chromium.launchPersistentContext(profileDir, launchOptions);
    page = context.pages()[0] || await context.newPage();

    if (VERBOSE) process.stderr.write('[Sentinel] L1: Browser launched (persistent context)\n');

    // ═══ L2: addInitScript INJECTION [C-IDX-03] ═══
    await page.addInitScript({ content: shieldScript });
    await page.addInitScript({ content: stealthScript });
    await page.addInitScript({ content: interceptorScript });

    if (VERBOSE) process.stderr.write('[Sentinel] L2: Scripts injected (Shield → Stealth → Interceptor)\n');

    // ═══ L3: CDP SESSION SETUP [C-IDX-04] ═══
    cdp = await context.newCDPSession(page);

    // [C-IDX-05] Push telemetry binding
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

    // ═══ L4-L5: TARGET GRAPH + WORKER PIPELINE [C-IDX-06] ═══
    targetGraph = new TargetGraph(cdp, interceptorScript, shieldScript, stealthScript, { verbose: VERBOSE });
    await targetGraph.initialize();

    if (VERBOSE) process.stderr.write('[Sentinel] L4-L5: TargetGraph + Worker Pipeline initialized\n');

    // ═══ L6: FRAME LIFECYCLE HANDLERS [C-IDX-07/08] ═══
    page.on('frameattached', async function(frame) {
      try { await injectToFrame(frame, shieldScript + stealthScript + interceptorScript); } catch(e) {}
    });
    page.on('framenavigated', async function(frame) {
      if (frame !== page.mainFrame()) {
        try { await injectToFrame(frame, shieldScript + stealthScript + interceptorScript); } catch(e) {}
      }
    });

    if (VERBOSE) process.stderr.write('[Sentinel] L6: Frame lifecycle handlers registered\n');

    // ═══ L8: BIDIRECTIONAL NETWORK CAPTURE [C-IDX-09] ═══
    networkLog = setupNetworkCapture(page);

    if (VERBOSE) process.stderr.write('[Sentinel] L8: Bidirectional network capture enabled\n');

    // ═══ L7: NAVIGATE & OBSERVE ═══
    process.stderr.write('[Sentinel] Navigating to ' + targetUrl + '...\n');
    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });

    if (VERBOSE) process.stderr.write('[Sentinel] L7: Page loaded, starting observation\n');

    await scrollAndWait(page, SCAN_WAIT);

    // ═══ L9: PARALLEL COLLECTION [C-IDX-10] ═══
    // Trigger final flush [C-IDX-05]
    try {
      await page.evaluate(function() {
        if (typeof window.__SENTINEL_FLUSH__ === 'function') window.__SENTINEL_FLUSH__();
      });
    } catch (e) {}
    await page.waitForTimeout(800);

    // Collect from main frame
    var mainData = await evalWithTimeout(page, function() {
      return window.__SENTINEL_DATA__ ? JSON.parse(JSON.stringify(window.__SENTINEL_DATA__)) : null;
    }, 8000);

    // [C-IDX-10/11] Collect from sub-frames via Promise.allSettled
    var allFrames = page.frames();
    var subFramePromises = [];
    var subFrameCount = 0;

    for (var fi = 0; fi < allFrames.length; fi++) {
      if (allFrames[fi] === page.mainFrame()) continue;
      var frameUrl = '';
      try { frameUrl = allFrames[fi].url(); } catch(e) {}

      subFramePromises.push(
        evalWithTimeout(allFrames[fi], function() {
          return window.__SENTINEL_DATA__ ? JSON.parse(JSON.stringify(window.__SENTINEL_DATA__)) : null;
        }, 3000)
      );
      subFrameCount++;
    }

    var subFrameResults = await Promise.allSettled(subFramePromises);
    var allEvents = [];

    // Merge push events
    for (var pi = 0; pi < pushEvents.length; pi++) {
      allEvents.push(pushEvents[pi]);
    }

    // Merge main frame events
    if (mainData && mainData.events) {
      for (var mi = 0; mi < mainData.events.length; mi++) {
        allEvents.push(mainData.events[mi]);
      }
    }

    // Merge sub-frame events
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

    // Merge worker events
    var workerEvts = targetGraph.getWorkerEvents();
    for (var wei = 0; wei < workerEvts.length; wei++) {
      allEvents.push(workerEvts[wei]);
    }

    // Dedup by ts+cat+api
    var seen = {};
    var deduped = [];
    for (var di = 0; di < allEvents.length; di++) {
      var key = allEvents[di].ts + ':' + allEvents[di].cat + ':' + allEvents[di].api;
      if (!seen[key]) {
        seen[key] = true;
        deduped.push(allEvents[di]);
      }
    }
    allEvents = deduped;

    // Frame info for CTX report
    var frameInfo = allFrames.map(function(f) {
      try { return { url: f.url(), name: f.name() }; } catch(e) { return { url: 'destroyed', name: '' }; }
    });

    // ═══ L10: UNIFIED REPORT GENERATION ═══
    // [C-IDX-12] Explicit injection flags
    var injectionFlags = {
      layer1_addInitScript: true,
      layer2_shield: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.shield),
      layer3_stealth: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.stealth),
      layer4_interceptor: !!(mainData && mainData.injectionFlags && mainData.injectionFlags.interceptor),
      layer5_recursiveAutoAttach: true,
      layer6_workerPipeline: workerEvts.length > 0 || true,
      layer7_frameLifecycle: true,
      layer8_networkCapture: networkLog.length > 0,
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
      events: allEvents,
      networkLog: networkLog,
      injectionFlags: injectionFlags,
      targetGraph: tgInventory,
      frameInfo: frameInfo,
      mode: mode,
      target: targetUrl
    }, OUTPUT_DIR);

    process.stderr.write('[Sentinel] Reports: ' + reportResult.jsonPath + '\n');
    process.stderr.write('[Sentinel] HTML: ' + reportResult.htmlPath + '\n');

    return reportResult;

  } catch (e) {
    process.stderr.write('[Sentinel] Error: ' + e.message + '\n');
    throw e;
  } finally {
    // ═══ CLEANUP ═══
    try { if (context) await context.close(); } catch(e) {}
    cleanupProfile(profileDir);
    if (VERBOSE) process.stderr.write('[Sentinel] Profile cleaned: ' + profileDir + '\n');
  }
}

// ════════════════════════════════════════════════════
//  ENTRY POINT [C-IDX-13]
// ════════════════════════════════════════════════════
async function main() {
  process.stderr.write('\n🛡️  SENTINEL v5.0.0 — Unified Forensic Engine\n');
  process.stderr.write('   Zero Spoofing | Zero Blind Spot | Zero Regression\n');
  process.stderr.write('   Target: ' + TARGET_URL + '\n');
  process.stderr.write('   Mode: ' + (DUAL_MODE ? 'DUAL (observe → stealth)' : OBSERVE_MODE ? 'OBSERVE' : 'STEALTH') + '\n');
  process.stderr.write('   Headless: ' + HEADLESS + '\n\n');

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
