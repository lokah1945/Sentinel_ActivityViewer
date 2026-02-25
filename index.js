// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — HYBRID DUAL-TELEMETRY FORENSIC ENGINE
//  Main Orchestrator: 12-Layer Pipeline
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - PURE NEW CONCEPT: Hybrid engine combining:
//     * v6.4 basis: persistentContext, rebrowser-patches, CDP observer,
//       auto-cleanup, stealth plugin
//     * v6.1/v5.0 restored: hook layer (42 categories), push telemetry,
//       frame lifecycle handlers, bidirectional network capture
//   - L1:  Persistent Browser Launch (from v6.4 — REG-022)
//   - L2:  Stealth Plugin + rebrowser patches (from v6.4 — REG-028)
//   - L3:  addInitScript Injection — Shield + Interceptor (RESTORED — REG-001)
//   - L4:  CDP Session Setup + Runtime.addBinding (from v6.1)
//   - L5:  Push Telemetry receiver (500ms — REG-015)
//   - L6:  Recursive Auto-Attach — TargetGraph (from v6.4 — REG-016)
//   - L7:  Worker Pipeline — Network.enable per worker (from v6.4)
//   - L8:  Frame Lifecycle Handlers (RESTORED — REG-006, REG-007)
//   - L9:  CDP Domain Collectors (from v6.4 — REG-026)
//   - L10: Bidirectional Network Capture (RESTORED)
//   - L11: Parallel Collection + Dedup + Merge (REG-018)
//   - L12: Unified Report Generation — JSON/HTML/CTX
//   - REG-021: Final flush before browser close
//   - REG-022: launchPersistentContext as default
//   - REG-027: persistentContext auto-cleanup
//   - NO BACKWARD COMPATIBILITY — pure v7.0.0 architecture
//
// LAST HISTORY LOG:
//   v6.4.0: CDP-only observer, persistentContext, auto-cleanup
//   v6.1.0: Hook layer + CDP collectors, standard launch
//   v5.0.0: Unified engine with 42 categories
//   v7.0.0: Hybrid dual-telemetry (hook + CDP) with persistent context
// ═══════════════════════════════════════════════════════════════

'use strict';

var fs = require('fs');
var path = require('path');
var { chromium } = require('playwright-extra');
var { createStealthPlugin } = require('./hooks/stealth-config');
var { getShieldScript } = require('./hooks/anti-detection-shield');
var { getInterceptorScript } = require('./hooks/api-interceptor');
var { EventPipeline } = require('./lib/event-pipeline');
var { CdpObserverEngine } = require('./lib/cdp-observer-engine');
var { TargetGraph } = require('./lib/target-graph');
var { CorrelationEngine } = require('./lib/correlation-engine');
var { ReportGenerator } = require('./reporters/report-generator');

// ═══════════════════════════════════════════
//  CONFIGURATION
// ═══════════════════════════════════════════
var VERSION = 'sentinel-v7.0.0';
var DEFAULT_TARGET = 'https://browserscan.net';
var DEFAULT_TIMEOUT = 30000;
var CLEANUP_PROFILE = true;
var PROFILE_BASE = path.join(process.cwd(), '.sentinel-profiles');

// Parse CLI arguments
var args = process.argv.slice(2);
var TARGET = args[0] || DEFAULT_TARGET;
var MODE = (args[1] || 'stealth').toLowerCase();
var TIMEOUT = parseInt(args[2]) || DEFAULT_TIMEOUT;

if (MODE !== 'stealth' && MODE !== 'observe') {
  process.stderr.write('Usage: node index.js [url] [stealth|observe] [timeout_ms]\n');
  process.exit(1);
}

// ═══════════════════════════════════════════
//  MAIN EXECUTION
// ═══════════════════════════════════════════
(async function main() {
  var ts = Date.now();
  var profileDir = path.join(PROFILE_BASE, 'profile-' + ts);

  process.stderr.write('\n');
  process.stderr.write('═══════════════════════════════════════════════════════════\n');
  process.stderr.write('  ' + VERSION + ' — Hybrid Dual-Telemetry CCTV\n');
  process.stderr.write('  Target: ' + TARGET + '\n');
  process.stderr.write('  Mode: ' + MODE + ' | Timeout: ' + TIMEOUT + 'ms\n');
  process.stderr.write('═══════════════════════════════════════════════════════════\n\n');

  // ─── L1: PIPELINE INITIALIZATION ───
  var pipeline = new EventPipeline({ maxBuffer: 100000 });
  process.stderr.write('[L1] Pipeline initialized\n');

  // ─── L2: STEALTH PLUGIN (REG-028: rebrowser-patched core) ───
  var stealth = createStealthPlugin();
  chromium.use(stealth);
  process.stderr.write('[L2] Stealth plugin loaded (17 evasions)\n');

  // ─── L1: PERSISTENT BROWSER LAUNCH (REG-022, REG-027) ───
  var launchOpts = {
    headless: false,
    args: [
      '--disable-blink-features=AutomationControlled',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-infobars',
      '--disable-session-crashed-bubble',
      '--disable-features=TranslateUI'
    ]
  };

  process.stderr.write('[L1] Launching persistent context: ' + profileDir + '\n');
  var context = await chromium.launchPersistentContext(profileDir, launchOpts);
  process.stderr.write('[L1] Browser launched (persistentContext)\n');

  var browser = null;
  var page = null;

  try {
    // Get or create page
    var pages = context.pages();
    page = pages.length > 0 ? pages[0] : await context.newPage();

    // ─── L3: addInitScript INJECTION (REG-001: PRIMARY injection) ───
    // Shield MUST be injected FIRST (provides hook utilities)
    await context.addInitScript({ content: getShieldScript() });
    process.stderr.write('[L3] Shield injected via addInitScript\n');

    // Interceptor injected SECOND (uses shield utilities)
    await context.addInitScript({ content: getInterceptorScript({
      timeout: TIMEOUT,
      maxEvents: 50000,
      pushInterval: 500
    }) });
    process.stderr.write('[L3] Interceptor injected (42 categories, 110+ hooks)\n');

    // ─── L4: CDP SESSION + RUNTIME BINDING ───
    var cdp = await context.newCDPSession(page);
    process.stderr.write('[L4] CDP session established\n');

    // Runtime.addBinding for push telemetry from hooks
    await cdp.send('Runtime.addBinding', { name: 'SENTINEL_PUSH' });
    process.stderr.write('[L4] SENTINEL_PUSH binding registered\n');

    // ─── L5: PUSH TELEMETRY RECEIVER ───
    cdp.on('Runtime.bindingCalled', function(params) {
      if (params.name === 'SENTINEL_PUSH') {
        try {
          var payload = JSON.parse(params.payload);
          if (payload.type === 'events' && Array.isArray(payload.events)) {
            pipeline.pushBatchHook(payload.events);
          }
        } catch (e) {
          process.stderr.write('[L5] Push parse error: ' + e.message + '\n');
        }
      }
    });
    process.stderr.write('[L5] Push telemetry receiver active (500ms interval)\n');

    // ─── L9: CDP OBSERVER ENGINE (REG-026: ALL domains enabled) ───
    var observer = new CdpObserverEngine(pipeline, cdp);
    await observer.start();
    process.stderr.write('[L9] CDP observer started (Network, Page, Security, Console, DOM, Performance, Runtime)\n');

    // ─── L6: TARGET GRAPH — Recursive Auto-Attach (REG-016) ───
    var targetGraph = new TargetGraph(pipeline, cdp, context);
    await targetGraph.start();
    process.stderr.write('[L6] TargetGraph started (recursive auto-attach)\n');

    // ─── L8: FRAME LIFECYCLE HANDLERS (REG-006, REG-007) ───
    page.on('frameattached', function(frame) {
      pipeline.pushPage({
        cat: 'frame-lifecycle',
        api: 'frameattached-pw',
        risk: 'info',
        detail: 'PW frameattached: ' + (frame.url() || 'about:blank')
      });
    });
    page.on('framenavigated', function(frame) {
      pipeline.pushPage({
        cat: 'frame-lifecycle',
        api: 'framenavigated-pw',
        risk: 'info',
        detail: 'PW framenavigated: ' + frame.url()
      });
    });
    page.on('framedetached', function(frame) {
      pipeline.pushPage({
        cat: 'frame-lifecycle',
        api: 'framedetached-pw',
        risk: 'info',
        detail: 'PW framedetached'
      });
    });
    process.stderr.write('[L8] Frame lifecycle handlers registered\n');

    // ─── L10: BIDIRECTIONAL NETWORK CAPTURE ───
    page.on('request', function(req) {
      pipeline.pushPage({
        cat: 'network-request',
        api: req.method(),
        risk: 'info',
        detail: req.method() + ' ' + req.url().slice(0, 300),
        meta: { type: req.resourceType(), url: req.url() }
      });
    });
    page.on('response', function(resp) {
      pipeline.pushPage({
        cat: 'network-response',
        api: String(resp.status()),
        risk: resp.status() >= 400 ? 'high' : 'info',
        detail: resp.status() + ' ' + resp.url().slice(0, 300),
        meta: { status: resp.status(), url: resp.url() }
      });
    });
    process.stderr.write('[L10] Bidirectional network capture active\n');

    // ─── NAVIGATE TO TARGET ───
    process.stderr.write('\n[NAV] Navigating to ' + TARGET + '...\n');
    await page.goto(TARGET, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });
    process.stderr.write('[NAV] Page loaded, waiting ' + TIMEOUT + 'ms for activity...\n');

    // ─── WAIT FOR ACTIVITY ───
    await new Promise(function(resolve) { setTimeout(resolve, TIMEOUT); });

    // ─── L5: FINAL FLUSH (REG-021) ───
    try {
      await page.evaluate(function() {
        if (typeof window._SENTINEL_DATA !== 'undefined' && typeof window.SENTINEL_PUSH === 'function') {
          var lastIdx = window._SENTINEL_DATA._lastPushIndex || 0;
          var batch = window._SENTINEL_DATA.events.slice(lastIdx);
          if (batch.length > 0) {
            window.SENTINEL_PUSH(JSON.stringify({
              type: 'events',
              count: batch.length,
              total: window._SENTINEL_DATA.events.length,
              events: batch,
              frame: window._SENTINEL_DATA.frameType,
              ts: Date.now()
            }));
          }
        }
      });
    } catch (e) {
      process.stderr.write('[L5] Final flush warning: ' + e.message + '\n');
    }
    process.stderr.write('[L5] Final event flush completed\n');

    // Small wait for final push to arrive
    await new Promise(function(resolve) { setTimeout(resolve, 500); });

    // ─── L11: PARALLEL COLLECTION + MERGE (REG-018) ───
    var events = pipeline.drain();
    var pStats = pipeline.getStats();
    var frames = observer.getFrames();
    var tgStats = targetGraph.getStats();

    process.stderr.write('\n[L11] Collection complete:\n');
    process.stderr.write('  Total events (deduped): ' + events.length + '\n');
    process.stderr.write('  Hook events: ' + pStats.hookEvents + '\n');
    process.stderr.write('  CDP events: ' + pStats.cdpEvents + '\n');
    process.stderr.write('  Page events: ' + pStats.pageEvents + '\n');
    process.stderr.write('  Frames: ' + frames.length + '\n');
    process.stderr.write('  Targets: ' + tgStats.discovered + ' discovered, ' + tgStats.attached + ' attached\n');

    // ─── L11: ANALYSIS ───
    var engine = new CorrelationEngine(VERSION);
    var analysis = engine.analyze(events, frames, pStats);

    var catCount = analysis.categories.length;
    process.stderr.write('  Categories detected: ' + catCount + '\n');
    process.stderr.write('  Risk score: ' + analysis.riskScore + '\n');

    // ─── BUILD CONTEXT ───
    var contextData = {
      version: VERSION,
      target: TARGET,
      mode: MODE,
      scanDate: new Date(ts).toISOString(),
      timeout: TIMEOUT,
      engine: 'hybrid-dual-telemetry',
      layers: {
        L1: 'persistentContext + auto-cleanup',
        L2: 'stealth-plugin (17 evasions) + rebrowser-patches',
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
      categoriesMonitored: 42,
      hookPoints: analysis.hookStats ? (analysis.hookStats.hookEventCount > 0 ? '110+' : '0') : '0',
      categoryCoverage: ((catCount / 42) * 100).toFixed(1) + '%'
    };

    // ─── L12: REPORT GENERATION ───
    var reporter = new ReportGenerator(VERSION);
    var paths = reporter.save(MODE, ts, events, analysis, contextData);

    process.stderr.write('\n[L12] Reports generated:\n');
    process.stderr.write('  JSON: ' + paths.json + '\n');
    process.stderr.write('  HTML: ' + paths.html + '\n');
    process.stderr.write('  CTX:  ' + paths.context + '\n');

    // ─── SUMMARY ───
    process.stderr.write('\n═══════════════════════════════════════════════════════════\n');
    process.stderr.write('  SCAN COMPLETE\n');
    process.stderr.write('  Events: ' + events.length + ' (hook:' + pStats.hookEvents + ' + cdp:' + pStats.cdpEvents + ' + page:' + pStats.pageEvents + ')\n');
    process.stderr.write('  Categories: ' + catCount + '/42 (' + contextData.categoryCoverage + ')\n');
    process.stderr.write('  Risk Score: ' + analysis.riskScore + '/100\n');
    process.stderr.write('  Libraries: ' + analysis.libraryDetections.length + '\n');
    process.stderr.write('═══════════════════════════════════════════════════════════\n');

  } catch (err) {
    process.stderr.write('\n[ERROR] ' + err.message + '\n');
    process.stderr.write(err.stack + '\n');
  } finally {
    // Close browser
    try {
      await context.close();
    } catch (e) {}

    // ─── REG-027: Auto-cleanup persistent context ───
    if (CLEANUP_PROFILE) {
      try {
        fs.rmSync(profileDir, { recursive: true, force: true });
        process.stderr.write('[CLEANUP] Profile removed: ' + profileDir + '\n');
      } catch (e) {
        process.stderr.write('[CLEANUP] Warning: ' + e.message + '\n');
      }
    }
  }
})();
