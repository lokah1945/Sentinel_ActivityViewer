#!/usr/bin/env node
/**
 * ╔═══════════════════════════════════════════════════════════╗
 * ║   🛡️  SENTINEL v4.6 — GHOST PROTOCOL FORENSIC CATCHER     ║
 * ║   Recursive Coverage | Worker Pipeline | Quiet Mode        ║
 * ║   Zero Spoofing | Bidirectional Capture | 1H5W Framework   ║
 * ╚═══════════════════════════════════════════════════════════╝
 *
 * v4.6 KEY IMPROVEMENTS over v4.5:
 *   1. Recursive auto-attach: ALL nested iframes get monitored (not just direct children)
 *   2. Worker pipeline: Dedicated/Shared/Service workers get network+runtime monitoring
 *   3. about:blank sandbox triage: Smart detection of active vs empty blank frames
 *   4. Quiet mode: No enumerable globals, no console output from sentinel
 *   5. Coverage proof: Report includes per-target attach/inject/boot evidence
 *   6. HTML report bug fix: "vc is not defined" error resolved
 *   7. 5 new detection categories (42 total, 220+ hooks)
 *   8. postMessage/cross-frame communication monitoring
 *
 * Usage:
 *   node index.js <url>                     — Quick scan
 *   node index.js <url> --no-headless       — Show browser window
 *   node index.js <url> --timeout=45000     — Custom timeout
 *   node index.js <url> --dual-mode         — Run observe then stealth, compare
 *   node index.js <url> --observe           — No automation cleanup at all
 *   node index.js <url> --verbose           — Show target graph debug info
 */

const { getExtraStealthScript } = require('./hooks/stealth-config');
const { getAntiDetectionScript } = require('./hooks/anti-detection-shield');
const { getInterceptorScript } = require('./hooks/api-interceptor');
const { generateReport } = require('./reporters/report-generator');
const { TargetGraph } = require('./lib/target-graph');
const readline = require('readline');
const path = require('path');
const fs = require('fs');
const os = require('os');

// ── Parse CLI arguments ──
const args = process.argv.slice(2);
const flags = {};
let targetUrl = null;

for (const arg of args) {
  if (arg.startsWith('--')) {
    const [key, val] = arg.slice(2).split('=');
    flags[key] = val || true;
  } else if (!targetUrl) {
    targetUrl = arg;
  }
}

const TIMEOUT = parseInt(flags.timeout) || 30000;
const HEADLESS = flags['no-headless'] ? false : true;
const DUAL_MODE = flags['dual-mode'] === true;
const OBSERVE_ONLY = flags.observe === true;
const VERBOSE = flags.verbose === true;

function normalizeUrl(input) {
  input = input.trim();
  if (!input.match(/^https?:\/\//i)) input = 'https://' + input;
  return input;
}

async function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer.trim()); }));
}

function createTempProfile() {
  const tmpBase = path.join(os.tmpdir(), 'sentinel-profiles');
  if (!fs.existsSync(tmpBase)) fs.mkdirSync(tmpBase, { recursive: true });
  const profileDir = path.join(tmpBase, `sentinel_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);
  fs.mkdirSync(profileDir, { recursive: true });
  return profileDir;
}

function cleanupProfile(profileDir) {
  try {
    if (profileDir && fs.existsSync(profileDir)) {
      fs.rmSync(profileDir, { recursive: true, force: true });
      console.log(`  🗑️  Profile cleaned: ${path.basename(profileDir)}`);
    }
  } catch(e) {
    console.warn(`  ⚠️  Profile cleanup failed: ${e.message}`);
  }
}

/**
 * Evaluate with timeout — prevents stuck on destroyed/cross-origin frames
 */
async function evalWithTimeout(target, fn, ms) {
  ms = ms || 5000;
  return Promise.race([
    target.evaluate(fn),
    new Promise((_, rej) => setTimeout(() => rej(new Error('EVAL_TIMEOUT')), ms))
  ]);
}

/**
 * Setup bidirectional network capture.
 * Records the full "conversation" between maling and browser.
 */
function setupNetworkCapture(page) {
  const networkLog = [];

  page.on('request', (request) => {
    try {
      const url = request.url();
      if (url.startsWith('data:')) return;
      networkLog.push({
        ts: Date.now(),
        dir: 'request',
        method: request.method(),
        url: url.slice(0, 500),
        resourceType: request.resourceType(),
        headers: (() => {
          try {
            const h = request.headers();
            const keep = {};
            for (const k of ['user-agent', 'referer', 'origin', 'content-type', 'cookie',
              'accept', 'accept-language', 'sec-ch-ua', 'sec-ch-ua-platform',
              'sec-ch-ua-mobile', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site']) {
              if (h[k]) keep[k] = h[k].slice(0, 300);
            }
            return keep;
          } catch(e) { return {}; }
        })(),
        postData: (() => {
          try { return request.postData() ? request.postData().slice(0, 1000) : null; } catch(e) { return null; }
        })()
      });
    } catch(e) {}
  });

  page.on('response', async (response) => {
    try {
      const url = response.url();
      if (url.startsWith('data:')) return;
      const entry = {
        ts: Date.now(),
        dir: 'response',
        status: response.status(),
        statusText: response.statusText(),
        url: url.slice(0, 500),
        headers: (() => {
          try {
            const h = response.headers();
            const keep = {};
            for (const k of ['content-type', 'content-length', 'set-cookie',
              'cache-control', 'access-control-allow-origin', 'x-powered-by', 'server',
              'content-security-policy', 'x-frame-options', 'strict-transport-security']) {
              if (h[k]) keep[k] = h[k].slice(0, 300);
            }
            return keep;
          } catch(e) { return {}; }
        })()
      };

      try {
        const ct = response.headers()['content-type'] || '';
        if (ct.match(/json|text|javascript|html|css|xml/i)) {
          const bodyText = await response.text().catch(() => null);
          if (bodyText) {
            entry.bodyPreview = bodyText.slice(0, 2000);
            entry.bodySize = bodyText.length;
          }
        } else {
          const body = await response.body().catch(() => null);
          if (body) entry.bodySize = body.length;
        }
      } catch(e) {
        entry.bodyPreview = null;
      }

      networkLog.push(entry);
    } catch(e) {}
  });

  return networkLog;
}

const OUTPUT_DIR = path.join(__dirname, 'output');

async function runScan(url, options = {}) {
  const stealthEnabled = options.stealth !== false;
  const label = stealthEnabled ? '🥷 STEALTH' : '👁️ OBSERVE';
  let profileDir = null;

  console.log(`\n${'═'.repeat(65)}`);
  console.log(`  ${label} MODE — Sentinel v4.6 Ghost Protocol`);
  console.log(`  Target: ${url}`);
  console.log(`  Timeout: ${TIMEOUT / 1000}s | Headless: ${HEADLESS}`);
  console.log(`  Spoofing: NONE | Quiet: ON | Recursive: ON`);
  console.log(`${'═'.repeat(65)}\n`);

  let context, page, cdpSession, targetGraph, networkLog;
  const injectionFlags = {
    L1_addInitScript: false,
    L2_automationCleanup: false,
    L3_cdpSupplement: false,
    L4_perFrame: false,
    L5_recursiveAutoAttach: false,
    L6_workerPipeline: false
  };

  try {
    // ══════════════════════════════════════
    //  STEP 1: LAUNCH BROWSER
    // ══════════════════════════════════════
    console.log('[1/8] Launching browser (persistent context, zero plugins)...');
    const { chromium } = require('playwright');

    const launchArgs = [
      '--disable-blink-features=AutomationControlled',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding',
    ];

    profileDir = createTempProfile();
    if (VERBOSE) console.log(`  → Temp profile: ${path.basename(profileDir)}`);

    context = await chromium.launchPersistentContext(profileDir, {
      headless: HEADLESS,
      args: launchArgs,
      ignoreDefaultArgs: ['--enable-automation'],
      viewport: { width: 1920, height: 1080 },
      permissions: [],
      colorScheme: 'light',
    });
    page = context.pages()[0] || await context.newPage();
    console.log('  ✅ Browser launched');

    // ══════════════════════════════════════
    //  STEP 2: INJECTION via addInitScript
    // ══════════════════════════════════════
    console.log('[2/8] Injecting monitoring hooks...');

    const shieldScript = getAntiDetectionScript();
    const stealthScript = stealthEnabled ? getExtraStealthScript() : '';
    const interceptorScript = getInterceptorScript({
      timeout: TIMEOUT,
      stealthEnabled: stealthEnabled,
      stackSampleRate: 10
    });

    // Shield first (always)
    await page.addInitScript(shieldScript);

    // Stealth cleanup (only in stealth mode)
    if (stealthEnabled) {
      await page.addInitScript(stealthScript);
      injectionFlags.L2_automationCleanup = true;
    }

    // API Interceptor
    await page.addInitScript(interceptorScript);
    injectionFlags.L1_addInitScript = true;
    console.log('  ✅ Hooks injected (42 categories, 220+ hooks)');

    // ══════════════════════════════════════
    //  STEP 3: CDP SESSION + TARGET GRAPH
    // ══════════════════════════════════════
    console.log('[3/8] Setting up CDP + Target Graph (recursive auto-attach)...');

    cdpSession = await page.context().newCDPSession(page);

    // Initialize the Target Graph Walker
    targetGraph = new TargetGraph({
      verbose: VERBOSE,
      injectionScript: shieldScript + ';\n' + stealthScript + ';\n' + interceptorScript,
      shieldScript: shieldScript,
      stealthScript: stealthScript
    });
    await targetGraph.initialize(cdpSession);
    injectionFlags.L3_cdpSupplement = true;
    injectionFlags.L5_recursiveAutoAttach = true;
    console.log('  ✅ Target Graph Walker active (recursive auto-attach)');

    // Setup bidirectional network capture
    networkLog = setupNetworkCapture(page);
    console.log('  ✅ Network conversation capture active');

    // Per-frame injection for late-attached frames (via Playwright API)
    page.on('frameattached', async (frame) => {
      try {
        const fUrl = frame.url() || '';
        // Skip truly empty frames
        if (!fUrl && !frame.parentFrame()) return;
        await frame.evaluate(shieldScript + ';\n' +
          (stealthEnabled ? stealthScript + ';\n' : '') +
          interceptorScript).catch(() => {});
        injectionFlags.L4_perFrame = true;
      } catch(e) {}
    });

    // ══════════════════════════════════════
    //  STEP 4: NAVIGATE TO TARGET
    // ══════════════════════════════════════
    console.log('[4/8] Navigating to target...');
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });
    } catch(e) {
      await page.goto(url, { waitUntil: 'commit', timeout: TIMEOUT * 2 });
    }
    console.log(`  🌐 Page loaded: ${page.url()}`);

    // Diagnostic check (quiet — no globals exposed)
    try {
      const active = await page.evaluate(() => {
        // Check for non-enumerable sentinel data
        return Object.getOwnPropertyNames(window).some(function(k) {
          return k === '__SENTINEL_DATA__' || k === '__SENTINEL_ACTIVE__' || k.indexOf('_sd') === 0;
        });
      });
      const bootOk = await page.evaluate(() => {
        try { return window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.bootOk : false; } catch(e) { return false; }
      });
      const shieldOk = await page.evaluate(() => !!window.__SENTINEL_SHIELD__);
      if (VERBOSE) console.log(`  🔍 Diagnostic: ACTIVE=${active} | BOOT=${bootOk} | SHIELD=${shieldOk}`);
      if (!active) {
        console.error('  🔴 CRITICAL: Injection failed! Emergency re-inject...');
        await page.evaluate(shieldScript + ';\n' +
          (stealthEnabled ? stealthScript + ';\n' : '') + interceptorScript);
      }
    } catch(e) {
      if (VERBOSE) console.warn('  ⚠️ Diagnostic check failed:', e.message);
    }

    // ══════════════════════════════════════
    //  STEP 5: OBSERVE ACTIVITY
    // ══════════════════════════════════════
    console.log('[5/8] Observing activity...');
    const observeTime = Math.max(TIMEOUT - 5000, 10000);

    // Simulate realistic user behavior (scroll patterns)
    await page.waitForTimeout(Math.floor(observeTime * 0.35));
    try { await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight / 3)); } catch(e) {}
    await page.waitForTimeout(1500);
    try { await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight * 0.6)); } catch(e) {}
    await page.waitForTimeout(1500);
    try { await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight)); } catch(e) {}
    await page.waitForTimeout(1500);
    try { await page.evaluate(() => window.scrollTo(0, 0)); } catch(e) {}

    const remaining = observeTime - Math.floor(observeTime * 0.35) - 4500;
    if (remaining > 0) await page.waitForTimeout(remaining);

    const midCount = await page.evaluate(() => {
      try { return window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.events.length : 0; } catch(e) { return 0; }
    }).catch(() => 0);
    const graphSummary = targetGraph.getSummary();
    console.log(`  📊 Events: ${midCount} (API) + ${networkLog.length} (network) | Targets: ${graphSummary.totalTargets} (${graphSummary.iframes} iframes, ${graphSummary.workers} workers)`);

    // Adaptive wait if low event count
    if (midCount < 50) {
      await page.waitForTimeout(Math.min(TIMEOUT, 15000));
    }

    // ══════════════════════════════════════
    //  STEP 6: COLLECT WORKER EVENTS
    // ══════════════════════════════════════
    console.log('[6/8] Collecting worker events...');
    let workerEvents = [];
    try {
      workerEvents = await targetGraph.collectWorkerEvents(cdpSession);
      if (workerEvents.length > 0) {
        injectionFlags.L6_workerPipeline = true;
      }
      console.log(`  📦 Worker events: ${workerEvents.length}`);
    } catch(e) {
      if (VERBOSE) console.warn(`  ⚠️ Worker collection failed: ${e.message}`);
    }

    // ══════════════════════════════════════
    //  STEP 7: COLLECT FORENSIC DATA (anti-stuck)
    // ══════════════════════════════════════
    console.log('[7/8] Collecting forensic data...');

    // Final flush via push telemetry
    try {
      await page.evaluate(() => {
        var pushFn = typeof window.__SENTINEL_PUSH__ === 'function' ? window.__SENTINEL_PUSH__ :
                     typeof window.__s46push__ === 'function' ? window.__s46push__ : null;
        if (pushFn && window.__SENTINEL_DATA__) {
          try {
            pushFn(JSON.stringify({
              type: 'final_flush',
              frameId: window.__SENTINEL_DATA__.frameId || '',
              events: window.__SENTINEL_DATA__.events.slice(-100)
            }));
          } catch(e) {}
        }
      });
      await page.waitForTimeout(500);
    } catch(e) {}

    // Collect from main frame
    let sentinelData;
    try {
      sentinelData = await evalWithTimeout(page, () => {
        if (window.__SENTINEL_DATA__) {
          return {
            events: window.__SENTINEL_DATA__.events || [],
            bootOk: window.__SENTINEL_DATA__.bootOk || false,
            frameId: window.__SENTINEL_DATA__.frameId || '',
            dedupCount: window.__SENTINEL_DATA__.dedupCount || 0
          };
        }
        if (typeof window.__SENTINEL_FLUSH__ === 'function') {
          var flushed = JSON.parse(window.__SENTINEL_FLUSH__());
          return { events: flushed.events || [], bootOk: true, frameId: 'flushed', dedupCount: 0 };
        }
        return { events: [], bootOk: false, frameId: 'none', dedupCount: 0 };
      }, 8000);
    } catch(e) {
      console.warn(`  ⚠️ Main frame timeout: ${e.message}`);
      sentinelData = { events: [], bootOk: false, frameId: 'error', dedupCount: 0 };
    }
    console.log(`  📦 Main frame: ${sentinelData.events.length} events`);

    // Collect from sub-frames (parallel + timeout + smart triage)
    const frames = page.frames();
    const framePromises = [];
    const frameInfoList = [];

    for (let i = 0; i < frames.length; i++) {
      const f = frames[i];
      const fUrl = f.url() || '';
      let fOrigin = null;
      try { if (fUrl.startsWith('http')) fOrigin = new URL(fUrl).origin; } catch(e) {}
      frameInfoList.push({ type: 'frame', url: fUrl, origin: fOrigin, name: f.name() || '', index: i });

      if (i === 0) continue; // skip main frame (already collected)

      // v4.6 SMART TRIAGE: Don't skip about:blank if it might have activity
      const shouldCollect = (() => {
        if (fUrl.startsWith('http')) return true;  // Always collect http frames
        if (fUrl === 'about:srcdoc') return true;  // srcdoc frames often have scripts
        if (fUrl === 'about:blank' || !fUrl) {
          // Check if this frame has a name (named frames are usually functional)
          if (f.name()) return true;
          // Check if parent is same-origin main frame
          try {
            const parent = f.parentFrame();
            if (parent && parent === page.mainFrame()) return true;
          } catch(e) {}
          return false; // Truly empty blank frame
        }
        return false;
      })();

      if (!shouldCollect) continue;

      framePromises.push(
        evalWithTimeout(f, () => {
          if (window.__SENTINEL_DATA__) {
            return {
              events: window.__SENTINEL_DATA__.events || [],
              bootOk: window.__SENTINEL_DATA__.bootOk || false,
              frameId: window.__SENTINEL_DATA__.frameId || ''
            };
          }
          if (typeof window.__SENTINEL_FLUSH__ === 'function') {
            var fl = JSON.parse(window.__SENTINEL_FLUSH__());
            return { events: fl.events || [], bootOk: true, frameId: 'flushed' };
          }
          return null;
        }, 3000).catch(() => null)
      );
    }

    let subFrameEvents = 0;
    if (framePromises.length > 0) {
      const results = await Promise.allSettled(framePromises);
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value && r.value.events && r.value.events.length > 0) {
          sentinelData.events = sentinelData.events.concat(r.value.events);
          subFrameEvents += r.value.events.length;
        }
      }
    }
    console.log(`  📦 Frames: ${frames.length} total, ${framePromises.length} collected (${subFrameEvents} sub-frame events)`);

    // Merge CDP push events from target graph
    if (targetGraph.events.length > 0) {
      const existingTs = new Set(sentinelData.events.map(e => e.ts + ':' + e.api));
      let merged = 0;
      for (const pe of targetGraph.events) {
        if (!existingTs.has(pe.ts + ':' + pe.api)) {
          sentinelData.events.push(pe);
          merged++;
        }
      }
      if (VERBOSE) console.log(`  📦 Merged ${merged} CDP push events`);
    }

    // Merge worker events
    if (workerEvents.length > 0) {
      for (const we of workerEvents) {
        sentinelData.events.push({
          ts: we.ts,
          cat: 'worker',
          api: we.api,
          detail: JSON.stringify({ url: we.url, type: we.workerType }).slice(0, 500),
          risk: 'high',
          dir: 'call',
          origin: we.workerUrl || 'worker',
          frame: 'worker:' + (we.targetId || '').slice(0, 8)
        });
      }
    }

    console.log(`  📦 Grand total: ${sentinelData.events.length} API events + ${networkLog.length} network events + ${workerEvents.length} worker events`);

    // Build context map
    const pageCtxMap = await page.evaluate(() => window.__SENTINEL_CONTEXT_MAP__ || []).catch(() => []);
    const fullContextMap = [...(pageCtxMap || []), ...frameInfoList];

    // Get target graph inventory for coverage proof
    const targetInventory = targetGraph.getInventory();
    const targetSummary = targetGraph.getSummary();

    // ══════════════════════════════════════
    //  STEP 8: GENERATE REPORT
    // ══════════════════════════════════════
    console.log('[8/8] Generating forensic report...');

    const reportResult = generateReport(sentinelData, fullContextMap, url, {
      stealthEnabled,
      prefix: `sentinel_${stealthEnabled ? 'stealth' : 'observe'}_${Date.now()}`,
      injectionFlags,
      frameInfo: frameInfoList,
      networkLog: networkLog,
      workerEvents: workerEvents,
      targetInventory: targetInventory,
      targetSummary: targetSummary
    });

    const r = reportResult.reportJson;

    console.log(`\nReports saved:`);
    console.log(`   JSON: ${reportResult.jsonPath}`);
    console.log(`   HTML: ${reportResult.htmlPath}`);
    console.log(`   CTX:  ${reportResult.ctxPath}`);

    console.log('');
    console.log('┌──────────────────────────────────────────────────────┐');
    console.log(`│  🛡️ SENTINEL v4.6 — GHOST PROTOCOL SUMMARY            │`);
    console.log('├──────────────────────────────────────────────────────┤');
    console.log(`│  API Events:      ${String(r.totalEvents).padEnd(8)}`);
    console.log(`│  Network Events:  ${String(networkLog.length).padEnd(8)} (${networkLog.filter(n=>n.dir==='request').length} req / ${networkLog.filter(n=>n.dir==='response').length} resp)`);
    console.log(`│  Worker Events:   ${String(workerEvents.length).padEnd(8)}`);
    console.log(`│  Risk Score:      ${r.riskScore}/100 ${r.riskLevel}`);
    console.log(`│  Threats:         ${r.threats?.length || 0}`);
    console.log(`│  Categories:      ${r.categoriesDetected}/${r.categoriesMonitored}`);
    console.log(`│  Duration:        ${(r.timeSpanMs / 1000).toFixed(1)}s`);
    console.log(`│  Coverage:        ${r.coveragePercent}%`);
    console.log('├──────────────────────────────────────────────────────┤');
    console.log(`│  Targets: ${targetSummary.totalTargets} total (${targetSummary.iframes} iframe, ${targetSummary.workers} worker)`);
    console.log(`│  Injected: ${targetSummary.injectedTargets}/${targetSummary.totalTargets} | Network: ${targetSummary.networkEnabledTargets}/${targetSummary.totalTargets}`);
    console.log('├──────────────────────────────────────────────────────┤');
    console.log(`│  Injection: L1=${injectionFlags.L1_addInitScript} L2=${injectionFlags.L2_automationCleanup} L3=${injectionFlags.L3_cdpSupplement}`);
    console.log(`│             L4=${injectionFlags.L4_perFrame} L5=${injectionFlags.L5_recursiveAutoAttach} L6=${injectionFlags.L6_workerPipeline}`);
    console.log(`│  Spoofing:  NONE (Ghost Protocol)`);
    console.log('└──────────────────────────────────────────────────────┘');

    // Cleanup
    try { if (cdpSession) await cdpSession.detach().catch(() => {}); } catch(e) {}

    await context.close();
    cleanupProfile(profileDir);
    profileDir = null;

    return reportResult;

  } catch(e) {
    console.error(`\n🔴 Scan failed: ${e.message}`);
    if (VERBOSE) console.error(e.stack);
    try { if (context) await context.close().catch(() => {}); } catch(ex) {}
    if (profileDir) cleanupProfile(profileDir);
    return null;
  }
}

// ── Main ──
async function main() {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║   🛡️  SENTINEL v4.6 — GHOST PROTOCOL FORENSIC CATCHER     ║');
  console.log('║   Recursive Coverage | Worker Pipeline | 1H5W Framework    ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');

  if (!targetUrl) targetUrl = await prompt('\n🔍 Enter URL to scan: ');
  if (!targetUrl) { console.log('❌ No URL provided.'); process.exit(1); }
  targetUrl = normalizeUrl(targetUrl);

  if (DUAL_MODE) {
    console.log('\n🔄 DUAL MODE: Running observe then stealth...\n');
    const observeResult = await runScan(targetUrl, { stealth: false });
    const stealthResult = await runScan(targetUrl, { stealth: true });
    if (observeResult && stealthResult) {
      const o = observeResult.reportJson, s = stealthResult.reportJson;
      console.log('\n╔═════════════════════════════════════╗');
      console.log('║  📊 DUAL MODE COMPARISON             ║');
      console.log('╠═════════════════════════════════════╣');
      console.log(`║  Observe: ${o.totalEvents} events, risk ${o.riskScore}/100, ${o.categoriesDetected}/${o.categoriesMonitored} cats`);
      console.log(`║  Stealth: ${s.totalEvents} events, risk ${s.riskScore}/100, ${s.categoriesDetected}/${s.categoriesMonitored} cats`);
      console.log(`║  Delta:   ${Math.abs(o.totalEvents - s.totalEvents)} events`);
      console.log(`║  Duration: O=${(o.timeSpanMs/1000).toFixed(1)}s S=${(s.timeSpanMs/1000).toFixed(1)}s`);
      console.log('╚═════════════════════════════════════╝');
    }
  } else {
    await runScan(targetUrl, { stealth: !OBSERVE_ONLY });
  }
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
