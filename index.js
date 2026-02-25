#!/usr/bin/env node
/**
 * ╔═══════════════════════════════════════════════════════════════╗
 * ║   🛡️  SENTINEL v4.6.2 — GHOST PROTOCOL FORENSIC CATCHER       ║
 * ║   8-Layer Architecture | 37 Categories | 1H5W | Zero Spoofing ║
 * ╠═══════════════════════════════════════════════════════════════╣
 * ║   v4.6.2 FIXES over v4.6.1:                                   ║
 * ║   1. PERSISTENT CONTEXT always ON + cleanup after scan        ║
 * ║   2. GPU hardware accel forced (--use-gl=desktop) no SwiftSh  ║
 * ║   3. No unnecessary polyfills (chrome.csi/loadTimes removed)  ║
 * ║   4. Header shows Persistent: true correctly                  ║
 * ║   5. Locale auto-detect from system                           ║
 * ║   6. Stealth config minimal — only remove real Playwright     ║
 * ║      artifacts, do NOT polyfill chrome.runtime/plugins/etc    ║
 * ║   7. Network log uses paired request/response structure       ║
 * ║   8. No userAgent override — let Chromium be itself           ║
 * ╚═══════════════════════════════════════════════════════════════╝
 *
 * Usage:
 *   node index.js <url>                     — Quick scan
 *   node index.js <url> --no-headless       — Show browser window
 *   node index.js <url> --timeout=45000     — Custom timeout
 *   node index.js <url> --dual-mode         — Run observe then stealth
 *   node index.js <url> --observe           — No automation cleanup
 *   node index.js <url> --verbose           — Debug info
 *   node index.js <url> --locale=id-ID      — Override locale
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

// ── Parse CLI ──
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
const LOCALE = flags.locale || Intl.DateTimeFormat().resolvedOptions().locale || 'en-US';
const TIMEZONE = flags.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'Asia/Jakarta';

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
      if (VERBOSE) console.log(`  🗑️  Profile cleaned: ${path.basename(profileDir)}`);
    }
  } catch(e) {
    if (VERBOSE) console.warn(`  ⚠️  Profile cleanup failed: ${e.message}`);
  }
}

async function evalWithTimeout(target, fn, ms) {
  ms = ms || 5000;
  return Promise.race([
    target.evaluate(fn),
    new Promise((_, rej) => setTimeout(() => rej(new Error('EVAL_TIMEOUT')), ms))
  ]);
}

/**
 * v4.6.2: Network capture returns structured object compatible with report-generator
 */
function setupNetworkCapture(page) {
  const requests = [];
  const responses = [];
  const pairs = [];
  const pendingRequests = new Map();

  page.on('request', (request) => {
    try {
      const url = request.url();
      if (url.startsWith('data:')) return;
      const entry = {
        ts: Date.now(),
        method: request.method(),
        url: url.slice(0, 500),
        resourceType: request.resourceType(),
        requestHeaders: (() => {
          try {
            const h = request.headers();
            const keep = {};
            for (const k of ['user-agent', 'referer', 'origin', 'content-type',
              'sec-ch-ua', 'sec-ch-ua-platform', 'sec-ch-ua-mobile']) {
              if (h[k]) keep[k] = h[k].slice(0, 300);
            }
            return keep;
          } catch(e) { return {}; }
        })(),
        postData: (() => {
          try { return request.postData() ? request.postData().slice(0, 1000) : null; } catch(e) { return null; }
        })()
      };
      requests.push(entry);
      pendingRequests.set(url, entry);
    } catch(e) {}
  });

  page.on('response', async (response) => {
    try {
      const url = response.url();
      if (url.startsWith('data:')) return;
      const rh = (() => {
        try {
          const h = response.headers();
          const keep = {};
          for (const k of ['content-type', 'content-length', 'cache-control',
            'access-control-allow-origin', 'server']) {
            if (h[k]) keep[k] = h[k].slice(0, 300);
          }
          return keep;
        } catch(e) { return {}; }
      })();
      let bodyText = null, bodySize = 0;
      try {
        const ct = rh['content-type'] || '';
        if (ct.match(/json|text|javascript|html|css|xml/i)) {
          bodyText = await response.text().catch(() => null);
          if (bodyText) bodySize = bodyText.length;
        } else {
          const body = await response.body().catch(() => null);
          if (body) bodySize = body.length;
        }
      } catch(e) {}
      responses.push({ ts: Date.now(), status: response.status(), url: url.slice(0, 500) });

      const reqEntry = pendingRequests.get(url);
      if (reqEntry) {
        pairs.push({
          url: url.slice(0, 500),
          method: reqEntry.method,
          resourceType: reqEntry.resourceType,
          requestHeaders: reqEntry.requestHeaders,
          postData: reqEntry.postData,
          responseStatus: response.status(),
          responseHeaders: rh,
          responseBody: bodyText ? bodyText.slice(0, 2000) : null,
          responseSize: bodySize,
          ts: reqEntry.ts
        });
        pendingRequests.delete(url);
      }
    } catch(e) {}
  });

  return { requests: requests.length, responses: responses.length, pairs,
    get requestCount() { return requests.length; },
    get responseCount() { return responses.length; }
  };
}

const OUTPUT_DIR = path.join(__dirname, 'output');

async function runScan(url, options = {}) {
  const stealthEnabled = options.stealth !== false;
  const label = stealthEnabled ? '🥷 STEALTH' : '👁️ OBSERVE';
  let profileDir = null;

  console.log(`\n${'═'.repeat(65)}`);
  console.log(`  ${label} MODE — Sentinel v4.6.2 Ghost Protocol`);
  console.log(`  Target: ${url}`);
  console.log(`  Timeout: ${TIMEOUT / 1000}s | Headless: ${HEADLESS}`);
  console.log(`  Locale: ${LOCALE} | TZ: ${TIMEZONE} | Persistent: true`);
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
    // ══════ STEP 1: LAUNCH (PERSISTENT + GPU) ══════
    console.log('[1/8] Launching browser...');
    const { chromium } = require('playwright');

    /**
     * v4.6.2 KEY FIXES:
     * --use-gl=desktop → Forces real GPU instead of SwiftShader
     *   SwiftShader = "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device..." = BOT SIGNAL
     *   Real GPU    = "ANGLE (NVIDIA, GeForce..." or "ANGLE (Intel, HD..." = HUMAN
     * --enable-gpu → Ensures GPU process starts even in some CI environments
     * ignoreDefaultArgs: ['--enable-automation'] → Removes Chrome automation bar
     * NO userAgent override → UA matches sec-ch-ua naturally
     */
    const launchArgs = [
      '--disable-blink-features=AutomationControlled',
      '--use-gl=desktop',
      '--enable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding',
      '--disable-background-timer-throttling',
    ];

    profileDir = createTempProfile();
    context = await chromium.launchPersistentContext(profileDir, {
      headless: HEADLESS,
      args: launchArgs,
      ignoreDefaultArgs: ['--enable-automation'],
      viewport: { width: 1920, height: 1080 },
      locale: LOCALE,
      timezoneId: TIMEZONE,
      permissions: [],
      colorScheme: 'light',
      // v4.6.2: NO userAgent override. Chromium's native UA = consistent with sec-ch-ua
    });
    page = context.pages()[0] || await context.newPage();
    console.log('  ✅ Browser launched');

    // ══════ STEP 2: INJECT HOOKS ══════
    console.log('[2/8] Injecting monitoring scripts...');
    const shieldScript = getAntiDetectionScript();
    const stealthScript = stealthEnabled ? getExtraStealthScript() : '';
    const interceptorScript = getInterceptorScript({
      timeout: TIMEOUT,
      stealthEnabled: stealthEnabled,
      stackSampleRate: 10
    });

    await page.addInitScript(shieldScript);
    if (stealthEnabled) {
      await page.addInitScript(stealthScript);
      injectionFlags.L2_automationCleanup = true;
      console.log('  ✅ Anti-detection shield + stealth patches');
    } else {
      console.log('  ✅ Anti-detection shield (observe mode)');
    }
    await page.addInitScript(interceptorScript);
    injectionFlags.L1_addInitScript = true;
    console.log('  ✅ API interceptor (37 categories, 200+ hooks, push telemetry)');

    // ══════ STEP 3: CDP + TARGET GRAPH ══════
    console.log('[3/8] Setting up CDP supplement...');
    cdpSession = await page.context().newCDPSession(page);
    targetGraph = new TargetGraph({
      verbose: VERBOSE,
      injectionScript: shieldScript + ';\n' + stealthScript + ';\n' + interceptorScript,
      shieldScript: shieldScript,
      stealthScript: stealthScript
    });
    await targetGraph.initialize(cdpSession);
    injectionFlags.L3_cdpSupplement = true;
    injectionFlags.L5_recursiveAutoAttach = true;
    networkLog = setupNetworkCapture(page);
    console.log('  ✅ CDP telemetry + auto-attach + network monitor active');

    // ══════ STEP 4: NAVIGATE ══════
    console.log('[4/8] Navigating to target...');
    const navStart = Date.now();
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });
    } catch(e) {
      if (e.message.includes('net::')) throw e;
    }
    console.log(`  🌐 Page loaded in ${((Date.now()-navStart)/1000).toFixed(1)}s: ${page.url()}`);

    // Per-frame injection
    const existingFrames = page.frames();
    for (let i = 1; i < existingFrames.length; i++) {
      const fUrl = existingFrames[i].url() || '';
      if (fUrl.startsWith('http')) {
        try {
          await existingFrames[i].evaluate(shieldScript + ';\n' + (stealthEnabled ? stealthScript + ';\n' : '') + interceptorScript);
          injectionFlags.L4_perFrame = true;
        } catch(e) {}
      }
    }

    // Diagnostic
    try {
      const active = await page.evaluate(() => !!(window.__SENTINEL_DATA__ || Object.getOwnPropertyNames(window).some(k => k.indexOf('_s') === 0))).catch(() => false);
      const bootOk = await page.evaluate(() => window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.bootOk : false).catch(() => false);
      const shieldOk = await page.evaluate(() => !!window.__SENTINEL_SHIELD__).catch(() => false);
      console.log(`  🔍 Diagnostic: ACTIVE=${active} | BOOT=${bootOk} | SHIELD=${shieldOk}`);
      if (!active) {
        console.error('  🔴 Emergency re-inject...');
        await page.evaluate(shieldScript + ';\n' + (stealthEnabled ? stealthScript + ';\n' : '') + interceptorScript);
      }
    } catch(e) {}

    // ══════ STEP 5: OBSERVE ══════
    console.log('[5/8] Monitoring fingerprinting activity...');
    const observeTime = Math.max(TIMEOUT - 5000, 10000);
    await page.waitForTimeout(Math.floor(observeTime * 0.35));
    try { await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight / 3)); } catch(e) {}
    await page.waitForTimeout(1500);
    try { await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight * 0.6)); } catch(e) {}
    await page.waitForTimeout(1500);
    try { await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight)); } catch(e) {}
    await page.waitForTimeout(1500);
    try { await page.evaluate(() => window.scrollTo(0, 0)); } catch(e) {}
    const rem = observeTime - Math.floor(observeTime * 0.35) - 4500;
    if (rem > 0) await page.waitForTimeout(rem);

    const midCount = await page.evaluate(() => {
      try { return window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.events.length : 0; } catch(e) { return 0; }
    }).catch(() => 0);
    console.log(`  📊 Events after ${(observeTime/1000).toFixed(0)}s wait: ${midCount}`);
    if (midCount < 50) await page.waitForTimeout(Math.min(TIMEOUT, 15000));

    // ══════ STEP 6: WORKER EVENTS ══════
    console.log('[6/8] Collecting worker events...');
    let workerEvents = [];
    try {
      workerEvents = await targetGraph.collectWorkerEvents(cdpSession);
      if (workerEvents.length > 0) injectionFlags.L6_workerPipeline = true;
    } catch(e) {}
    console.log(`  📦 Worker events: ${workerEvents.length}`);

    // ══════ STEP 7: COLLECT FORENSIC DATA ══════
    console.log('[7/8] Collecting forensic data...');

    // Final flush
    try {
      await page.evaluate(() => {
        var pushFn = typeof window.__SENTINEL_PUSH__ === 'function' ? window.__SENTINEL_PUSH__ :
                     typeof window.__s46push__ === 'function' ? window.__s46push__ : null;
        if (pushFn && window.__SENTINEL_DATA__) {
          try { pushFn(JSON.stringify({ type:'final_flush', frameId: window.__SENTINEL_DATA__.frameId||'', events: window.__SENTINEL_DATA__.events.slice(-100) })); } catch(e) {}
        }
      });
      await page.waitForTimeout(500);
    } catch(e) {}

    let sentinelData;
    try {
      sentinelData = await evalWithTimeout(page, () => {
        if (window.__SENTINEL_DATA__) return { events: window.__SENTINEL_DATA__.events||[], bootOk: window.__SENTINEL_DATA__.bootOk||false, frameId: window.__SENTINEL_DATA__.frameId||'', dedupCount: window.__SENTINEL_DATA__.dedupCount||0 };
        if (typeof window.__SENTINEL_FLUSH__ === 'function') { var fl=JSON.parse(window.__SENTINEL_FLUSH__()); return { events:fl.events||[], bootOk:true, frameId:'flushed', dedupCount:0 }; }
        return { events:[], bootOk:false, frameId:'none', dedupCount:0 };
      }, 8000);
    } catch(e) {
      console.warn(`  ⚠️ Main frame timeout: ${e.message}`);
      sentinelData = { events:[], bootOk:false, frameId:'error', dedupCount:0 };
    }
    console.log(`  📦 Main frame: ${sentinelData.events.length} events (boot=${sentinelData.bootOk})`);

    // Sub-frames
    const frames = page.frames();
    const framePromises = [];
    const frameInfoList = [];
    for (let i = 0; i < frames.length; i++) {
      const f = frames[i];
      const fUrl = f.url() || '';
      let fOrigin = null;
      try { if (fUrl.startsWith('http')) fOrigin = new URL(fUrl).origin; } catch(e) {}
      frameInfoList.push({ type:'frame', url:fUrl, origin:fOrigin, name:f.name()||'', index:i });
      if (i===0) continue;
      const shouldCollect = (() => {
        if (fUrl.startsWith('http')) return true;
        if (fUrl==='about:srcdoc') return true;
        if (fUrl==='about:blank'||!fUrl) { if(f.name()) return true; try { if(f.parentFrame()===page.mainFrame()) return true; } catch(e) {} return false; }
        return false;
      })();
      if (!shouldCollect) continue;
      framePromises.push(evalWithTimeout(f, () => {
        if (window.__SENTINEL_DATA__) return { events:window.__SENTINEL_DATA__.events||[], bootOk:window.__SENTINEL_DATA__.bootOk||false, frameId:window.__SENTINEL_DATA__.frameId||'' };
        if (typeof window.__SENTINEL_FLUSH__==='function') { var fl=JSON.parse(window.__SENTINEL_FLUSH__()); return { events:fl.events||[], bootOk:true, frameId:'flushed' }; }
        return null;
      }, 3000).catch(() => null));
    }

    let subFrameEvents = 0;
    if (framePromises.length > 0) {
      const results = await Promise.allSettled(framePromises);
      for (const r of results) {
        if (r.status==='fulfilled' && r.value && r.value.events && r.value.events.length>0) {
          sentinelData.events = sentinelData.events.concat(r.value.events);
          subFrameEvents += r.value.events.length;
        }
      }
    }

    // Merge CDP push
    if (targetGraph.events.length > 0) {
      const existingTs = new Set(sentinelData.events.map(e => e.ts+':'+e.api));
      let merged = 0;
      for (const pe of targetGraph.events) {
        if (!existingTs.has(pe.ts+':'+pe.api)) { sentinelData.events.push(pe); merged++; }
      }
      console.log(`  📡 CDP push events: ${merged} new`);
    }

    // Merge workers
    if (workerEvents.length > 0) {
      for (const we of workerEvents) {
        sentinelData.events.push({ ts:we.ts, cat:'worker', api:we.api, detail:JSON.stringify({url:we.url,type:we.workerType}).slice(0,500), risk:'high', dir:'call', origin:we.workerUrl||'worker', frame:'worker:'+(we.targetId||'').slice(0,8) });
      }
    }

    const pageCtxMap = await page.evaluate(() => window.__SENTINEL_CONTEXT_MAP__||[]).catch(() => []);
    const fullContextMap = [...(pageCtxMap||[]), ...frameInfoList];
    const targetInventory = targetGraph.getInventory();
    const targetSummary = targetGraph.getSummary();

    // ══════ STEP 8: REPORT ══════
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
    console.log('┌─────────────────────────────────────────────────┐');
    console.log(`│  🛡️ SENTINEL v4.6.2 FORENSIC SUMMARY             │`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  Mode:       ${stealthEnabled?'STEALTH':'OBSERVE'}`);
    console.log(`│  Events:     ${String(r.totalEvents).padEnd(8)} (from ${frameInfoList.length} frames)`);
    console.log(`│  Risk Score: ${r.riskScore}/100 ${r.riskLevel}`);
    console.log(`│  Threats:    ${r.threats?.length||0}`);
    console.log(`│  Categories: ${r.categoriesDetected}/${r.categoriesMonitored}`);
    console.log(`│  Coverage:   ${r.coveragePercent}%`);
    console.log(`│  Duration:   ${(r.timeSpanMs/1000).toFixed(1)}s`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  Injection Layers:`);
    console.log(`│    L1 addInitScript:    ${injectionFlags.L1_addInitScript}`);
    console.log(`│    L2 automationCleanup:${injectionFlags.L2_automationCleanup}`);
    console.log(`│    L3 CDP supplement:   ${injectionFlags.L3_cdpSupplement}`);
    console.log(`│    L4 per-frame:        ${injectionFlags.L4_perFrame}`);
    console.log(`│    L5 recursive attach: ${injectionFlags.L5_recursiveAutoAttach}`);
    console.log(`│    L6 worker pipeline:  ${injectionFlags.L6_workerPipeline}`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  Persistent: true | GPU: desktop | Spoofing: NONE`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  JSON: ${reportResult.jsonPath}`);
    console.log(`│  HTML: ${reportResult.htmlPath}`);
    console.log('└─────────────────────────────────────────────────┘');

    try { if (cdpSession) await cdpSession.detach().catch(()=>{}); } catch(e) {}
    await context.close();
    cleanupProfile(profileDir);
    profileDir = null;
    return reportResult;

  } catch(e) {
    console.error(`\n🔴 Scan failed: ${e.message}`);
    if (VERBOSE) console.error(e.stack);
    try { if (context) await context.close().catch(()=>{}); } catch(ex) {}
    if (profileDir) cleanupProfile(profileDir);
    return null;
  }
}

async function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════════╗');
  console.log('║   🛡️  SENTINEL v4.6.2 — GHOST PROTOCOL FORENSIC CATCHER         ║');
  console.log('║   8-Layer Architecture | 37 Categories | 1H5W | Zero Spoofing   ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝');

  if (!targetUrl) targetUrl = await prompt('\n🔍 Enter URL to scan: ');
  if (!targetUrl) { console.log('❌ No URL provided.'); process.exit(1); }
  targetUrl = normalizeUrl(targetUrl);

  if (DUAL_MODE) {
    console.log('\n🔄 DUAL MODE: Running both observe and stealth scans...\n');
    const observeResult = await runScan(targetUrl, { stealth: false });
    const stealthResult = await runScan(targetUrl, { stealth: true });
    if (observeResult && stealthResult) {
      const o = observeResult.reportJson, s = stealthResult.reportJson;
      console.log('\n╔═══════════════════════════════════╗');
      console.log('║  📊 DUAL MODE COMPARISON           ║');
      console.log('╠═══════════════════════════════════╣');
      console.log(`║  Observe: ${o.totalEvents} events, risk ${o.riskScore}/100`);
      console.log(`║  Stealth: ${s.totalEvents} events, risk ${s.riskScore}/100`);
      console.log(`║  Delta:   ${Math.abs(o.totalEvents - s.totalEvents)} events`);
      console.log('╚═══════════════════════════════════╝');
    }
  } else {
    await runScan(targetUrl, { stealth: !OBSERVE_ONLY });
  }
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
