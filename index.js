#!/usr/bin/env node
/**
 * ╔═══════════════════════════════════════════════════════════╗
 * ║   🛡️  SENTINEL v4.5 — FULL CONVERSATION FORENSIC CATCHER  ║
 * ║   Pure CCTV Mode | Zero Spoofing | Bidirectional Capture   ║
 * ╚═══════════════════════════════════════════════════════════╝
 *
 * v4.5 PHILOSOPHY: We are a CCTV camera. We record everything.
 *   - We do NOT spoof anything (no fake UA, language, plugins, etc.)
 *   - We do NOT use playwright-extra or stealth plugins
 *   - We only remove automation markers (webdriver, __playwright)
 *   - We capture BOTH directions: what "maling" asks AND what browser answers
 *   - We capture ALL network traffic: requests AND responses with bodies
 *
 * Usage:
 *   node index.js <url>                     — Quick scan
 *   node index.js <url> --no-headless       — Show browser window
 *   node index.js <url> --timeout=45000     — Custom timeout
 *   node index.js <url> --dual-mode         — Run observe then stealth, compare
 *   node index.js <url> --observe           — No automation cleanup at all
 */

const { getExtraStealthScript } = require('./hooks/stealth-config');
const { getAntiDetectionScript } = require('./hooks/anti-detection-shield');
const { getInterceptorScript } = require('./hooks/api-interceptor');
const { generateReport } = require('./reporters/report-generator');
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

function normalizeUrl(input) {
  input = input.trim();
  if (!input.match(/^https?:\/\//i)) input = 'https://' + input;
  return input;
}

async function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer.trim()); }));
}

/**
 * Create a temporary persistent profile directory.
 * This gives us a "real" browser profile (not incognito) that gets
 * auto-deleted after the scan completes.
 */
function createTempProfile() {
  const tmpBase = path.join(os.tmpdir(), 'sentinel-profiles');
  if (!fs.existsSync(tmpBase)) fs.mkdirSync(tmpBase, { recursive: true });
  const profileDir = path.join(tmpBase, `sentinel_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);
  fs.mkdirSync(profileDir, { recursive: true });
  return profileDir;
}

/**
 * Delete a profile directory (cleanup after scan)
 */
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
 * CDP Supplement — for push telemetry and iframe auto-attach
 */
async function setupCDPSupplement(page) {
  try {
    const cdpSession = await page.context().newCDPSession(page);
    const pushEvents = [];

    try {
      await cdpSession.send('Runtime.addBinding', { name: '__SENTINEL_PUSH__' });
    } catch(e) {}

    cdpSession.on('Runtime.bindingCalled', (params) => {
      if (params.name === '__SENTINEL_PUSH__') {
        try {
          const data = JSON.parse(params.payload);
          if (data.events) pushEvents.push(...data.events);
        } catch(e) {}
      }
    });

    // Auto-attach to iframes/workers
    try {
      await cdpSession.send('Target.setAutoAttach', {
        autoAttach: true, waitForDebuggerOnStart: true, flatten: true
      });
    } catch(e) {}

    cdpSession.on('Target.attachedToTarget', async (event) => {
      try {
        if (event.targetInfo && ['iframe', 'worker', 'service_worker'].includes(event.targetInfo.type)) {
          try { await cdpSession.send('Runtime.runIfWaitingForDebugger', {}, event.sessionId); } catch(e) {}
        }
      } catch(e) {}
    });

    return { cdpSession, pushEvents };
  } catch(e) {
    return { cdpSession: null, pushEvents: [] };
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
 * Records the full "conversation" between maling and browser:
 *   - What the maling ASKS (requests with url, method, headers, body)
 *   - What the browser ANSWERS (responses with status, headers, body preview)
 */
function setupNetworkCapture(page) {
  const networkLog = [];

  // Capture outgoing requests
  page.on('request', (request) => {
    try {
      const url = request.url();
      // Skip data: URLs and very long URLs that are just noise
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
            // Only capture interesting headers
            const keep = {};
            for (const k of ['user-agent', 'referer', 'origin', 'content-type', 'cookie', 'accept', 'accept-language', 'sec-ch-ua', 'sec-ch-ua-platform', 'sec-ch-ua-mobile', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site']) {
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

  // Capture incoming responses
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
            for (const k of ['content-type', 'content-length', 'set-cookie', 'cache-control', 'access-control-allow-origin', 'x-powered-by', 'server']) {
              if (h[k]) keep[k] = h[k].slice(0, 300);
            }
            return keep;
          } catch(e) { return {}; }
        })()
      };

      // Try to capture response body preview (non-blocking)
      try {
        const ct = response.headers()['content-type'] || '';
        // Only capture text-based responses (JSON, HTML, JS, CSS, text)
        if (ct.match(/json|text|javascript|html|css|xml/i)) {
          const bodyText = await response.text().catch(() => null);
          if (bodyText) {
            entry.bodyPreview = bodyText.slice(0, 2000);
            entry.bodySize = bodyText.length;
          }
        } else {
          // Binary content — just record size
          const body = await response.body().catch(() => null);
          if (body) entry.bodySize = body.length;
        }
      } catch(e) {
        // Response body not available (e.g., streaming, redirects)
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
  console.log(`  ${label} MODE — Sentinel v4.5 Full Conversation Catcher`);
  console.log(`  Target: ${url}`);
  console.log(`  Timeout: ${TIMEOUT / 1000}s | Headless: ${HEADLESS}`);
  console.log(`  Spoofing: NONE | Profile: Temp (auto-cleanup)`);
  console.log(`${'═'.repeat(65)}\n`);

  let context, page, cdpData, networkLog;
  const injectionFlags = { L1_addInitScript: false, L2_automationCleanup: false, L3_cdpSupplement: false, L4_perFrame: false };

  try {
    // ══════════════════════════════════════
    //  STEP 1: LAUNCH BROWSER — Pure Playwright, no extras
    // ══════════════════════════════════════
    console.log('[1/7] Launching browser (pure Playwright, zero plugins)...');

    const { chromium } = require('playwright');

    const launchArgs = [
      '--disable-blink-features=AutomationControlled',
      '--no-first-run',
      '--no-default-browser-check',
    ];

    // Create temporary persistent profile (anti-incognito, auto-cleanup)
    profileDir = createTempProfile();
    console.log(`  → Temp profile: ${path.basename(profileDir)}`);

    context = await chromium.launchPersistentContext(profileDir, {
      headless: HEADLESS,
      args: launchArgs,
      ignoreDefaultArgs: ['--enable-automation'],
      // NO userAgent override — let browser report its real UA
      // NO locale override — let browser report its real locale
      // NO timezone override — let OS timezone be used
      viewport: { width: 1920, height: 1080 },
      permissions: [],
      colorScheme: 'light',
    });
    page = context.pages()[0] || await context.newPage();
    console.log('  ✅ Browser launched (persistent context, no spoofing)');

    // ══════════════════════════════════════
    //  STEP 2: INJECTION via addInitScript
    //  Order: shield → cleanup → interceptor
    //  Interceptor is UNCHANGED from v4.4.1 (proven: 1685 events)
    // ══════════════════════════════════════
    console.log('[2/7] Injecting monitoring hooks...');

    // Shield first
    await page.addInitScript(getAntiDetectionScript());

    // Automation cleanup (only if stealth mode — removes webdriver etc.)
    if (stealthEnabled) {
      await page.addInitScript(getExtraStealthScript());
      injectionFlags.L2_automationCleanup = true;
      console.log('  ✅ Automation marker cleanup injected (zero spoofing)');
    }

    // Interceptor — the proven 200+ hook engine from v4.4.1
    await page.addInitScript(getInterceptorScript({
      timeout: TIMEOUT,
      stealthEnabled: stealthEnabled,
      stackSampleRate: 10
    }));
    injectionFlags.L1_addInitScript = true;
    console.log('  ✅ API interceptor injected (37 categories, 200+ hooks)');

    // ══════════════════════════════════════
    //  STEP 3: CDP SUPPLEMENT + NETWORK CAPTURE
    // ══════════════════════════════════════
    console.log('[3/7] Setting up CDP + bidirectional network capture...');
    cdpData = await setupCDPSupplement(page);
    if (cdpData.cdpSession) {
      injectionFlags.L3_cdpSupplement = true;
      console.log('  ✅ CDP push telemetry + auto-attach active');
    }

    // Setup bidirectional network capture (the "conversation")
    networkLog = setupNetworkCapture(page);
    console.log('  ✅ Network conversation capture active (request ↔ response)');

    // Per-frame injection for late-attached frames
    page.on('frameattached', async (frame) => {
      try {
        await frame.evaluate(getAntiDetectionScript() + ';\n' +
          getInterceptorScript({ timeout: TIMEOUT, stealthEnabled }));
        injectionFlags.L4_perFrame = true;
      } catch(e) {}
    });

    // ══════════════════════════════════════
    //  STEP 4: NAVIGATE TO TARGET
    // ══════════════════════════════════════
    console.log('[4/7] Navigating to target...');
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });
    } catch(e) {
      await page.goto(url, { waitUntil: 'commit', timeout: TIMEOUT * 2 });
    }
    console.log(`  🌐 Page loaded: ${page.url()}`);

    // Diagnostic check
    try {
      const active = await page.evaluate(() => !!window.__SENTINEL_ACTIVE__);
      const bootOk = await page.evaluate(() => window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.bootOk : false);
      const shieldOk = await page.evaluate(() => !!window.__SENTINEL_SHIELD__);
      console.log(`  🔍 Diagnostic: ACTIVE=${active} | BOOT_OK=${bootOk} | SHIELD=${shieldOk}`);
      if (!active) {
        console.error('  🔴 CRITICAL: Injection failed! Emergency re-inject...');
        await page.evaluate(getAntiDetectionScript() + ';\n' +
          getInterceptorScript({ timeout: TIMEOUT, stealthEnabled }));
      }
    } catch(e) { console.warn('  ⚠️ Diagnostic check failed:', e.message); }

    // ══════════════════════════════════════
    //  STEP 5: OBSERVE ACTIVITY
    // ══════════════════════════════════════
    console.log('[5/7] Observing activity...');
    const observeTime = Math.max(TIMEOUT - 5000, 10000);

    await page.waitForTimeout(Math.floor(observeTime * 0.4));
    try { await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight / 2)); } catch(e) {}
    await page.waitForTimeout(2000);
    try { await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight)); } catch(e) {}
    await page.waitForTimeout(2000);
    try { await page.evaluate(() => window.scrollTo(0, 0)); } catch(e) {}

    const remaining = observeTime - Math.floor(observeTime * 0.4) - 4000;
    if (remaining > 0) await page.waitForTimeout(remaining);

    const midCount = await page.evaluate(() => window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.events.length : 0).catch(() => 0);
    console.log(`  📊 Events captured: ${midCount} (API) + ${networkLog.length} (network)`);

    // Adaptive wait
    if (midCount < 50) {
      await page.waitForTimeout(Math.min(TIMEOUT, 15000));
    }

    // ══════════════════════════════════════
    //  STEP 6: COLLECT DATA (anti-stuck + final flush)
    // ══════════════════════════════════════
    console.log('[6/7] Collecting forensic data...');

    // Final flush
    try {
      await page.evaluate(() => {
        if (typeof window.__SENTINEL_PUSH__ === 'function' && window.__SENTINEL_DATA__) {
          try {
            window.__SENTINEL_PUSH__(JSON.stringify({
              type: 'final_flush', frameId: window.__SENTINEL_DATA__.frameId || '',
              events: window.__SENTINEL_DATA__.events.slice(-100)
            }));
          } catch(e) {}
        }
      });
      await page.waitForTimeout(500);
    } catch(e) {}

    // Collect from main frame (with timeout)
    let sentinelData;
    try {
      sentinelData = await evalWithTimeout(page, () => {
        if (window.__SENTINEL_DATA__) {
          return {
            events: window.__SENTINEL_DATA__.events || [],
            bootOk: window.__SENTINEL_DATA__.bootOk || false,
            frameId: window.__SENTINEL_DATA__.frameId || ''
          };
        }
        if (typeof window.__SENTINEL_FLUSH__ === 'function') {
          var flushed = JSON.parse(window.__SENTINEL_FLUSH__());
          return { events: flushed.events || [], bootOk: true, frameId: 'flushed' };
        }
        return { events: [], bootOk: false, frameId: 'none' };
      }, 8000);
    } catch(e) {
      console.warn(`  ⚠️ Main frame timeout: ${e.message}`);
      sentinelData = { events: [], bootOk: false, frameId: 'error' };
    }
    console.log(`  📦 Main frame: ${sentinelData.events.length} events`);

    // Collect from sub-frames (parallel + timeout)
    const frames = page.frames();
    const framePromises = [];
    const frameInfoList = [];

    for (let i = 0; i < frames.length; i++) {
      const f = frames[i];
      const fUrl = f.url() || '';
      let fOrigin = null;
      try { if (fUrl.startsWith('http')) fOrigin = new URL(fUrl).origin; } catch(e) {}
      frameInfoList.push({ type: 'frame', url: fUrl, origin: fOrigin, name: f.name() || '' });

      if (i === 0) continue;
      if (!fUrl || fUrl === 'about:blank' || !fUrl.startsWith('http')) continue;

      framePromises.push(
        evalWithTimeout(f, () => {
          if (window.__SENTINEL_DATA__) return { events: window.__SENTINEL_DATA__.events || [], bootOk: window.__SENTINEL_DATA__.bootOk || false };
          if (typeof window.__SENTINEL_FLUSH__ === 'function') { var fl = JSON.parse(window.__SENTINEL_FLUSH__()); return { events: fl.events || [], bootOk: true }; }
          return null;
        }, 3000).catch(() => null)
      );
    }

    if (framePromises.length > 0) {
      const results = await Promise.allSettled(framePromises);
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value && r.value.events && r.value.events.length > 0) {
          sentinelData.events = sentinelData.events.concat(r.value.events);
        }
      }
    }
    console.log(`  📦 Frames: ${frames.length} total, ${framePromises.length} sub-frames checked`);

    // Merge CDP push events
    if (cdpData && cdpData.pushEvents.length > 0) {
      const existingTs = new Set(sentinelData.events.map(e => e.ts + ':' + e.api));
      for (const pe of cdpData.pushEvents) {
        if (!existingTs.has(pe.ts + ':' + pe.api)) sentinelData.events.push(pe);
      }
    }

    console.log(`  📦 Grand total: ${sentinelData.events.length} API events + ${networkLog.length} network events`);

    // Build context map
    const pageCtxMap = await page.evaluate(() => window.__SENTINEL_CONTEXT_MAP__ || []).catch(() => []);
    const fullContextMap = [...(pageCtxMap || []), ...frameInfoList];

    // ══════════════════════════════════════
    //  STEP 7: GENERATE REPORT
    // ══════════════════════════════════════
    console.log('[7/7] Generating forensic report...');

    const reportResult = generateReport(sentinelData, fullContextMap, url, {
      stealthEnabled,
      prefix: `sentinel_${stealthEnabled ? 'stealth' : 'observe'}_${Date.now()}`,
      injectionFlags,
      frameInfo: frameInfoList,
      networkLog: networkLog  // NEW in v4.5: pass network conversation
    });

    const r = reportResult.reportJson;

    console.log(`\nReports saved:`);
    console.log(`   JSON: ${reportResult.jsonPath}`);
    console.log(`   HTML: ${reportResult.htmlPath}`);
    console.log(`   CTX:  ${reportResult.ctxPath}`);

    console.log('');
    console.log('┌──────────────────────────────────────────────────────┐');
    console.log(`│  🛡️ SENTINEL v4.5 — FULL CONVERSATION FORENSIC SUMMARY  │`);
    console.log('├──────────────────────────────────────────────────────┤');
    console.log(`│  API Events:      ${String(r.totalEvents).padEnd(8)}`);
    console.log(`│  Network Events:  ${String(networkLog.length).padEnd(8)} (${networkLog.filter(n=>n.dir==='request').length} req / ${networkLog.filter(n=>n.dir==='response').length} resp)`);
    console.log(`│  Risk Score:      ${r.riskScore}/100 ${r.riskLevel}`);
    console.log(`│  Threats:         ${r.threats?.length || 0}`);
    console.log(`│  Categories:      ${r.categoriesDetected}/${r.categoriesMonitored}`);
    console.log(`│  Duration:        ${(r.timeSpanMs / 1000).toFixed(1)}s`);
    console.log(`│  Coverage:        ${r.coveragePercent}%`);
    console.log('├──────────────────────────────────────────────────────┤');
    console.log(`│  Injection: L1=${injectionFlags.L1_addInitScript} L2=${injectionFlags.L2_automationCleanup} L3=${injectionFlags.L3_cdpSupplement} L4=${injectionFlags.L4_perFrame}`);
    console.log(`│  Spoofing:  NONE (pure CCTV mode)`);
    console.log('└──────────────────────────────────────────────────────┘');

    // Cleanup
    try { if (cdpData?.cdpSession) await cdpData.cdpSession.detach().catch(() => {}); } catch(e) {}

    await context.close();
    cleanupProfile(profileDir);
    profileDir = null;

    return reportResult;

  } catch(e) {
    console.error(`\n🔴 Scan failed: ${e.message}`);
    try { if (context) await context.close().catch(() => {}); } catch(ex) {}
    if (profileDir) cleanupProfile(profileDir);
    return null;
  }
}

// ── Main ──
async function main() {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║   🛡️  SENTINEL v4.5 — FULL CONVERSATION FORENSIC CATCHER  ║');
  console.log('║   Pure CCTV Mode | Zero Spoofing | 1H5W Framework          ║');
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
