#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║   SENTINEL v4.4 — ZERO BLIND SPOT FORENSIC CATCHER      ║
 * ║   7-Layer Architecture | 37 Categories | 1H5W Framework  ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * CRITICAL FIXES from v4.3 (0 events → full capture):
 *
 *   BUG #1 [FATAL]: v4.3 anti-detection-shield exported a FUNCTION reference.
 *     buildInjectionPayload() stringified it for CDP injection, but the 
 *     resulting IIFE created window.__sentinelShield__ in wrong execution
 *     context. v4.4 returns a TEMPLATE STRING (like v4.1) injected via
 *     addInitScript, which runs reliably in MAIN world.
 *
 *   BUG #2 [FATAL]: v4.3 used CDP as PRIMARY with addInitScript as fallback
 *     ONLY when CDP threw an error. CDP never throws (it "succeeds" silently)
 *     but scripts injected via CDP with runImmediately:false don't execute
 *     before page scripts. v4.4 uses addInitScript as PRIMARY (proven v3/v4.1
 *     approach) and CDP as SUPPLEMENT for push telemetry + iframe monitoring.
 *
 *   BUG #3 [FATAL]: v4.3 set runImmediately:false for CDP injection.
 *     This was intended to fix v4.2's crash but caused hooks to wait for
 *     next navigation, missing the initial page load entirely.
 *
 *   BUG #4: v4.3 removed playwright-extra + puppeteer-extra-plugin-stealth
 *     from stealth mode, using only custom scripts that were never injected
 *     (because of BUG #2). v4.4 restores the stealth plugin.
 *
 *   BUG #5: v4.3 hardcoded timezoneId: 'America/New_York' instead of
 *     'Asia/Jakarta'. This caused geo/locale inconsistency detected as bot.
 *
 *   BUG #6: v4.3 CDP Target.setAutoAttach used waitForDebuggerOnStart:false,
 *     so iframes started executing before injection. v4.4 sets it to true
 *     and properly resumes targets after injection.
 *
 * ARCHITECTURE v4.4:
 *   Layer 1: addInitScript PRIMARY injection (proven v3/v4.1 method)
 *   Layer 2: Anti-Detection Shield (WeakMap descriptor cache from v4.3)
 *   Layer 3: API Interceptor (200+ hooks, 37 categories, 1H5W)
 *   Layer 4: Stealth Config (playwright-extra + custom patches)
 *   Layer 5: CDP Supplemental (push telemetry + iframe auto-attach)
 *   Layer 6: Correlation Engine (burst/slow-probe/attribution)
 *   Layer 7: Signature DB + Report Generator (JSON + HTML + 1H5W)
 *
 * INJECTION STRATEGY (belt-and-suspenders):
 *   addInitScript → ALWAYS used (primary, runs before ANY page script)
 *   CDP → SUPPLEMENT only (push telemetry binding + cross-origin iframe inject)
 *   Per-frame → evaluate() fallback for late-attached frames
 *
 * Usage:
 *   node index.js                        — Interactive mode
 *   node index.js <url>                  — Quick scan (stealth default)
 *   node index.js <url> --stealth        — Stealth mode (default)
 *   node index.js <url> --observe        — Observe mode (no stealth)
 *   node index.js <url> --dual-mode      — Run BOTH modes & compare
 *   node index.js <url> --timeout=45000  — Custom timeout (ms)
 *   node index.js <url> --headless       — Headless mode
 *   node index.js <url> --no-headless    — Show browser window
 *   node index.js <url> --locale=id      — Set locale (default: id)
 */

const { createStealthPlugin, getExtraStealthScript } = require('./hooks/stealth-config');
const { getAntiDetectionScript } = require('./hooks/anti-detection-shield');
const { getInterceptorScript } = require('./hooks/api-interceptor');
const { generateReport } = require('./reporters/report-generator');
const readline = require('readline');
const path = require('path');

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
const MAX_TIMEOUT = parseInt(flags['max-timeout']) || 120000;
const HEADLESS = flags['no-headless'] ? false : (flags.headless === true || flags.headless === 'true' || !flags.headless);
const DUAL_MODE = flags['dual-mode'] === true;
const STEALTH_MODE = flags.observe ? false : true; // stealth is default
const LOCALE = flags.locale || 'id';
const TIMEZONE = flags.timezone || 'Asia/Jakarta';
const OUTPUT_DIR = flags.output || path.join(__dirname, 'output');

function normalizeUrl(input) {
  input = input.trim();
  if (!input.match(/^https?:\/\//i)) {
    input = 'https://' + input;
  }
  return input;
}

async function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * Setup CDP session for SUPPLEMENTAL purposes only.
 * NOT used for script injection (addInitScript handles that).
 * Provides:
 *   1. Runtime.addBinding for push-based telemetry
 *   2. Target.setAutoAttach for cross-origin iframe monitoring
 */
async function setupCDPSupplement(page, scripts) {
  try {
    const cdpSession = await page.context().newCDPSession(page);

    // Push telemetry binding
    await cdpSession.send('Runtime.enable');
    try {
      await cdpSession.send('Runtime.addBinding', { name: '__SENTINEL_PUSH__' });
    } catch(e) { /* binding may already exist */ }

    const pushEvents = [];
    cdpSession.on('Runtime.bindingCalled', (params) => {
      if (params.name === '__SENTINEL_PUSH__') {
        try {
          const data = JSON.parse(params.payload);
          if (data.type === 'event_batch' && Array.isArray(data.events)) {
            pushEvents.push(...data.events);
          }
        } catch(e) {}
      }
    });

    // Auto-attach to cross-origin iframes + workers
    const attachedTargets = [];
    try {
      await cdpSession.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: true,  // FIXED: was false in v4.3
        flatten: true
      });

      cdpSession.on('Target.attachedToTarget', async (params) => {
        const sessionId = params.sessionId;
        const targetInfo = params.targetInfo;
        attachedTargets.push({
          targetId: targetInfo.targetId,
          type: targetInfo.type,
          url: targetInfo.url
        });

        // Try to inject into attached target via CDP
        if (targetInfo.type === 'iframe' || targetInfo.type === 'page') {
          for (const script of scripts) {
            try {
              await cdpSession.send('Page.addScriptToEvaluateOnNewDocument', {
                source: script,
                runImmediately: true  // FIXED: for already-attached targets, run immediately
              }, sessionId);
            } catch(e) {}
          }
        }

        // Resume the target (was paused by waitForDebuggerOnStart)
        try {
          await cdpSession.send('Runtime.runIfWaitingForDebugger', {}, sessionId);
        } catch(e) {}
      });
    } catch(e) {
      // Not critical — iframe monitoring is best-effort
    }

    return { cdpSession, pushEvents, attachedTargets };
  } catch(err) {
    console.warn('⚠️  CDP supplement setup warning:', err.message);
    return null;
  }
}

/**
 * Adaptive timeout — extends observation if events are still flowing
 */
function AdaptiveTimeout(baseMs, maxMs) {
  this.baseMs = baseMs;
  this.maxMs = maxMs;
  this.lastEventCount = 0;
  this.extensions = 0;
  this.maxExtensions = 3;
  this.extensionMs = 15000;
  this.extended = false;
  this.finalTimeout = baseMs;
}

AdaptiveTimeout.prototype.checkAndExtend = function(currentEventCount) {
  if (this.extensions >= this.maxExtensions) return false;
  if (currentEventCount > this.lastEventCount + 20) {
    this.extensions++;
    this.finalTimeout = Math.min(this.finalTimeout + this.extensionMs, this.maxMs);
    this.lastEventCount = currentEventCount;
    this.extended = true;
    return true;
  }
  return false;
};

// ═══════════════════════════════════════════
//  MAIN SCAN FUNCTION
// ═══════════════════════════════════════════
async function runScan(url, options = {}) {
  const stealthEnabled = options.stealth !== false;
  const label = stealthEnabled ? '🥷 STEALTH' : '👁️ OBSERVE';

  console.log(`\n${'═'.repeat(65)}`);
  console.log(`  ${label} MODE — Sentinel v4.4 Zero Blind Spot`);
  console.log(`  Target: ${url}`);
  console.log(`  Timeout: ${TIMEOUT / 1000}s (adaptive up to ${MAX_TIMEOUT / 1000}s)`);
  console.log(`  Headless: ${HEADLESS} | Locale: ${LOCALE} | TZ: ${TIMEZONE}`);
  console.log(`${'═'.repeat(65)}\n`);

  let browser, page, cdpResult = null;
  const injectionFlags = { L1_addInitScript: false, L2_stealthPlugin: false, L3_cdpSupplement: false, L4_perFrame: false };

  try {
    // ══════════════════════════════════════
    //  STEP 1: LAUNCH BROWSER
    // ══════════════════════════════════════
    if (stealthEnabled) {
      // STEALTH MODE: use playwright-extra with stealth plugin
      let chromiumLauncher;
      try {
        const playwrightExtra = require('playwright-extra');
        chromiumLauncher = playwrightExtra.chromium;
        const stealthPlugin = createStealthPlugin();
        if (stealthPlugin) {
          chromiumLauncher.use(stealthPlugin);
          injectionFlags.L2_stealthPlugin = true;
          console.log('✅ Stealth plugin loaded (puppeteer-extra-plugin-stealth)');
        }
      } catch(e) {
        console.warn('⚠️  playwright-extra not available, using plain playwright');
        chromiumLauncher = require('playwright').chromium;
      }

      browser = await chromiumLauncher.launch({
        headless: HEADLESS,
        args: [
          '--disable-blink-features=AutomationControlled',
          '--disable-features=IsolateOrigins,site-per-process',
          '--disable-web-security',
          '--no-first-run',
          '--no-default-browser-check',
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage'
        ]
      });
    } else {
      // OBSERVE MODE: plain playwright
      const { chromium } = require('playwright');
      browser = await chromium.launch({
        headless: HEADLESS,
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
      });
    }

    const context = await browser.newContext({
      viewport: { width: 1920, height: 1080 },
      locale: LOCALE === 'id' ? 'id-ID' : LOCALE,
      timezoneId: TIMEZONE,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      permissions: [],
      colorScheme: 'light',
      javaScriptEnabled: true,
      ignoreHTTPSErrors: true
    });

    page = await context.newPage();

    // ══════════════════════════════════════
    //  STEP 2: PRIMARY INJECTION via addInitScript
    //  This is the PROVEN method from v3 and v4.1
    //  Runs before ANY page script — guaranteed MAIN world
    // ══════════════════════════════════════
    console.log('[1/7] Injecting via addInitScript (PRIMARY — proven method)...');

    // Order matters: shield first, then stealth patches, then interceptor
    await page.addInitScript(getAntiDetectionScript());

    if (stealthEnabled) {
      await page.addInitScript(getExtraStealthScript({
        locale: LOCALE,
        languages: LOCALE === 'id' ? "['id', 'en-US', 'en']" : "['en-US', 'en']",
        platform: 'Win32',
        hardwareConcurrency: 8,
        deviceMemory: 8
      }));
      console.log('  ✅ Anti-detection shield + stealth patches injected');
    } else {
      console.log('  ✅ Anti-detection shield injected');
    }

    await page.addInitScript(getInterceptorScript({
      timeout: TIMEOUT,
      stealthEnabled: stealthEnabled,
      stackSampleRate: 10
    }));
    injectionFlags.L1_addInitScript = true;
    console.log('  ✅ API interceptor injected (37 categories, 200+ hooks)');

    // ══════════════════════════════════════
    //  STEP 3: CDP SUPPLEMENT (push telemetry + iframe monitoring)
    //  NOT used for primary injection
    // ══════════════════════════════════════
    console.log('[2/7] Setting up CDP supplement (telemetry + iframe monitor)...');
    const scriptsForCDP = [
      getAntiDetectionScript(),
      getInterceptorScript({ timeout: TIMEOUT, stealthEnabled: stealthEnabled })
    ];
    cdpResult = await setupCDPSupplement(page, scriptsForCDP);
    if (cdpResult) {
      injectionFlags.L3_cdpSupplement = true;
      console.log('  ✅ CDP push telemetry + auto-attach active');
    }

    // ══════════════════════════════════════
    //  STEP 4: FRAME MONITORING (fallback for late-attached frames)
    // ══════════════════════════════════════
    page.on('frameattached', async (frame) => {
      try {
        await frame.evaluate(getAntiDetectionScript() + ';\n' + 
          getInterceptorScript({ timeout: TIMEOUT, stealthEnabled: stealthEnabled }));
        injectionFlags.L4_perFrame = true;
      } catch (e) {
        // Cross-origin frames will fail — expected, handled by CDP auto-attach
      }
    });

    // ══════════════════════════════════════
    //  STEP 5: NAVIGATE TO TARGET
    // ══════════════════════════════════════
    console.log('[3/7] Navigating to target...');
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });
    } catch(navErr) {
      console.warn('  ⚠️  Navigation timeout, retrying with networkidle...');
      try {
        await page.goto(url, { waitUntil: 'load', timeout: TIMEOUT });
      } catch(e) {
        console.warn('  ⚠️  Navigation failed, continuing with current state...');
      }
    }
    console.log('  🌐 Page loaded: ' + page.url());

    // Diagnostic: verify injection success
    try {
      const active = await page.evaluate(() => !!window.__SENTINEL_ACTIVE__);
      const bootOk = await page.evaluate(() => window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.bootOk : false);
      const shieldOk = await page.evaluate(() => !!window.__SENTINEL_SHIELD__);
      console.log(`  🔍 Diagnostic: ACTIVE=${active} | BOOT_OK=${bootOk} | SHIELD=${shieldOk}`);
      if (!active) {
        console.error('  🔴 CRITICAL: Injection failed! __SENTINEL_ACTIVE__ is false.');
        console.error('  🔴 Check if page blocked script execution or CSP is active.');
      }
    } catch(e) {
      console.warn('  ⚠️  Diagnostic check failed:', e.message);
    }

    // ══════════════════════════════════════
    //  STEP 6: OBSERVE ACTIVITY (adaptive timeout)
    // ══════════════════════════════════════
    console.log('[4/7] Observing activity...');
    const adaptiveTimeout = new AdaptiveTimeout(TIMEOUT, MAX_TIMEOUT);
    const observeTime = Math.max(TIMEOUT - 5000, 10000);

    await page.waitForTimeout(observeTime / 2);

    // Scroll to trigger lazy-loaded fingerprinting
    try {
      await page.evaluate(() => { window.scrollTo(0, document.body.scrollHeight / 2); });
      await page.waitForTimeout(2000);
      await page.evaluate(() => { window.scrollTo(0, document.body.scrollHeight); });
      await page.waitForTimeout(2000);
      await page.evaluate(() => { window.scrollTo(0, 0); });
    } catch(e) {}

    // Check for adaptive extension
    try {
      const midCount = await page.evaluate(() => {
        return window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.events.length : 0;
      });
      console.log(`  📊 Mid-scan events: ${midCount}`);
      if (adaptiveTimeout.checkAndExtend(midCount)) {
        console.log(`  ⏱️  Timeout extended to ${adaptiveTimeout.finalTimeout / 1000}s`);
      }
    } catch(e) {}

    await page.waitForTimeout(observeTime / 2);

    // Second adaptive check
    try {
      const lateCount = await page.evaluate(() => {
        return window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.events.length : 0;
      });
      if (adaptiveTimeout.checkAndExtend(lateCount)) {
        console.log(`  ⏱️  Timeout extended to ${adaptiveTimeout.finalTimeout / 1000}s`);
        await page.waitForTimeout(adaptiveTimeout.extensionMs);
      }
    } catch(e) {}

    // ══════════════════════════════════════
    //  STEP 7: COLLECT RESULTS FROM ALL FRAMES
    // ══════════════════════════════════════
    console.log('[5/7] Collecting forensic data...');

    // Primary: get data from top frame via __SENTINEL_DATA__ (direct object, proven v4.1 method)
    let sentinelData = { events: [], bootOk: false, frameId: '' };
    try {
      sentinelData = await page.evaluate(() => {
        if (window.__SENTINEL_DATA__) {
          return {
            events: window.__SENTINEL_DATA__.events || [],
            bootOk: window.__SENTINEL_DATA__.bootOk || false,
            frameId: window.__SENTINEL_DATA__.frameId || ''
          };
        }
        // Fallback: try __SENTINEL_FLUSH__ if __SENTINEL_DATA__ not available
        if (typeof window.__SENTINEL_FLUSH__ === 'function') {
          const flushed = JSON.parse(window.__SENTINEL_FLUSH__());
          return { events: flushed.events || [], bootOk: true, frameId: 'flush' };
        }
        return { events: [], bootOk: false, frameId: '' };
      });
    } catch(e) {
      console.warn('  ⚠️  Could not read top frame data:', e.message);
    }

    // Merge push-based telemetry from CDP binding (SUPPLEMENTAL)
    if (cdpResult && cdpResult.pushEvents && cdpResult.pushEvents.length > 0) {
      console.log(`  📡 Push telemetry: ${cdpResult.pushEvents.length} additional events from CDP`);
      const existingKeys = new Set(sentinelData.events.map(e => `${e.ts}-${e.api}-${e.frameId}`));
      const newPushEvents = cdpResult.pushEvents.filter(e => !existingKeys.has(`${e.ts}-${e.api}-${e.frameId}`));
      sentinelData.events = [...sentinelData.events, ...newPushEvents];
    }

    // Collect from child frames
    const frames = page.frames();
    const frameContextMap = [];

    for (const frame of frames) {
      try {
        const frameData = await frame.evaluate(() => {
          if (window.__SENTINEL_DATA__) {
            return {
              events: window.__SENTINEL_DATA__.events || [],
              bootOk: window.__SENTINEL_DATA__.bootOk || false,
              frameId: window.__SENTINEL_DATA__.frameId || '',
              url: location.href,
              origin: location.origin
            };
          }
          // Fallback
          if (typeof window.__SENTINEL_FLUSH__ === 'function') {
            const f = JSON.parse(window.__SENTINEL_FLUSH__());
            return { events: f.events || [], bootOk: true, frameId: 'flush', url: location.href, origin: location.origin };
          }
          return null;
        });

        if (frameData) {
          frameContextMap.push({
            type: 'frame',
            url: frameData.url,
            origin: frameData.origin,
            frameId: frameData.frameId,
            bootOk: frameData.bootOk,
            eventCount: frameData.events.length
          });

          if (frameData.events.length > 0 && frameData.frameId !== sentinelData.frameId) {
            const existingKeys = new Set(sentinelData.events.map(e => `${e.ts}-${e.api}-${e.frameId}`));
            const newFrameEvents = frameData.events.filter(e => !existingKeys.has(`${e.ts}-${e.api}-${e.frameId}`));
            sentinelData.events = [...sentinelData.events, ...newFrameEvents];
            console.log(`  📄 Frame: ${frameData.url.slice(0, 60)} — ${newFrameEvents.length} new events`);
          }
        }
      } catch (e) {
        // Cross-origin frames will fail — expected
      }
    }

    // Also collect context map from page
    try {
      const pageCtxMap = await page.evaluate(() => window.__SENTINEL_CONTEXT_MAP__ || []);
      frameContextMap.push(...pageCtxMap);
    } catch(e) {}

    // Sort events chronologically
    sentinelData.events.sort((a, b) => a.ts - b.ts);

    // ══════════════════════════════════════
    //  STEP 8: GENERATE REPORTS
    // ══════════════════════════════════════
    console.log('[6/7] Generating forensic report...');

    // Build sentinel data compatible with report generator
    const reportData = {
      events: sentinelData.events,
      injectionFlags: injectionFlags,
      dedupStats: {
        totalReceived: sentinelData.events.length,
        deduplicated: 0,
        kept: sentinelData.events.length
      }
    };

    const reportResult = generateReport(
      reportData,
      frameContextMap,
      url,
      {
        stealthEnabled: stealthEnabled,
        outputDir: OUTPUT_DIR,
        timeoutExtended: adaptiveTimeout.extended,
        finalTimeout: adaptiveTimeout.finalTimeout,
        prefix: `sentinel_${stealthEnabled ? 'stealth' : 'observe'}_${Date.now()}`
      }
    );

    // ══════════════════════════════════════
    //  STEP 9: SUMMARY
    // ══════════════════════════════════════
    const r = reportResult.reportJson;
    const bootOkFrames = frameContextMap.filter(f => f.bootOk).length;

    console.log('');
    console.log('┌─────────────────────────────────────────────────┐');
    console.log(`│  🛡️ SENTINEL v4.4 FORENSIC SUMMARY                │`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  Events:     ${String(sentinelData.events.length).padEnd(8)} (from ${bootOkFrames} frames)`);
    console.log(`│  Risk Score: ${r.riskScore || 0}/100 ${r.riskLevel || 'N/A'}`);
    console.log(`│  Threats:    ${(r.threats || []).length}`);
    console.log(`│  Categories: ${r.categoriesDetected || 0}/${r.categoriesMonitored || 37}`);
    console.log(`│  Coverage:   ${r.coveragePercent || 0}%`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  Injection: L1=${injectionFlags.L1_addInitScript} L2=${injectionFlags.L2_stealthPlugin} L3=${injectionFlags.L3_cdpSupplement} L4=${injectionFlags.L4_perFrame}`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  JSON: ${reportResult.jsonPath || 'N/A'}`);
    console.log(`│  HTML: ${reportResult.htmlPath || 'N/A'}`);
    console.log(`│  CTX:  ${reportResult.ctxPath || 'N/A'}`);
    console.log('└─────────────────────────────────────────────────┘');

    return reportResult;

  } catch (err) {
    console.error('FATAL ERROR:', err.message);
    console.error(err.stack);
    throw err;
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

// ═══════════════════════════════════════════
//  ENTRY POINT
// ═══════════════════════════════════════════
async function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║   🛡️  SENTINEL v4.4 — ZERO BLIND SPOT FORENSIC CATCHER  ║');
  console.log('║   7-Layer Architecture | 37 Categories | 1H5W Framework  ║');
  console.log('╚══════════════════════════════════════════════════════════╝');

  if (targetUrl) {
    const url = normalizeUrl(targetUrl);

    if (DUAL_MODE) {
      console.log('\n🔄 DUAL MODE: Running both observe and stealth scans...\n');
      const observeResult = await runScan(url, { stealth: false });
      const stealthResult = await runScan(url, { stealth: true });

      console.log('\n╔═══════════════════════════════════╗');
      console.log('║  📊 DUAL MODE COMPARISON           ║');
      console.log('╠═══════════════════════════════════╣');
      console.log(`║  Observe: ${observeResult.reportJson.totalEvents || 0} events, risk ${observeResult.reportJson.riskScore || 0}/100`);
      console.log(`║  Stealth: ${stealthResult.reportJson.totalEvents || 0} events, risk ${stealthResult.reportJson.riskScore || 0}/100`);
      const diff = Math.abs((observeResult.reportJson.totalEvents || 0) - (stealthResult.reportJson.totalEvents || 0));
      console.log(`║  Delta:   ${diff} events difference`);
      console.log('╚═══════════════════════════════════╝');
    } else {
      await runScan(url, { stealth: STEALTH_MODE });
    }
  } else {
    // Interactive mode
    const url = await prompt('\n🎯 Enter target URL: ');
    if (!url) {
      console.log('No URL provided. Exiting.');
      process.exit(1);
    }
    const normalizedUrl = normalizeUrl(url);
    const mode = await prompt('Mode? [1] Stealth (default) [2] Observe [3] Dual: ');

    if (mode === '3') {
      await runScan(normalizedUrl, { stealth: false });
      await runScan(normalizedUrl, { stealth: true });
    } else if (mode === '2') {
      await runScan(normalizedUrl, { stealth: false });
    } else {
      await runScan(normalizedUrl, { stealth: true });
    }
  }
}

main().catch(err => {
  console.error('Unhandled error:', err);
  process.exit(1);
});
