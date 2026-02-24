#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║   🛡️  SENTINEL v4.4.2 — ZERO BLIND SPOT FORENSIC CATCHER ║
 * ║   7-Layer Architecture | 37 Categories | 1H5W Framework   ║
 * ╚══════════════════════════════════════════════════════════╝
 * 
 * BASED ON v4.4.1 (WORKING — 1512 events captured)
 * 
 * v4.4.2 FIXES (surgical, non-breaking):
 *   FIX #1: Persistent context option (--persistent) to avoid incognito flag
 *   FIX #2: Anti-stuck [5/7] — parallel frame.evaluate with timeout
 *   FIX #3: Final flush before browser close (no event loss)
 *   FIX #4: Injection flags passed correctly to report generator
 *   FIX #5: Frame info with proper url/origin for coverage proof
 *   FIX #6: timeSpanMs fix in report generator (max ts, not last ts)
 *   FIX #7: CoverageProof fix (no null in unmonitored frames)
 *
 * Usage:
 *   node index.js <url>                    — Quick scan (stealth default)
 *   node index.js <url> --observe          — Observe mode (no stealth)
 *   node index.js <url> --dual-mode        — Run BOTH modes & compare
 *   node index.js <url> --no-headless      — Show browser window
 *   node index.js <url> --persistent       — Use persistent context (anti-incognito)
 *   node index.js <url> --profile-dir=PATH — Custom profile directory
 *   node index.js <url> --timeout=45000    — Custom timeout (ms)
 *   node index.js <url> --locale=en-US     — Override locale
 *   node index.js <url> --timezone=Asia/Jakarta — Override timezone
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
const HEADLESS = flags['no-headless'] ? false : (flags.headless !== undefined ? flags.headless !== 'false' : true);
const DUAL_MODE = flags['dual-mode'] === true;
const STEALTH_MODE = flags.observe ? false : true;
const LOCALE = flags.locale || 'id';
const TIMEZONE = flags.timezone || 'Asia/Jakarta';
const PERSISTENT = flags['profile-dir'] || flags['persistent'] || '';

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
 * CDP Supplement — for push telemetry and iframe auto-attach
 * NOT used for primary injection (addInitScript handles that)
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

    // Auto-attach to iframes/workers for monitoring (L3)
    try {
      await cdpSession.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: true,
        flatten: true
      });
    } catch(e) {}

    cdpSession.on('Target.attachedToTarget', async (event) => {
      try {
        if (event.targetInfo && (event.targetInfo.type === 'iframe' || event.targetInfo.type === 'worker' || event.targetInfo.type === 'service_worker')) {
          try {
            await cdpSession.send('Runtime.runIfWaitingForDebugger', {}, event.sessionId);
          } catch(e) {}
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
 * FIX #2: Anti-stuck
 */
async function evalWithTimeout(target, fn, ms) {
  ms = ms || 5000;
  return Promise.race([
    target.evaluate(fn),
    new Promise((_, rej) => setTimeout(() => rej(new Error('EVAL_TIMEOUT')), ms))
  ]);
}

async function runScan(url, options = {}) {
  const stealthEnabled = options.stealth !== false;
  const label = stealthEnabled ? '🥷 STEALTH' : '👁️ OBSERVE';

  console.log(`\n${'═'.repeat(65)}`);
  console.log(`  ${label} MODE — Sentinel v4.4.2 Zero Blind Spot`);
  console.log(`  Target: ${url}`);
  console.log(`  Timeout: ${TIMEOUT / 1000}s | Headless: ${HEADLESS} | Locale: ${LOCALE} | TZ: ${TIMEZONE}`);
  console.log(`  Persistent: ${PERSISTENT ? 'Yes' : 'No (ephemeral)'}`);
  console.log(`${'═'.repeat(65)}\n`);

  let browser, context, page, cdpData;
  const injectionFlags = { L1_addInitScript: false, L2_stealthPlugin: false, L3_cdpSupplement: false, L4_perFrame: false };

  try {
    // ══════════════════════════════════════
    //  STEP 1: LAUNCH BROWSER
    // ══════════════════════════════════════
    const launchArgs = [
      '--disable-blink-features=AutomationControlled',
      '--disable-features=IsolateOrigins,site-per-process',
      '--disable-web-security',
      '--no-first-run',
      '--no-default-browser-check',
    ];

    const contextOptions = {
      viewport: { width: 1920, height: 1080 },
      locale: LOCALE,
      timezoneId: TIMEZONE,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      permissions: [],
      colorScheme: 'light',
    };

    let chromium;

    if (stealthEnabled) {
      try {
        const pe = require('playwright-extra');
        chromium = pe.chromium;
        const stealthPlugin = createStealthPlugin();
        if (stealthPlugin) {
          chromium.use(stealthPlugin);
          injectionFlags.L2_stealthPlugin = true;
          console.log('✅ Stealth plugin loaded');
        }
      } catch(e) {
        chromium = require('playwright').chromium;
      }
    } else {
      chromium = require('playwright').chromium;
    }

    // FIX #1: Persistent context option
    if (PERSISTENT) {
      const profileDir = typeof PERSISTENT === 'string' && PERSISTENT !== 'true'
        ? path.resolve(PERSISTENT)
        : path.join(__dirname, 'chrome_profile');

      console.log(`  → Using persistent context: ${profileDir}`);
      context = await chromium.launchPersistentContext(profileDir, {
        headless: HEADLESS,
        args: launchArgs,
        ignoreDefaultArgs: ['--enable-automation'],
        ...contextOptions
      });
      browser = null; // persistent context IS the browser
      page = context.pages()[0] || await context.newPage();
    } else {
      browser = await chromium.launch({
        headless: HEADLESS,
        args: launchArgs
      });
      context = await browser.newContext(contextOptions);
      page = await context.newPage();
    }

    // ══════════════════════════════════════
    //  STEP 2: PRIMARY INJECTION via addInitScript
    //  Order: shield → stealth → interceptor
    //  UNCHANGED FROM v4.4.1 — this is the PROVEN working method
    // ══════════════════════════════════════
    console.log('[1/7] Injecting via addInitScript (PRIMARY — proven method)...');

    // First: shield (sets window.__SENTINEL_SHIELD__)
    await page.addInitScript(getAntiDetectionScript());

    // Second: stealth patches (patches navigator/screen INSTANCE properties)
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

    // Third: interceptor (uses smartHookGetter to wrap whatever is there)
    await page.addInitScript(getInterceptorScript({
      timeout: TIMEOUT,
      stealthEnabled: stealthEnabled,
      stackSampleRate: 10
    }));
    injectionFlags.L1_addInitScript = true;
    console.log('  ✅ API interceptor injected (37 categories, 200+ hooks)');

    // ══════════════════════════════════════
    //  STEP 3: CDP SUPPLEMENT
    // ══════════════════════════════════════
    console.log('[2/7] Setting up CDP supplement (telemetry + iframe monitor)...');
    cdpData = await setupCDPSupplement(page);
    if (cdpData.cdpSession) {
      injectionFlags.L3_cdpSupplement = true;
      console.log('  ✅ CDP push telemetry + auto-attach active');
    }

    // ══════════════════════════════════════
    //  STEP 4: Per-frame injection for late-attached frames
    // ══════════════════════════════════════
    page.on('frameattached', async (frame) => {
      try {
        await frame.evaluate(getAntiDetectionScript() + ';\n' + 
          getInterceptorScript({ timeout: TIMEOUT, stealthEnabled: stealthEnabled }));
        injectionFlags.L4_perFrame = true;
      } catch(e) { /* cross-origin — expected */ }
    });

    // ══════════════════════════════════════
    //  STEP 5: NAVIGATE TO TARGET
    // ══════════════════════════════════════
    console.log('[3/7] Navigating to target...');
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });
    } catch(e) {
      await page.goto(url, { waitUntil: 'commit', timeout: TIMEOUT * 2 });
    }
    console.log(`  🌐 Page loaded: ${page.url()}`);

    // ══════════════════════════════════════
    //  STEP 6: DIAGNOSTIC CHECK
    // ══════════════════════════════════════
    try {
      const active = await page.evaluate(() => !!window.__SENTINEL_ACTIVE__);
      const bootOk = await page.evaluate(() => window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.bootOk : false);
      const shieldOk = await page.evaluate(() => !!window.__SENTINEL_SHIELD__);
      console.log(`  🔍 Diagnostic: ACTIVE=${active} | BOOT_OK=${bootOk} | SHIELD=${shieldOk}`);
      if (!active) {
        console.error('  🔴 CRITICAL: Injection failed! Trying emergency re-injection...');
        await page.evaluate(getAntiDetectionScript() + ';\n' +
          getInterceptorScript({ timeout: TIMEOUT, stealthEnabled }));
      }
    } catch(e) { console.warn('  ⚠️ Diagnostic check failed:', e.message); }

    // ══════════════════════════════════════
    //  STEP 7: OBSERVE ACTIVITY (with adaptive timeout)
    //  UNCHANGED FROM v4.4.1 — proven working
    // ══════════════════════════════════════
    console.log('[4/7] Observing activity...');
    const observeTime = Math.max(TIMEOUT - 5000, 10000);

    // Scroll to trigger lazy-loaded scripts
    await page.waitForTimeout(Math.floor(observeTime * 0.4));
    try { await page.evaluate(() => { window.scrollTo(0, document.body.scrollHeight / 2); }); } catch(e) {}
    await page.waitForTimeout(2000);
    try { await page.evaluate(() => { window.scrollTo(0, document.body.scrollHeight); }); } catch(e) {}
    await page.waitForTimeout(2000);
    try { await page.evaluate(() => { window.scrollTo(0, 0); }); } catch(e) {}

    // Wait remaining time
    const remaining = observeTime - Math.floor(observeTime * 0.4) - 4000;
    if (remaining > 0) await page.waitForTimeout(remaining);

    const midCount = await page.evaluate(() => {
      return window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.events.length : 0;
    }).catch(() => 0);
    console.log(`  📊 Mid-scan events: ${midCount}`);

    // Adaptive: if events are low, wait longer
    if (midCount < 50) {
      const extraWait = Math.min(TIMEOUT, 15000);
      await page.waitForTimeout(extraWait);
      const lateCount = await page.evaluate(() => {
        return window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.events.length : 0;
      }).catch(() => 0);
      if (lateCount > midCount) console.log(`  📊 Late events detected: ${lateCount}`);
    }

    // ══════════════════════════════════════
    //  STEP 8: COLLECT DATA — FIX #2: anti-stuck + FIX #3: final flush
    // ══════════════════════════════════════
    console.log('[5/7] Collecting forensic data...');

    // FIX #3: Final flush — trigger push of remaining events
    try {
      await page.evaluate(() => {
        if (typeof window.__SENTINEL_PUSH__ === 'function' && window.__SENTINEL_DATA__) {
          try {
            window.__SENTINEL_PUSH__(JSON.stringify({
              type: 'final_flush',
              frameId: window.__SENTINEL_DATA__.frameId || '',
              events: window.__SENTINEL_DATA__.events.slice(-100)
            }));
          } catch(e) {}
        }
      });
      await page.waitForTimeout(500); // grace period for push to arrive
    } catch(e) {}

    // Primary: get from top frame (with timeout protection)
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
      console.warn(`  ⚠️ Main frame collection timeout: ${e.message}`);
      sentinelData = { events: [], bootOk: false, frameId: 'error' };
    }
    console.log(`  📦 Main frame: ${sentinelData.events.length} events`);

    // FIX #2: Collect from iframes — parallel with timeout, skip blank frames
    const frames = page.frames();
    const framePromises = [];
    const frameInfoList = [];

    for (let i = 0; i < frames.length; i++) {
      const f = frames[i];
      const fUrl = f.url() || '';
      let fOrigin = null;
      try {
        if (fUrl.startsWith('http')) fOrigin = new URL(fUrl).origin;
      } catch(e) {}
      frameInfoList.push({ type: 'frame', url: fUrl, origin: fOrigin, name: f.name() || '' });

      // Skip main frame (already collected), blank/empty frames
      if (i === 0) continue;
      if (!fUrl || fUrl === 'about:blank' || !fUrl.startsWith('http')) continue;

      framePromises.push(
        evalWithTimeout(f, () => {
          if (window.__SENTINEL_DATA__) {
            return {
              events: window.__SENTINEL_DATA__.events || [],
              bootOk: window.__SENTINEL_DATA__.bootOk || false,
              frameId: window.__SENTINEL_DATA__.frameId || '',
              origin: location.origin
            };
          }
          if (typeof window.__SENTINEL_FLUSH__ === 'function') {
            var fl = JSON.parse(window.__SENTINEL_FLUSH__());
            return { events: fl.events || [], bootOk: true, frameId: 'iframe-flushed', origin: location.origin };
          }
          return null;
        }, 3000).catch(e => null) // silently handle cross-origin/destroyed frames
      );
    }

    // Parallel collection (FIX #2: anti-stuck)
    if (framePromises.length > 0) {
      const results = await Promise.allSettled(framePromises);
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value && r.value.events && r.value.events.length > 0) {
          sentinelData.events = sentinelData.events.concat(r.value.events);
        }
      }
    }
    console.log(`  📦 Total frames: ${frames.length} (${framePromises.length} sub-frames checked)`);

    // Merge CDP push events
    if (cdpData && cdpData.pushEvents.length > 0) {
      console.log(`  📡 Push telemetry: ${cdpData.pushEvents.length} additional events from CDP`);
      const existingTs = new Set(sentinelData.events.map(e => e.ts + ':' + e.api));
      for (const pe of cdpData.pushEvents) {
        const key = pe.ts + ':' + pe.api;
        if (!existingTs.has(key)) {
          sentinelData.events.push(pe);
          existingTs.add(key);
        }
      }
    }

    console.log(`  📦 Grand total: ${sentinelData.events.length} events`);

    // FIX #5: Build context map with proper url/origin
    const pageCtxMap = await page.evaluate(() => window.__SENTINEL_CONTEXT_MAP__ || []).catch(() => []);
    const fullContextMap = [...(pageCtxMap || []), ...frameInfoList];

    console.log(`[6/7] Generating forensic report...`);

    // ══════════════════════════════════════
    //  STEP 9: GENERATE REPORT — FIX #4: pass injection flags
    // ══════════════════════════════════════
    const reportResult = generateReport(sentinelData, fullContextMap, url, {
      stealthEnabled,
      prefix: `sentinel_${stealthEnabled ? 'stealth' : 'observe'}_${Date.now()}`,
      injectionFlags: injectionFlags,  // FIX #4: pass real flags
      frameInfo: frameInfoList         // FIX #5: pass proper frame info
    });

    const r = reportResult.reportJson;

    console.log(`Reports saved:`);
    console.log(`   JSON: ${reportResult.jsonPath}`);
    console.log(`   HTML: ${reportResult.htmlPath}`);
    console.log(`   CTX:  ${reportResult.ctxPath}`);

    console.log('');
    console.log('┌─────────────────────────────────────────────────┐');
    console.log(`│  🛡️ SENTINEL v4.4.2 FORENSIC SUMMARY               │`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  Events:     ${String(r.totalEvents).padEnd(8)} (from ${r.coverageProof?.totalFramesDetected || '?'} frames)`);
    console.log(`│  Risk Score: ${r.riskScore}/100 ${r.riskLevel}`);
    console.log(`│  Threats:    ${r.threats?.length || 0}`);
    console.log(`│  Categories: ${r.categoriesDetected}/${r.categoriesMonitored}`);
    console.log(`│  Duration:   ${(r.timeSpanMs / 1000).toFixed(1)}s`);
    console.log(`│  Coverage:   ${r.coveragePercent}%`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  Injection: L1=${injectionFlags.L1_addInitScript} L2=${injectionFlags.L2_stealthPlugin} L3=${injectionFlags.L3_cdpSupplement} L4=${injectionFlags.L4_perFrame}`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  JSON: ${reportResult.jsonPath}`);
    console.log(`│  HTML: ${reportResult.htmlPath}`);
    console.log(`│  CTX:  ${reportResult.ctxPath}`);
    console.log('└─────────────────────────────────────────────────┘');

    // Cleanup
    try {
      if (cdpData && cdpData.cdpSession) await cdpData.cdpSession.detach().catch(() => {});
    } catch(e) {}

    if (browser) await browser.close();
    else if (context) await context.close();

    return reportResult;

  } catch(e) {
    console.error(`\n🔴 Scan failed: ${e.message}`);
    try {
      if (browser) await browser.close().catch(() => {});
      else if (context) await context.close().catch(() => {});
    } catch(ex) {}
    return null;
  }
}

// ── Main ──
async function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║   🛡️  SENTINEL v4.4.2 — ZERO BLIND SPOT FORENSIC CATCHER ║');
  console.log('║   Based on v4.4.1 | Surgical Fixes | 1H5W Framework      ║');
  console.log('╚══════════════════════════════════════════════════════════╝');

  if (!targetUrl) {
    targetUrl = await prompt('\n🔍 Enter URL to scan: ');
  }

  if (!targetUrl) {
    console.log('❌ No URL provided. Exiting.');
    process.exit(1);
  }

  targetUrl = normalizeUrl(targetUrl);

  if (DUAL_MODE) {
    console.log('\n🔄 DUAL MODE: Running both observe and stealth scans...\n');
    const observeResult = await runScan(targetUrl, { stealth: false });
    const stealthResult = await runScan(targetUrl, { stealth: true });

    if (observeResult && stealthResult) {
      const oEvents = observeResult.reportJson.totalEvents;
      const sEvents = stealthResult.reportJson.totalEvents;
      console.log('\n╔═══════════════════════════════════╗');
      console.log('║  📊 DUAL MODE COMPARISON           ║');
      console.log('╠═══════════════════════════════════╣');
      console.log(`║  Observe: ${oEvents} events, risk ${observeResult.reportJson.riskScore}/100`);
      console.log(`║  Stealth: ${sEvents} events, risk ${stealthResult.reportJson.riskScore}/100`);
      console.log(`║  Delta:   ${Math.abs(oEvents - sEvents)} events difference`);
      console.log(`║  Duration: O=${(observeResult.reportJson.timeSpanMs/1000).toFixed(1)}s S=${(stealthResult.reportJson.timeSpanMs/1000).toFixed(1)}s`);
      console.log('╚═══════════════════════════════════╝');
    }
  } else {
    await runScan(targetUrl, { stealth: STEALTH_MODE });
  }
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
