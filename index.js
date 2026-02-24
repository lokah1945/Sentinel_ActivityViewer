#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║   🛡️  SENTINEL v4.4.1 — ZERO BLIND SPOT FORENSIC CATCHER ║
 * ║   7-Layer Architecture | 37 Categories | 1H5W Framework   ║
 * ╚══════════════════════════════════════════════════════════╝
 * 
 * CRITICAL FIXES from v4.4:
 *   BUG #1: Navigator hooks on PROTOTYPE were shadowed by stealth's INSTANCE patches
 *     → FIX: Smart target detection — hooks where the getter actually lives
 *   BUG #2: Property-enum logged ALL Object.keys calls (noise, not fingerprint-specific)
 *     → FIX: Only log when target is navigator/screen (v4.1 approach)
 *   BUG #3: document.cookie only getter hooked (setter missed)
 *     → FIX: Both getter and setter hooked via hookGetterSetter
 *   BUG #4: createElement logged ALL tags (noise)
 *     → FIX: Filter to fingerprint-relevant tags only
 *   BUG #5: shield.hookGetterSetter not available
 *     → FIX: Added hookGetterSetter to shield
 *
 * Usage:
 *   node index.js <url>                    — Quick scan (stealth default)
 *   node index.js <url> --observe          — Observe mode (no stealth)
 *   node index.js <url> --dual-mode        — Run BOTH modes & compare
 *   node index.js <url> --no-headless      — Show browser window
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

    // Auto-attach to iframes for monitoring
    try {
      await cdpSession.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: true,
        flatten: true
      });
    } catch(e) {}

    cdpSession.on('Target.attachedToTarget', async (event) => {
      try {
        const childSession = cdpSession.session || cdpSession;
        if (event.targetInfo && event.targetInfo.type === 'iframe') {
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

async function runScan(url, options = {}) {
  const stealthEnabled = options.stealth !== false;
  const label = stealthEnabled ? '🥷 STEALTH' : '👁️ OBSERVE';

  console.log(`\n${'═'.repeat(65)}`);
  console.log(`  ${label} MODE — Sentinel v4.4.1 Zero Blind Spot`);
  console.log(`  Target: ${url}`);
  console.log(`  Timeout: ${TIMEOUT / 1000}s (adaptive up to ${TIMEOUT * 4 / 1000}s)`);
  console.log(`  Headless: ${HEADLESS} | Locale: ${LOCALE} | TZ: ${TIMEZONE}`);
  console.log(`${'═'.repeat(65)}\n`);

  let browser, page, cdpData;
  const injectionFlags = { L1_addInitScript: false, L2_stealthPlugin: false, L3_cdpSupplement: false, L4_perFrame: false };

  try {
    // ══════════════════════════════════════
    //  STEP 1: LAUNCH BROWSER
    // ══════════════════════════════════════
    if (stealthEnabled) {
      try {
        const { chromium } = require('playwright-extra');
        const stealthPlugin = createStealthPlugin();
        if (stealthPlugin) {
          chromium.use(stealthPlugin);
          injectionFlags.L2_stealthPlugin = true;
          console.log('✅ Stealth plugin loaded (puppeteer-extra-plugin-stealth)');
        }
        browser = await chromium.launch({
          headless: HEADLESS,
          args: [
            '--disable-blink-features=AutomationControlled',
            '--disable-features=IsolateOrigins,site-per-process',
            '--disable-web-security',
            '--no-first-run',
            '--no-default-browser-check',
          ]
        });
      } catch(e) {
        const { chromium } = require('playwright');
        browser = await chromium.launch({ headless: HEADLESS,
          args: ['--disable-blink-features=AutomationControlled', '--disable-features=IsolateOrigins,site-per-process']
        });
      }
    } else {
      const { chromium } = require('playwright');
      browser = await chromium.launch({ headless: HEADLESS });
    }

    const context = await browser.newContext({
      viewport: { width: 1920, height: 1080 },
      locale: LOCALE,
      timezoneId: TIMEZONE,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      permissions: [],
      colorScheme: 'light',
    });

    page = await context.newPage();

    // ══════════════════════════════════════
    //  STEP 2: PRIMARY INJECTION via addInitScript
    //  Order: shield → stealth → interceptor
    //  The interceptor MUST run AFTER stealth patches navigator properties,
    //  so it can wrap those patches with monitoring.
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
        console.error('  🔴 CRITICAL: Injection failed! __SENTINEL_ACTIVE__ is false.');
        console.error('  Trying emergency re-injection...');
        await page.evaluate(getAntiDetectionScript() + ';\n' +
          getInterceptorScript({ timeout: TIMEOUT, stealthEnabled }));
      }
    } catch(e) { console.warn('  ⚠️ Diagnostic check failed:', e.message); }

    // ══════════════════════════════════════
    //  STEP 7: OBSERVE ACTIVITY (with adaptive timeout)
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
    //  STEP 8: COLLECT DATA
    // ══════════════════════════════════════
    console.log('[5/7] Collecting forensic data...');

    // Primary: get from top frame
    let sentinelData;
    try {
      sentinelData = await page.evaluate(() => {
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
      });
    } catch(e) {
      sentinelData = { events: [], bootOk: false, frameId: 'error' };
    }

    // Collect from iframes
    const frames = page.frames();
    for (let i = 1; i < frames.length; i++) {
      try {
        const frameData = await frames[i].evaluate(() => {
          if (window.__SENTINEL_DATA__) {
            return {
              events: window.__SENTINEL_DATA__.events || [],
              bootOk: window.__SENTINEL_DATA__.bootOk || false,
              frameId: window.__SENTINEL_DATA__.frameId || '',
              origin: location.origin
            };
          }
          if (typeof window.__SENTINEL_FLUSH__ === 'function') {
            var f = JSON.parse(window.__SENTINEL_FLUSH__());
            return { events: f.events || [], bootOk: true, frameId: 'iframe-flushed', origin: location.origin };
          }
          return null;
        });
        if (frameData && frameData.events.length > 0) {
          sentinelData.events = sentinelData.events.concat(frameData.events);
        }
      } catch(e) { /* cross-origin iframe — expected */ }
    }

    // Merge CDP push events
    if (cdpData && cdpData.pushEvents.length > 0) {
      console.log(`  📡 Push telemetry: ${cdpData.pushEvents.length} additional events from CDP`);
      // Deduplicate: only add events not already in sentinelData
      const existingTs = new Set(sentinelData.events.map(e => e.ts + ':' + e.api));
      for (const pe of cdpData.pushEvents) {
        const key = pe.ts + ':' + pe.api;
        if (!existingTs.has(key)) {
          sentinelData.events.push(pe);
          existingTs.add(key);
        }
      }
    }

    // Build context map
    const pageCtxMap = await page.evaluate(() => window.__SENTINEL_CONTEXT_MAP__ || []).catch(() => []);
    const frameInfo = frames.map(f => ({ type: 'frame', url: f.url(), name: f.name() || '' }));
    const fullContextMap = [...(pageCtxMap || []), ...frameInfo];

    console.log(`[6/7] Generating forensic report...`);

    // ══════════════════════════════════════
    //  STEP 9: GENERATE REPORT
    // ══════════════════════════════════════
    const reportResult = generateReport(sentinelData, fullContextMap, url, {
      stealthEnabled,
      prefix: `sentinel_${stealthEnabled ? 'stealth' : 'observe'}_${Date.now()}`
    });

    const r = reportResult.reportJson;

    console.log(`Reports saved:`);
    console.log(`   JSON: ${reportResult.jsonPath}`);
    console.log(`   HTML: ${reportResult.htmlPath}`);
    console.log(`   CTX:  ${reportResult.ctxPath}`);

    console.log('');
    console.log('┌─────────────────────────────────────────────────┐');
    console.log(`│  🛡️ SENTINEL v4.4.1 FORENSIC SUMMARY               │`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  Events:     ${String(r.totalEvents).padEnd(8)} (from ${r.coverageProof?.totalFramesDetected || '?'} frames)`);
    console.log(`│  Risk Score: ${r.riskScore}/100 ${r.riskLevel}`);
    console.log(`│  Threats:    ${r.threats?.length || 0}`);
    console.log(`│  Categories: ${r.categoriesDetected}/${r.categoriesMonitored}`);
    console.log(`│  Coverage:   ${r.coveragePercent}%`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  Injection: L1=${injectionFlags.L1_addInitScript} L2=${injectionFlags.L2_stealthPlugin} L3=${injectionFlags.L3_cdpSupplement} L4=${injectionFlags.L4_perFrame}`);
    console.log('├─────────────────────────────────────────────────┤');
    console.log(`│  JSON: ${reportResult.jsonPath}`);
    console.log(`│  HTML: ${reportResult.htmlPath}`);
    console.log(`│  CTX:  ${reportResult.ctxPath}`);
    console.log('└─────────────────────────────────────────────────┘');

    await browser.close();
    return reportResult;

  } catch(e) {
    console.error(`\n🔴 Scan failed: ${e.message}`);
    if (browser) await browser.close().catch(() => {});
    return null;
  }
}

// ── Main ──
async function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║   🛡️  SENTINEL v4.4.1 — ZERO BLIND SPOT FORENSIC CATCHER ║');
  console.log('║   7-Layer Architecture | 37 Categories | 1H5W Framework   ║');
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
      console.log('╚═══════════════════════════════════╝');
    }
  } else {
    await runScan(targetUrl, { stealth: STEALTH_MODE });
  }
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
