#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║   SENTINEL v4.0 — FORENSIC MALING CATCHER               ║
 * ║   7-Layer Architecture | 31 Categories | 1H5W Framework  ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * LAYER 1: CDP Injection (Page.addScriptToEvaluateOnNewDocument)
 * LAYER 2: Anti-Detection Shield (toString, descriptor, stack)
 * LAYER 3: Core Hooks Enhanced (19 cat with value capture)
 * LAYER 4: Extended Hooks (12 new vectors)
 * LAYER 5: Exfiltration Monitor (fetch/xhr/beacon/ws/img)
 * LAYER 6: Behavior Correlation (signatures, bursts, entropy)
 * LAYER 7: 1H5W Forensic Reporting
 *
 * Usage:
 *   node index.js                        — Interactive mode
 *   node index.js <url>                  — Quick scan (stealth default)
 *   node index.js <url> --stealth        — Stealth mode (default)
 *   node index.js <url> --observe        — Observe mode (no stealth)
 *   node index.js <url> --dual-mode      — Run BOTH modes & compare
 *   node index.js <url> --timeout=45000  — Custom timeout (ms)
 *   node index.js <url> --headless       — Headless mode
 *   node index.js <url> --cdp            — Force CDP injection (recommended)
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
const HEADLESS = flags.headless === true || flags.headless === 'true';
const DUAL_MODE = flags['dual-mode'] === true;
const STEALTH_MODE = flags.observe ? false : true;
const USE_CDP = flags.cdp !== false; // CDP injection enabled by default

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
 * Setup CDP-level injection for guaranteed script execution
 * This solves the v3 bug where stealth mode captured 0 events
 * because addInitScript used isolated worlds
 */
async function setupCDPInjection(page, scripts) {
  try {
    const cdpSession = await page.context().newCDPSession(page);

    // Layer 1: Inject scripts via CDP into MAIN world
    // This runs BEFORE any page JavaScript, in every frame
    for (const script of scripts) {
      await cdpSession.send('Page.addScriptToEvaluateOnNewDocument', {
        source: script
        // NOTE: No worldName — runs in MAIN world, not isolated
      });
    }

    // Setup Runtime.addBinding for push-based telemetry
    try {
      await cdpSession.send('Runtime.addBinding', {
        name: '__SENTINEL_PUSH__'
      });
    } catch(e) {
      // Binding might already exist or not supported
    }

    // Listen for push telemetry from injected scripts
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

    // Enable Target.setAutoAttach for child frame monitoring
    try {
      await cdpSession.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: false,
        flatten: true
      });
    } catch(e) {
      // Not all contexts support this
    }

    return { cdpSession, pushEvents };
  } catch(err) {
    console.warn('⚠️  CDP injection setup failed, falling back to addInitScript:', err.message);
    return null;
  }
}

async function runScan(url, options = {}) {
  const stealthEnabled = options.stealth !== false;
  const label = stealthEnabled ? '🥷 STEALTH' : '👁️ OBSERVE';

  console.log(`\n${'═'.repeat(65)}`);
  console.log(`  ${label} MODE — Sentinel v4 Forensic Scan`);
  console.log(`  Target: ${url}`);
  console.log(`  Timeout: ${TIMEOUT / 1000}s | Headless: ${HEADLESS} | CDP: ${USE_CDP}`);
  console.log(`${'═'.repeat(65)}\n`);

  let browser, page, cdpResult = null;

  try {
    if (stealthEnabled) {
      const { chromium } = require('playwright-extra');
      const stealthPlugin = createStealthPlugin();
      chromium.use(stealthPlugin);

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

      const context = await browser.newContext({
        viewport: { width: 1920, height: 1080 },
        locale: 'en-US',
        timezoneId: 'Asia/Jakarta',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        permissions: [],
        colorScheme: 'light',
      });

      page = await context.newPage();

      // ── LAYER 1: CDP Injection (fixes v3 stealth 0-event bug) ──
      if (USE_CDP) {
        const scripts = [
          getAntiDetectionScript(),    // Layer 2: Anti-detection shield
          getInterceptorScript({ timeout: TIMEOUT }),  // Layer 3+4: Forensic hooks
        ];
        cdpResult = await setupCDPInjection(page, scripts);

        if (cdpResult) {
          console.log('✅ CDP injection active — scripts injected into MAIN world');
        }
      }

      // Fallback: also inject via addInitScript as backup
      if (!cdpResult) {
        await page.addInitScript(getAntiDetectionScript());
        await page.addInitScript(getExtraStealthScript());
        await page.addInitScript(getInterceptorScript({ timeout: TIMEOUT }));
        console.log('⚠️  Using addInitScript fallback (isolated world risk)');
      }

    } else {
      // ── OBSERVE MODE: Plain playwright ──
      const { chromium } = require('playwright');

      browser = await chromium.launch({
        headless: HEADLESS,
      });

      const context = await browser.newContext({
        viewport: { width: 1920, height: 1080 },
      });

      page = await context.newPage();

      // In observe mode, use CDP injection too for reliability
      if (USE_CDP) {
        const scripts = [
          getAntiDetectionScript(),
          getInterceptorScript({ timeout: TIMEOUT }),
        ];
        cdpResult = await setupCDPInjection(page, scripts);

        if (cdpResult) {
          console.log('✅ CDP injection active (observe mode)');
        }
      }

      if (!cdpResult) {
        await page.addInitScript(getAntiDetectionScript());
        await page.addInitScript(getInterceptorScript({ timeout: TIMEOUT }));
      }
    }

    // ── Frame monitoring: inject into all child frames safely ──
    page.on('frameattached', async (frame) => {
      try {
        await frame.evaluate(getAntiDetectionScript() + ';' + getInterceptorScript({ timeout: TIMEOUT }));
      } catch (e) {
        // Cross-origin frames will fail — CDP injection covers these
      }
    });

    console.log('🌐 Navigating to target...');
    await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: TIMEOUT
    });

    console.log('⏳ Observing activity...');

    const observeTime = Math.max(TIMEOUT - 5000, 10000);
    await page.waitForTimeout(observeTime);

    // Scroll to trigger lazy-loaded fingerprinting
    try {
      await page.evaluate(() => {
        window.scrollTo(0, document.body.scrollHeight / 2);
      });
      await page.waitForTimeout(2000);
      await page.evaluate(() => {
        window.scrollTo(0, document.body.scrollHeight);
      });
      await page.waitForTimeout(2000);
    } catch(e) {}

    // ── Collect results from all frames ──
    console.log('📊 Collecting forensic data...');

    // Primary: get data from top frame
    let sentinelData = { events: [], bootOk: false, frameId: '' };
    try {
      sentinelData = await page.evaluate(() => {
        return window.__SENTINEL_DATA__ || { events: [], bootOk: false };
      });
    } catch(e) {
      console.warn('⚠️  Could not read top frame data:', e.message);
    }

    // Merge push-based telemetry from CDP binding
    if (cdpResult && cdpResult.pushEvents && cdpResult.pushEvents.length > 0) {
      console.log(`  📡 Push telemetry: ${cdpResult.pushEvents.length} events from CDP binding`);
      sentinelData.events = [...(sentinelData.events || []), ...cdpResult.pushEvents];
    }

    // Try to collect from child frames (with error handling)
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

          // Merge frame events (avoid duplicates from top frame)
          if (frameData.frameId !== sentinelData.frameId && frameData.events.length > 0) {
            sentinelData.events = [...sentinelData.events, ...frameData.events];
          }
        }
      } catch(e) {
        // Cross-origin frame — record it as unmonitored
        frameContextMap.push({
          type: 'frame',
          url: frame.url(),
          origin: new URL(frame.url() || 'about:blank').origin,
          bootOk: false,
          eventCount: 0,
          error: 'cross-origin-access-denied'
        });
      }
    }

    // Also get context map from page
    let pageContextMap = [];
    try {
      pageContextMap = await page.evaluate(() => {
        return window.__SENTINEL_CONTEXT_MAP__ || [];
      });
    } catch(e) {}

    const fullContextMap = [...pageContextMap, ...frameContextMap];

    // Deduplicate events by ts+api+frameId
    const seen = new Set();
    sentinelData.events = (sentinelData.events || []).filter(e => {
      const key = `${e.ts}-${e.api}-${e.frameId || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    const eventCount = sentinelData.events?.length || 0;
    console.log(`\n✅ Scan complete! Captured ${eventCount} forensic events from ${frameContextMap.length} frames\n`);

    // Check BOOT_OK status
    const bootOkCount = sentinelData.events.filter(e => e.api === 'BOOT_OK').length;
    if (bootOkCount === 0) {
      console.log('⚠️  WARNING: No BOOT_OK received — injection may have failed!');
    } else {
      console.log(`✅ BOOT_OK received from ${bootOkCount} context(s)`);
    }

    // ── Generate forensic report ──
    const reportResult = generateReport(sentinelData, fullContextMap, url, {
      stealthEnabled,
      prefix: `sentinel_${stealthEnabled ? 'stealth' : 'observe'}_${Date.now()}`
    });

    // ── Print forensic summary ──
    const r = reportResult.reportJson;

    console.log('┌──────────────────────────────────────────────────┐');
    console.log(`│  🛡️ SENTINEL v4 FORENSIC SUMMARY                 │`);
    console.log('├──────────────────────────────────────────────────┤');
    console.log(`│  Risk Score: ${String(r.riskScore + '/100').padEnd(12)} ${r.riskLevel.padEnd(20)}│`);
    console.log(`│  Events: ${String(r.totalEvents).padEnd(12)} Categories: ${String(r.categoriesDetected + '/' + r.categoriesMonitored).padEnd(8)}│`);
    console.log(`│  Origins: ${String(r.uniqueOrigins.length).padEnd(11)} Threats: ${String(r.threats.length).padEnd(10)}│`);
    console.log(`│  Frames: ${String(r.uniqueFrames?.length || 0).padEnd(12)} Coverage: ${String((r.coverageProof?.coverage || 0) + '%').padEnd(8)}│`);
    console.log('└──────────────────────────────────────────────────┘');

    // 1H5W Summary
    if (r.forensic1H5W) {
      console.log('\n🔍 FORENSIC 1H5W:');
      console.log(`  👤 WHO:   ${r.forensic1H5W.WHO}`);
      console.log(`  📋 WHAT:  ${r.forensic1H5W.WHAT}`);
      console.log(`  ⏱️  WHEN:  ${r.forensic1H5W.WHEN}`);
      console.log(`  📍 WHERE: ${r.forensic1H5W.WHERE}`);
      console.log(`  ❓ WHY:   ${r.forensic1H5W.WHY}`);
      console.log(`  🔧 HOW:   ${r.forensic1H5W.HOW}`);
    }

    // Library attribution
    if (r.correlation?.attributions?.length > 0) {
      console.log('\n📚 IDENTIFIED LIBRARIES:');
      for (const attr of r.correlation.attributions) {
        console.log(`  🔍 ${attr.library} — ${attr.confidence}% confidence`);
        console.log(`     Patterns: ${attr.matchedPatterns.join(', ')}`);
      }
    }

    // Burst analysis summary
    if (r.correlation?.summary?.fingerprintBursts > 0) {
      console.log(`\n💥 BURST ANALYSIS: ${r.correlation.summary.fingerprintBursts} fingerprint burst(s) detected`);
    }

    if (r.threats.length > 0) {
      console.log('\n🚨 THREATS DETECTED:');
      for (const t of r.threats) {
        const icon = t.severity === 'CRITICAL' ? '🔴' : t.severity === 'HIGH' ? '🟡' : '🔵';
        console.log(`  ${icon} [${t.severity}] ${t.type}`);
        if (t.who) console.log(`     WHO: ${t.who}`);
        console.log(`     └─ ${t.detail}`);
      }
    }

    console.log(`\n📁 Reports saved:`);
    console.log(`   JSON: ${reportResult.jsonPath}`);
    console.log(`   HTML: ${reportResult.htmlPath}`);
    console.log(`   CTX:  ${reportResult.ctxPath}`);

    return reportResult;

  } catch (err) {
    console.error('❌ Scan error:', err.message);
    if (err.stack) console.error(err.stack.split('\n').slice(0, 3).join('\n'));
    throw err;
  } finally {
    if (cdpResult?.cdpSession) {
      try { await cdpResult.cdpSession.detach(); } catch(e) {}
    }
    if (browser) {
      await browser.close();
      console.log('🔒 Browser closed.\n');
    }
  }
}

async function runDualMode(url) {
  console.log('\n' + '🔄 DUAL MODE — Running both STEALTH and OBSERVE scans...\n');

  let stealthResult, observeResult;

  try {
    stealthResult = await runScan(url, { stealth: true });
  } catch (e) {
    console.error('Stealth scan failed:', e.message);
  }

  try {
    observeResult = await runScan(url, { stealth: false });
  } catch (e) {
    console.error('Observe scan failed:', e.message);
  }

  if (stealthResult && observeResult) {
    const s = stealthResult.reportJson;
    const o = observeResult.reportJson;

    console.log('\n' + '═'.repeat(65));
    console.log('  📊 DUAL MODE FORENSIC COMPARISON');
    console.log('═'.repeat(65));
    console.log(`  ${'Metric'.padEnd(25)} ${'STEALTH'.padEnd(15)} ${'OBSERVE'.padEnd(15)}`);
    console.log(`  ${'─'.repeat(55)}`);
    console.log(`  ${'Risk Score'.padEnd(25)} ${String(s.riskScore).padEnd(15)} ${String(o.riskScore).padEnd(15)}`);
    console.log(`  ${'Total Events'.padEnd(25)} ${String(s.totalEvents).padEnd(15)} ${String(o.totalEvents).padEnd(15)}`);
    console.log(`  ${'Categories'.padEnd(25)} ${String(s.categoriesDetected + '/' + s.categoriesMonitored).padEnd(15)} ${String(o.categoriesDetected + '/' + o.categoriesMonitored).padEnd(15)}`);
    console.log(`  ${'Origins'.padEnd(25)} ${String(s.uniqueOrigins.length).padEnd(15)} ${String(o.uniqueOrigins.length).padEnd(15)}`);
    console.log(`  ${'Threats'.padEnd(25)} ${String(s.threats.length).padEnd(15)} ${String(o.threats.length).padEnd(15)}`);
    console.log(`  ${'Coverage'.padEnd(25)} ${String((s.coverageProof?.coverage || 0) + '%').padEnd(15)} ${String((o.coverageProof?.coverage || 0) + '%').padEnd(15)}`);
    console.log(`  ${'FP Bursts'.padEnd(25)} ${String(s.correlation?.summary?.fingerprintBursts || 0).padEnd(15)} ${String(o.correlation?.summary?.fingerprintBursts || 0).padEnd(15)}`);
    console.log(`  ${'Libraries'.padEnd(25)} ${String(s.correlation?.summary?.identifiedLibraries?.join(', ') || 'none').padEnd(15)} ${String(o.correlation?.summary?.identifiedLibraries?.join(', ') || 'none').padEnd(15)}`);

    const sCats = new Set(Object.keys(s.byCategory));
    const oCats = new Set(Object.keys(o.byCategory));
    const onlyInStealth = [...sCats].filter(c => !oCats.has(c));
    const onlyInObserve = [...oCats].filter(c => !sCats.has(c));

    if (onlyInStealth.length > 0) {
      console.log(`\n  📌 Only in STEALTH: ${onlyInStealth.join(', ')}`);
    }
    if (onlyInObserve.length > 0) {
      console.log(`  📌 Only in OBSERVE: ${onlyInObserve.join(', ')}`);
    }

    const delta = s.totalEvents - o.totalEvents;
    if (Math.abs(delta) > 50) {
      console.log(`\n  ⚠️  Significant delta: ${delta > 0 ? '+' : ''}${delta} events`);
      console.log('     Website likely behaves differently based on automation detection.');
    }

    // Coverage comparison
    if ((s.coverageProof?.coverage || 0) !== (o.coverageProof?.coverage || 0)) {
      console.log(`\n  📡 Coverage difference detected — stealth may bypass iframe restrictions`);
    }

    console.log('\n' + '═'.repeat(65));
  }
}

// ── Main ──
(async () => {
  console.log(`
  ╔══════════════════════════════════════════════════════════╗
  ║   🛡️  SENTINEL v4.0 — FORENSIC MALING CATCHER           ║
  ║   7-Layer Architecture | 31 API Categories               ║
  ║   Value Capture | Stack Trace | 1H5W Framework           ║
  ║   Anti-Detection Shield | Burst Analysis | Attribution   ║
  ╚══════════════════════════════════════════════════════════╝
  `);

  if (!targetUrl) {
    targetUrl = await prompt('🎯 Target website (e.g. browserscan.net): ');
  }

  if (!targetUrl) {
    console.log('No target specified. Exiting.');
    process.exit(1);
  }

  const url = normalizeUrl(targetUrl);

  if (DUAL_MODE) {
    await runDualMode(url);
  } else {
    await runScan(url, { stealth: STEALTH_MODE });
  }
})();
