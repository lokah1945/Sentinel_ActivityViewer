#!/usr/bin/env node
/**
 * ╔═══════════════════════════════════════════════════════╗
 * ║   SENTINEL v3.0 — MALING CATCHER                     ║
 * ║   Browser Activity Viewer with Stealth Mode           ║
 * ╚═══════════════════════════════════════════════════════╝
 *
 * Usage:
 *   node index.js                        — Interactive mode
 *   node index.js <url>                  — Quick scan
 *   node index.js <url> --stealth        — Stealth mode (default)
 *   node index.js <url> --observe        — Observe mode (no stealth)
 *   node index.js <url> --dual-mode      — Run BOTH modes & compare
 *   node index.js <url> --timeout=45000  — Custom timeout (ms)
 *   node index.js <url> --headless       — Headless mode
 */

const { createStealthPlugin, getExtraStealthScript } = require('./hooks/stealth-config');
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
const STEALTH_MODE = flags.observe ? false : true; // stealth is default

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

async function runScan(url, options = {}) {
  const stealthEnabled = options.stealth !== false;
  const label = stealthEnabled ? '🥷 STEALTH' : '👁️ OBSERVE';

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  ${label} MODE — Scanning: ${url}`);
  console.log(`  Timeout: ${TIMEOUT / 1000}s | Headless: ${HEADLESS}`);
  console.log(`${'═'.repeat(60)}\n`);

  let browser, page;

  try {
    if (stealthEnabled) {
      // Use playwright-extra with stealth
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

      // Inject extra stealth BEFORE any page load
      await page.addInitScript(getExtraStealthScript());

    } else {
      // Plain playwright — observe mode (more detectable, shows raw behavior)
      const { chromium } = require('playwright');

      browser = await chromium.launch({
        headless: HEADLESS,
      });

      const context = await browser.newContext({
        viewport: { width: 1920, height: 1080 },
      });

      page = await context.newPage();
    }

    // Inject API interceptor BEFORE page navigation
    await page.addInitScript(getInterceptorScript({ timeout: TIMEOUT }));

    // Also inject into all frames
    page.on('frameattached', async (frame) => {
      try {
        await frame.evaluate(getInterceptorScript({ timeout: TIMEOUT }));
      } catch (e) { /* cross-origin frames will fail — expected */ }
    });

    console.log('🌐 Navigating to target...');
    await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: TIMEOUT
    });

    console.log('⏳ Observing activity...');

    // Wait for the configured timeout to collect events
    const observeTime = Math.max(TIMEOUT - 5000, 10000);
    await page.waitForTimeout(observeTime);

    // Scroll to trigger lazy-loaded fingerprinting scripts
    await page.evaluate(() => {
      window.scrollTo(0, document.body.scrollHeight / 2);
    });
    await page.waitForTimeout(3000);

    // Collect results
    console.log('📊 Collecting results...');

    const sentinelData = await page.evaluate(() => {
      return window.__SENTINEL_DATA__ || { events: [] };
    });

    const contextMap = await page.evaluate(() => {
      return window.__SENTINEL_CONTEXT_MAP__ || [];
    });

    // Also collect frame information
    const frames = page.frames();
    const frameInfo = frames.map(f => ({
      type: 'frame',
      url: f.url(),
      name: f.name() || '',
    }));

    const fullContextMap = [...(contextMap || []), ...frameInfo];

    console.log(`\n✅ Scan complete! Captured ${sentinelData.events?.length || 0} events\n`);

    // Generate report
    const reportResult = generateReport(sentinelData, fullContextMap, url, {
      stealthEnabled,
      prefix: `sentinel_${stealthEnabled ? 'stealth' : 'observe'}_${Date.now()}`
    });

    // Print summary
    const r = reportResult.reportJson;
    console.log('┌─────────────────────────────────────────┐');
    console.log(`│  Risk Score: ${r.riskScore}/100 ${r.riskLevel.padEnd(15)} │`);
    console.log(`│  Events: ${String(r.totalEvents).padEnd(10)} Categories: ${String(r.categoriesDetected).padEnd(4)}│`);
    console.log(`│  Origins: ${String(r.uniqueOrigins.length).padEnd(9)} Threats: ${String(r.threats.length).padEnd(6)}│`);
    console.log('└─────────────────────────────────────────┘');

    if (r.threats.length > 0) {
      console.log('\n🚨 THREATS DETECTED:');
      for (const t of r.threats) {
        const icon = t.severity === 'CRITICAL' ? '🔴' : t.severity === 'HIGH' ? '🟡' : '🔵';
        console.log(`  ${icon} [${t.severity}] ${t.type}`);
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
    throw err;
  } finally {
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

    console.log('\n' + '═'.repeat(60));
    console.log('  📊 DUAL MODE COMPARISON');
    console.log('═'.repeat(60));
    console.log(`  ${'Metric'.padEnd(25)} ${'STEALTH'.padEnd(15)} ${'OBSERVE'.padEnd(15)}`);
    console.log(`  ${'─'.repeat(55)}`);
    console.log(`  ${'Risk Score'.padEnd(25)} ${String(s.riskScore).padEnd(15)} ${String(o.riskScore).padEnd(15)}`);
    console.log(`  ${'Total Events'.padEnd(25)} ${String(s.totalEvents).padEnd(15)} ${String(o.totalEvents).padEnd(15)}`);
    console.log(`  ${'Categories'.padEnd(25)} ${String(s.categoriesDetected).padEnd(15)} ${String(o.categoriesDetected).padEnd(15)}`);
    console.log(`  ${'Origins'.padEnd(25)} ${String(s.uniqueOrigins.length).padEnd(15)} ${String(o.uniqueOrigins.length).padEnd(15)}`);
    console.log(`  ${'Threats'.padEnd(25)} ${String(s.threats.length).padEnd(15)} ${String(o.threats.length).padEnd(15)}`);

    // Show categories unique to each mode
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
      console.log(`     Website likely behaves differently based on automation detection.`);
    }

    console.log('\n' + '═'.repeat(60));
  }
}

// ── Main ──
(async () => {
  console.log(`
  ╔═══════════════════════════════════════════════════╗
  ║   🛡️  SENTINEL v3.0 — MALING CATCHER             ║
  ║   Browser Activity Viewer with Stealth Mode       ║
  ║   18 API categories | Threat detection            ║
  ╚═══════════════════════════════════════════════════╝
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
