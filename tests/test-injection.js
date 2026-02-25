// ═══════════════════════════════════════════════════════════════
//  SENTINEL v6.1.0 — INJECTION DIAGNOSTIC
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.1.0 (2026-02-25):
//   FROM v5.0.0:
//   - CHANGED: require('playwright') → require('playwright-extra')
//   - ADDED: CDPNetworkCollector injection check
//   - ADDED: CDPSecurityCollector injection check
//   - ADDED: EventPipeline stats output
//   - KEPT: All original injection checks (ACTIVE, SHIELD, BOOT_OK, WEBDRIVER, etc.)
//
// LAST HISTORY LOG:
//   v5.0.0: 9 checks (ACTIVE, VERSION, SHIELD, BOOT_OK, EVENTS, CATEGORIES, WEBDRIVER, CHROME_RUNTIME, ENUMERABLE)
//   v6.1.0: Patchright + CDP collector verification
// ═══════════════════════════════════════════════════════════════

var { chromium } = require('playwright-extra');
var fs = require('fs');
var path = require('path');
var os = require('os');
var { generateShieldScript } = require('../hooks/anti-detection-shield');
var { generateStealthScript } = require('../hooks/stealth-config');
var { generateInterceptorScript } = require('../hooks/api-interceptor');
var { EventPipeline } = require('../lib/event-pipeline');
var { CDPNetworkCollector } = require('../collectors/cdp-network-collector');
var { CDPSecurityCollector } = require('../collectors/cdp-security-collector');

var TARGET = process.argv[2] || 'https://www.browserscan.net';

async function runTest() {
  var profileDir = path.join(os.tmpdir(), 'sentinel-test-' + Date.now());
  fs.mkdirSync(profileDir, { recursive: true });

  var context = await chromium.launchPersistentContext(profileDir, {
    headless: true,
    args: ['--disable-blink-features=AutomationControlled', '--use-gl=desktop'],
    ignoreDefaultArgs: ['--enable-automation']
  });

  var page = context.pages()[0] || await context.newPage();

  var shield = generateShieldScript();
  var stealth = generateStealthScript();
  var interceptor = generateInterceptorScript();

  await page.addInitScript({ content: shield });
  await page.addInitScript({ content: stealth });
  await page.addInitScript({ content: interceptor });

  // CDP collectors
  var cdp = await context.newCDPSession(page);
  var pipeline = new EventPipeline({ maxEvents: 50000 });
  var networkCollector = new CDPNetworkCollector(cdp, pipeline, { verbose: false });
  await networkCollector.initialize();
  var securityCollector = new CDPSecurityCollector(cdp, pipeline, { verbose: false });
  await securityCollector.initialize();

  process.stderr.write('\n🛡️  SENTINEL v6.1.0 — INJECTION DIAGNOSTIC\n');
  process.stderr.write('   Target: ' + TARGET + '\n\n');

  await page.goto(TARGET, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(5000);

  var status = await page.evaluate(function() {
    return {
      ACTIVE: !!window.__SENTINEL_DATA__,
      VERSION: window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.version : 'N/A',
      SHIELD: !!window.__SENTINEL_SHIELD__,
      EVENTS: window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.events.length : 0,
      CATEGORIES: window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.categoriesMonitored : 0,
      BOOT_OK: window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.events.some(function(e) { return e.api === 'BOOT_OK'; }) : false,
      WEBDRIVER: navigator.webdriver,
      CHROME_RUNTIME: !!window.chrome && !!window.chrome.runtime,
      ENUMERABLE_SENTINEL: Object.keys(window).filter(function(k) { return k.indexOf('SENTINEL') >= 0; })
    };
  });

  var pipelineStats = pipeline.getStats();

  process.stderr.write('  ACTIVE:          ' + (status.ACTIVE ? '✅ YES' : '❌ NO') + '\n');
  process.stderr.write('  VERSION:         ' + status.VERSION + '\n');
  process.stderr.write('  SHIELD:          ' + (status.SHIELD ? '✅ YES' : '❌ NO') + '\n');
  process.stderr.write('  BOOT_OK:         ' + (status.BOOT_OK ? '✅ YES' : '❌ NO') + '\n');
  process.stderr.write('  EVENTS:          ' + status.EVENTS + '\n');
  process.stderr.write('  CATEGORIES:      ' + status.CATEGORIES + '\n');
  process.stderr.write('  WEBDRIVER:       ' + (status.WEBDRIVER ? '❌ EXPOSED' : '✅ HIDDEN') + '\n');
  process.stderr.write('  CHROME.RUNTIME:  ' + (status.CHROME_RUNTIME ? '✅ PRESENT' : '⚠️ MISSING') + '\n');
  process.stderr.write('  ENUMERABLE:      ' + (status.ENUMERABLE_SENTINEL.length === 0 ? '✅ QUIET MODE' : '❌ ' + status.ENUMERABLE_SENTINEL.join(', ')) + '\n');
  process.stderr.write('  CDP_PIPELINE:    ' + pipelineStats.total + ' events, ' + Object.keys(pipelineStats.categories).length + ' categories\n');

  var allOk = status.ACTIVE && status.SHIELD && status.BOOT_OK && !status.WEBDRIVER && status.ENUMERABLE_SENTINEL.length === 0;
  process.stderr.write('\n' + (allOk ? '✅ ALL CHECKS PASSED' : '❌ SOME CHECKS FAILED') + '\n');

  await context.close();
  try { fs.rmSync(profileDir, { recursive: true, force: true }); } catch(e) {}

  process.exit(allOk ? 0 : 1);
}

runTest().catch(function(e) {
  process.stderr.write('Test error: ' + e.message + '\n');
  process.exit(1);
});
