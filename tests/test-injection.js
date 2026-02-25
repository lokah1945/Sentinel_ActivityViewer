// ═══════════════════════════════════════════════════════════════
//  SENTINEL v5.0.0 — INJECTION DIAGNOSTIC TEST
//  Quick test: launches browser, injects scripts, checks status
// ═══════════════════════════════════════════════════════════════

var { chromium } = require('playwright');
var { generateShieldScript } = require('../hooks/anti-detection-shield');
var { generateStealthScript } = require('../hooks/stealth-config');
var { generateInterceptorScript } = require('../hooks/api-interceptor');
var path = require('path');
var os = require('os');
var fs = require('fs');
var crypto = require('crypto');

var TARGET = process.argv[2] || 'https://www.browserscan.net';

async function runTest() {
  var profileDir = path.join(os.tmpdir(), 'sentinel-test-' + crypto.randomBytes(4).toString('hex'));
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

  process.stderr.write('\n🛡️  SENTINEL v5.0.0 — INJECTION DIAGNOSTIC\n');
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

  process.stderr.write('  ACTIVE:          ' + (status.ACTIVE ? '✅ YES' : '❌ NO') + '\n');
  process.stderr.write('  VERSION:         ' + status.VERSION + '\n');
  process.stderr.write('  SHIELD:          ' + (status.SHIELD ? '✅ YES' : '❌ NO') + '\n');
  process.stderr.write('  BOOT_OK:         ' + (status.BOOT_OK ? '✅ YES' : '❌ NO') + '\n');
  process.stderr.write('  EVENTS:          ' + status.EVENTS + '\n');
  process.stderr.write('  CATEGORIES:      ' + status.CATEGORIES + '\n');
  process.stderr.write('  WEBDRIVER:       ' + (status.WEBDRIVER ? '❌ EXPOSED' : '✅ HIDDEN') + '\n');
  process.stderr.write('  CHROME.RUNTIME:  ' + (status.CHROME_RUNTIME ? '✅ PRESENT' : '⚠️ MISSING') + '\n');
  process.stderr.write('  ENUMERABLE:      ' + (status.ENUMERABLE_SENTINEL.length === 0 ? '✅ QUIET MODE' : '❌ ' + status.ENUMERABLE_SENTINEL.join(', ')) + '\n');

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
