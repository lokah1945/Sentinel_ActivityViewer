// Sentinel v4.4.2 — Injection Diagnostic Tool
// Quick test to verify all injection layers work

const path = require('path');
const { getAntiDetectionScript } = require('./hooks/anti-detection-shield');
const { getApiInterceptorScript } = require('./hooks/api-interceptor');
const { getStealthPatches } = require('./hooks/stealth-config');

const targetUrl = process.argv[2] || 'https://browserscan.net';

async function testInjection() {
  console.log('🔍 Sentinel v4.4.2 — Injection Test\n');
  console.log(`Target: ${targetUrl}\n`);

  let chromium;
  try {
    chromium = require('playwright-extra').chromium;
    const stealth = require('puppeteer-extra-plugin-stealth')();
    stealth.enabledEvasions.delete('iframe.contentWindow');
    chromium.use(stealth);
    console.log('✓ Using playwright-extra + stealth');
  } catch(e) {
    chromium = require('playwright').chromium;
    console.log('⚠ Using vanilla Playwright (no stealth plugin)');
  }

  const browser = await chromium.launch({
    headless: false,
    args: ['--disable-blink-features=AutomationControlled', '--no-sandbox'],
    ignoreDefaultArgs: ['--enable-automation']
  });

  const context = await browser.newContext({
    locale: 'id-ID',
    timezoneId: 'Asia/Jakarta',
    viewport: { width: 1920, height: 1080 }
  });

  const page = await context.newPage();

  // Inject all layers
  const payload = [
    getAntiDetectionScript(),
    getStealthPatches(),
    getApiInterceptorScript()
  ].join('\n');

  await page.addInitScript(payload);
  console.log('✓ Init scripts registered\n');

  // Navigate
  console.log(`Navigating to ${targetUrl}...`);
  await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(5000);

  // Check injection
  const result = await page.evaluate(() => {
    return {
      ACTIVE: !!window.__SENTINEL_ACTIVE,
      SHIELD: !!window.__SENTINEL_SHIELD,
      DATA: !!window.__SENTINEL_DATA,
      eventCount: window.__SENTINEL_DATA ? window.__SENTINEL_DATA.events.length : 0,
      bootOk: window.__SENTINEL_DATA ? window.__SENTINEL_DATA.events.filter(e => e.api === 'BOOT_OK').length : 0,
      categories: window.__SENTINEL_DATA ? [...new Set(window.__SENTINEL_DATA.events.map(e => e.cat))].join(', ') : 'none'
    };
  });

  console.log('\n═══════════════════════════════════════');
  console.log('  INJECTION TEST RESULTS');
  console.log('═══════════════════════════════════════');
  console.log(`  __SENTINEL_ACTIVE:  ${result.ACTIVE ? '✅ YES' : '❌ NO'}`);
  console.log(`  __SENTINEL_SHIELD:  ${result.SHIELD ? '✅ YES' : '❌ NO'}`);
  console.log(`  __SENTINEL_DATA:    ${result.DATA ? '✅ YES' : '❌ NO'}`);
  console.log(`  Events captured:    ${result.eventCount}`);
  console.log(`  BOOT_OK count:      ${result.bootOk}`);
  console.log(`  Active categories:  ${result.categories}`);
  console.log('═══════════════════════════════════════');

  if (result.ACTIVE && result.eventCount > 0) {
    console.log('\n✅ INJECTION WORKING — Ready for full scan!');
  } else {
    console.log('\n❌ INJECTION FAILED — Check console errors in browser');
    console.log('   Keeping browser open for 30s for debugging...');
    await page.waitForTimeout(30000);
  }

  await browser.close();
}

testInjection().catch(e => {
  console.error('Test failed:', e.message);
  process.exit(1);
});
