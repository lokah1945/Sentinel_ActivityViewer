#!/usr/bin/env node
/**
 * Sentinel v4.4.1 — Injection Diagnostic Test
 * Quick test to verify hooks are active in page context
 * Run: node test-injection.js [url]
 */

const { chromium } = require('playwright');
const { getAntiDetectionScript } = require('./hooks/anti-detection-shield');
const { getInterceptorScript } = require('./hooks/api-interceptor');

async function test(url) {
  url = url || 'https://example.com';
  console.log('\n🧪 Sentinel v4.4.1 Injection Test');
  console.log('Target:', url);
  console.log('');

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    locale: 'id-ID',
    timezoneId: 'Asia/Jakarta'
  });
  const page = await context.newPage();

  // Inject via addInitScript (PRIMARY method)
  await page.addInitScript(getAntiDetectionScript());
  await page.addInitScript(getInterceptorScript({ timeout: 10000 }));

  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
  await page.waitForTimeout(5000);

  // Diagnostic checks
  const diag = await page.evaluate(() => {
    return {
      SENTINEL_ACTIVE: !!window.__SENTINEL_ACTIVE__,
      SENTINEL_SHIELD: !!window.__SENTINEL_SHIELD__,
      SENTINEL_DATA: !!window.__SENTINEL_DATA__,
      SENTINEL_FLUSH: typeof window.__SENTINEL_FLUSH__ === 'function',
      bootOk: window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.bootOk : false,
      frameId: window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.frameId : 'N/A',
      eventCount: window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.events.length : 0,
      categories: window.__SENTINEL_DATA__ ? 
        [...new Set(window.__SENTINEL_DATA__.events.map(e => e.cat))].sort() : []
    };
  });

  console.log('┌─────────────────────────────────────┐');
  console.log('│  INJECTION DIAGNOSTIC RESULTS         │');
  console.log('├─────────────────────────────────────┤');
  console.log(`│  __SENTINEL_ACTIVE__:  ${diag.SENTINEL_ACTIVE ? '✅ YES' : '❌ NO'}`);
  console.log(`│  __SENTINEL_SHIELD__:  ${diag.SENTINEL_SHIELD ? '✅ YES' : '❌ NO'}`);
  console.log(`│  __SENTINEL_DATA__:    ${diag.SENTINEL_DATA ? '✅ YES' : '❌ NO'}`);
  console.log(`│  __SENTINEL_FLUSH__:   ${diag.SENTINEL_FLUSH ? '✅ YES' : '❌ NO'}`);
  console.log(`│  bootOk:               ${diag.bootOk ? '✅ YES' : '❌ NO'}`);
  console.log(`│  frameId:              ${diag.frameId}`);
  console.log(`│  Events captured:      ${diag.eventCount}`);
  console.log(`│  Categories active:    ${diag.categories.length}`);
  if (diag.categories.length > 0) {
    console.log(`│  Categories: ${diag.categories.join(', ')}`);
  }
  console.log('└─────────────────────────────────────┘');

  if (diag.SENTINEL_ACTIVE && diag.bootOk && diag.eventCount > 0) {
    console.log('\n✅ PASS — Sentinel v4.4.1 injection is working correctly!');
  } else {
    console.log('\n❌ FAIL — Injection problem detected. Check output above.');
  }

  await browser.close();
}

const testUrl = process.argv[2] || 'https://browserscan.net';
test(testUrl).catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
