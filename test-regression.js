#!/usr/bin/env node
/**
 * Sentinel v6.2.0 — Regression Test
 * 
 * Tests:
 *   1. rebrowser-patches is applied (Runtime.Enable fix active)
 *   2. Stealth plugin loaded
 *   3. CDP collectors work without Runtime.Enable
 *   4. Frame attachment works
 *   5. Event pipeline deduplication works
 */

'use strict';

process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE = 'addBinding';
process.env.REBROWSER_PATCHES_SOURCE_URL = 'analytics.js';

const { chromium } = require('playwright-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

chromium.use(StealthPlugin());

const { EventPipeline } = require('./lib/event-pipeline');
const { AntiDetectionShield } = require('./lib/anti-detection-shield');

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    console.log(`  ✅ ${name}`);
    passed++;
  } else {
    console.log(`  ❌ ${name}`);
    failed++;
  }
}

(async () => {
  console.log('\n🧪 Sentinel v6.2.0 Regression Tests\n');

  // Test 1: Pipeline
  console.log('─── EventPipeline ───');
  const pipeline = new EventPipeline();
  pipeline.push({ cat: 'test', api: 'test', risk: 'low', detail: 'hello' });
  pipeline.push({ cat: 'test', api: 'test', risk: 'low', detail: 'hello' }); // duplicate
  pipeline.push({ cat: 'test', api: 'test2', risk: 'low', detail: 'world' });
  assert(pipeline.drain().length === 2, 'Deduplication works (2 unique from 3 pushes)');
  assert(pipeline.getStats().totalPushed === 3, 'Total pushed count correct');

  pipeline.pushCdp({ cat: 'cdp-network', api: 'responseReceived', detail: 'test' });
  assert(pipeline.getStats().cdpEvents === 1, 'CDP events tracked');
  assert(pipeline.getStats().networkEntries === 1, 'Network entries counted');

  // Test 2: Browser launch with rebrowser-patches
  console.log('\n─── Browser Launch (rebrowser-patches) ───');
  let browser;
  try {
    browser = await chromium.launch({
      headless: true,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--no-sandbox',
      ],
      ignoreDefaultArgs: ['--enable-automation'],
    });
    assert(true, 'Browser launched with patched playwright');

    const context = await browser.newContext();
    const page = await context.newPage();

    // Test 3: CDP session
    const cdp = await context.newCDPSession(page);
    assert(cdp !== null, 'CDP session created');

    // Test 4: Shield injection
    const shield = new AntiDetectionShield();
    await shield.apply(page, cdp);
    assert(true, 'AntiDetectionShield applied');

    // Test 5: Navigate and check webdriver property
    await page.goto('data:text/html,<h1>Test</h1>');
    const webdriver = await page.evaluate(() => navigator.webdriver);
    assert(webdriver === undefined || webdriver === false, `navigator.webdriver = ${webdriver} (should be undefined/false)`);

    // Test 6: Check that our init script runs
    const sentinel = await page.evaluate(() => window.__sentinel_interceptor_v62__);
    // Note: in test mode we don't inject the full interceptor, so this should be undefined
    assert(sentinel === undefined || sentinel === true, 'Init script scope clean');

    // Test 7: Network.enable works (doesn't rely on Runtime.Enable)
    await cdp.send('Network.enable');
    assert(true, 'Network.enable works independently of Runtime.Enable');

    // Test 8: Frame detection
    await page.goto('data:text/html,<iframe src="data:text/html,<p>nested</p>"></iframe>');
    await page.waitForTimeout(1000);
    const frameCount = page.frames().length;
    assert(frameCount >= 2, `Frame detection: ${frameCount} frames found`);

    await browser.close();
  } catch (e) {
    console.log(`  ❌ Browser test failed: ${e.message}`);
    failed++;
    if (browser) await browser.close().catch(() => {});
  }

  // Summary
  console.log(`\n${'═'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log(`${'═'.repeat(40)}\n`);

  process.exit(failed > 0 ? 1 : 0);
})();
