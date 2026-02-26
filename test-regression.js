#!/usr/bin/env node
/**
 * Sentinel v6.3.0 — Regression Test
 */

'use strict';

process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE = 'addBinding';
process.env.REBROWSER_PATCHES_SOURCE_URL = 'analytics.js';

const { addExtra } = require('playwright-extra');
const playwrightCore = require('playwright-core');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

const { EventPipeline } = require('./lib/event-pipeline');

const chromium = addExtra(playwrightCore.chromium);
chromium.use(StealthPlugin());

let passed = 0, failed = 0;
function ok(cond, name) {
  if (cond) { console.log(`  ✅ ${name}`); passed++; }
  else { console.log(`  ❌ ${name}`); failed++; }
}

(async () => {
  console.log('\n🧪 Sentinel v6.3.0 Regression Tests\n');

  // Pipeline tests
  console.log('─── EventPipeline ───');
  const p = new EventPipeline();
  p.pushCdp({ cat: 'test', api: 'a', risk: 'low', detail: 'hello' });
  p.pushCdp({ cat: 'test', api: 'a', risk: 'low', detail: 'hello' });
  p.pushCdp({ cat: 'test', api: 'b', risk: 'low', detail: 'world' });
  p.pushCdp({ cat: 'network-response', api: '200', risk: 'info', detail: '200 test' });
  ok(p.drain().length === 3, 'Dedup: 3 unique from 4 pushes');
  ok(p.getStats().networkEntries === 1, 'Network counter works');

  // Browser launch
  console.log('\n─── Browser Launch (rebrowser-playwright-core) ───');
  let browser;
  try {
    browser = await chromium.launch({
      headless: true,
      args: ['--disable-blink-features=AutomationControlled', '--no-sandbox'],
      ignoreDefaultArgs: ['--enable-automation'],
    });
    ok(true, 'Browser launched with rebrowser-playwright-core');

    const ctx = await browser.newContext({ viewport: null });
    const page = await ctx.newPage();

    // CDP session
    const cdp = await ctx.newCDPSession(page);
    ok(!!cdp, 'CDP session created');

    // Network.enable
    await cdp.send('Network.enable');
    ok(true, 'Network.enable works');

    // Navigate
    await page.goto('data:text/html,<h1>Test</h1><iframe src="data:text/html,<p>inner</p>"></iframe>');
    await page.waitForTimeout(1000);

    // Webdriver check
    const wd = await page.evaluate(() => navigator.webdriver);
    ok(wd === undefined || wd === false, `navigator.webdriver = ${wd}`);

    // Frame check
    ok(page.frames().length >= 2, `Frames: ${page.frames().length}`);

    // Target.setAutoAttach
    await cdp.send('Target.setAutoAttach', {
      autoAttach: true, waitForDebuggerOnStart: false, flatten: true
    });
    ok(true, 'Target.setAutoAttach works');

    // Page.enable
    await cdp.send('Page.enable');
    ok(true, 'Page.enable works');

    // Security.enable
    await cdp.send('Security.enable');
    ok(true, 'Security.enable works');

    await browser.close();
  } catch (e) {
    console.log(`  ❌ Browser test error: ${e.message}`);
    failed++;
    if (browser) await browser.close().catch(() => {});
  }

  console.log(`\n${'═'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log(`${'═'.repeat(40)}\n`);
  process.exit(failed > 0 ? 1 : 0);
})();
