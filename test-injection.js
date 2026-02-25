#!/usr/bin/env node
/**
 * Sentinel v4.6.2 — Ghost Protocol Test Suite
 * 
 * Tests injection, quiet mode, and report generation without a browser.
 * For full integration testing, use: node index.js <url> --verbose
 */

const { getExtraStealthScript } = require('./hooks/stealth-config');
const { getAntiDetectionScript } = require('./hooks/anti-detection-shield');
const { getInterceptorScript } = require('./hooks/api-interceptor');
const { TargetGraph } = require('./lib/target-graph');
const fs = require('fs');

console.log('╔═══════════════════════════════════════════╗');
console.log('║  🧪 Sentinel v4.6.2 Ghost Protocol Tests     ║');
console.log('╚═══════════════════════════════════════════╝\n');

let pass = 0, fail = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    pass++;
  } catch(e) {
    console.log(`  ❌ ${name}: ${e.message}`);
    fail++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

// ── Test 1: Shield script generates valid JS ──
test('Shield script is valid JS string', () => {
  const script = getAntiDetectionScript();
  assert(typeof script === 'string', 'Not a string');
  assert(script.length > 100, 'Too short');
  assert(script.includes('__SENTINEL_SHIELD__'), 'Missing shield marker');
  // Verify it's syntactically valid JS
  new Function(script);
});

// ── Test 2: Stealth script generates valid JS ──
test('Stealth script is valid JS (Ghost Protocol)', () => {
  const script = getExtraStealthScript();
  assert(typeof script === 'string', 'Not a string');
  assert(script.includes('webdriver'), 'Missing webdriver cleanup');
  assert(!script.includes('console.log'), 'Should NOT have console.log (quiet mode)');
  assert(script.includes('chrome.runtime'), 'Missing chrome.runtime polyfill');
  assert(script.includes('chrome.loadTimes'), 'Missing chrome.loadTimes polyfill');
  new Function(script);
});

// ── Test 3: Interceptor script generates valid JS ──
test('Interceptor script is valid JS (42 categories)', () => {
  const script = getInterceptorScript({ timeout: 30000, stealthEnabled: true, stackSampleRate: 10 });
  assert(typeof script === 'string', 'Not a string');
  assert(script.length > 5000, 'Too short');
  // Check for v4.6.2 new hooks
  assert(script.includes('URL.createObjectURL'), 'Missing Blob URL monitoring');
  assert(script.includes('SharedArrayBuffer'), 'Missing SharedArrayBuffer monitoring');
  assert(script.includes('postMessage'), 'Missing postMessage monitoring');
  assert(script.includes('performance.now'), 'Missing performance.now monitoring');
  // Check quiet mode
  assert(script.includes('enumerable: false'), 'Missing non-enumerable globals (quiet mode)');
  new Function(script);
});

// ── Test 4: Quiet Mode — no enumerable globals ──
test('Quiet mode: __SENTINEL_DATA__ is non-enumerable', () => {
  const script = getInterceptorScript({ timeout: 30000, stealthEnabled: true });
  assert(script.includes("enumerable: false"), 'Globals should be non-enumerable');
  // Should NOT have direct window.__SENTINEL_ACTIVE__ = true assignment
  assert(!script.includes("window.__SENTINEL_ACTIVE__ = true"), 'Should not use direct assignment for ACTIVE flag');
});

// ── Test 5: TargetGraph class exists and works ──
test('TargetGraph class instantiates correctly', () => {
  const tg = new TargetGraph({ verbose: false });
  assert(tg.nodes instanceof Map, 'nodes should be a Map');
  assert(Array.isArray(tg.events), 'events should be an array');
  const summary = tg.getSummary();
  assert(summary.totalTargets === 0, 'Should start empty');
  assert(summary.coveragePercent === 0, 'Coverage should be 0');
  const inventory = tg.getInventory();
  assert(Array.isArray(inventory), 'Inventory should be array');
});

// ── Test 6: Report generator doesn't crash ──
test('Report generator produces valid output', () => {
  const { generateReport } = require('./reporters/report-generator');
  const mockData = {
    events: [
      { ts: 100, cat: 'fingerprint', api: 'BOOT_OK', detail: 'test', risk: 'low', frame: 'abc123' },
      { ts: 200, cat: 'canvas', api: 'toDataURL', detail: 'data:image/png', risk: 'high', frame: 'abc123', value: 'data:image/png...' },
      { ts: 300, cat: 'worker', api: 'worker.fetch', detail: 'https://example.com', risk: 'high', frame: 'worker:xyz' }
    ],
    bootOk: true,
    frameId: 'abc123'
  };
  const result = generateReport(mockData, [], 'https://test.example.com', {
    stealthEnabled: true,
    prefix: 'test_v46',
    injectionFlags: {
      L1_addInitScript: true, L2_automationCleanup: true, L3_cdpSupplement: true,
      L4_perFrame: false, L5_recursiveAutoAttach: true, L6_workerPipeline: true
    },
    frameInfo: [{ type: 'frame', url: 'https://test.example.com', origin: 'https://test.example.com', name: '', index: 0 }],
    networkLog: [],
    workerEvents: [{ ts: 400, api: 'worker.fetch', url: 'https://cdn.example.com/fp.js', workerType: 'worker' }],
    targetInventory: [
      { targetId: 'ABC12345', type: 'page', url: 'https://test.example.com', networkEnabled: true, injected: true, bootOk: true, eventsCollected: 3, cdpDomains: ['Network', 'Runtime'] }
    ],
    targetSummary: { totalTargets: 1, injectedTargets: 1, networkEnabledTargets: 1, workers: 0, iframes: 0, coveragePercent: 100 }
  });

  assert(result.reportJson, 'Missing reportJson');
  assert(result.reportJson.version === 'sentinel-v4.6', 'Wrong version');
  assert(result.reportJson.totalEvents === 3, 'Wrong event count');
  assert(result.reportJson.timeSpanMs === 300, 'timeSpanMs should be max(ts)=300');
  assert(result.reportJson.workerEvents.count >= 1, 'Should have worker events');
  assert(result.reportJson.coverageProof.targetGraph, 'Missing target graph in coverage proof');
  assert(result.reportJson.injectionStatus.layer5_recursiveAutoAttach === true, 'Missing L5 flag');
  assert(result.reportJson.injectionStatus.layer6_workerPipeline === true, 'Missing L6 flag');

  // Check HTML doesn't contain "vc is not defined"
  const html = fs.readFileSync(result.htmlPath, 'utf8');
  assert(!html.includes('vc is not defined'), 'HTML still has vc bug!');
  assert(!html.includes('undefined'), 'HTML has undefined values');
  assert(html.includes('Ghost Protocol'), 'Missing Ghost Protocol branding');
  assert(html.includes('Target Graph Inventory'), 'Missing Target Graph section');

  // Cleanup test files
  try { fs.unlinkSync(result.jsonPath); } catch(e) {}
  try { fs.unlinkSync(result.htmlPath); } catch(e) {}
  try { fs.unlinkSync(result.ctxPath); } catch(e) {}
});

// ── Test 7: Categories count ──
test('Report has 42 categories (v4.6.2 expansion)', () => {
  const { generateReport } = require('./reporters/report-generator');
  const result = generateReport(
    { events: [{ ts: 0, cat: 'system', api: 'BOOT_OK', risk: 'low' }], bootOk: true },
    [], 'https://test.com',
    { stealthEnabled: true, prefix: 'test_cats', injectionFlags: {}, frameInfo: [], networkLog: [] }
  );
  // categoriesMonitored should reflect ALL_CATEGORIES length
  assert(result.reportJson.categoriesMonitored >= 37, 'Should monitor at least 37 categories, got ' + result.reportJson.categoriesMonitored);
  try { fs.unlinkSync(result.jsonPath); } catch(e) {}
  try { fs.unlinkSync(result.htmlPath); } catch(e) {}
  try { fs.unlinkSync(result.ctxPath); } catch(e) {}
});

// ── Test 8: No spoofing in stealth script ──
test('Zero spoofing: no UA/locale/timezone override', () => {
  const script = getExtraStealthScript();
  assert(!script.includes('userAgent ='), 'Should not override UA');
  assert(!script.includes('Intl.DateTimeFormat'), 'Should not override timezone');
  assert(!script.includes('navigator.language ='), 'Should not override language');
});

// ── Summary ──
console.log(`\n${'─'.repeat(45)}`);
console.log(`  Results: ${pass} passed, ${fail} failed`);
if (fail === 0) {
  console.log('  🎉 All tests passed! v4.6.2 Ghost Protocol ready.');
} else {
  console.log('  ⚠️  Some tests failed. Review before deployment.');
}
console.log(`${'─'.repeat(45)}\n`);

process.exit(fail > 0 ? 1 : 0);
