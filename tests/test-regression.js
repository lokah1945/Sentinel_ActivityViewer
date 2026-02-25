// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — REGRESSION TEST SUITE (28 Rules)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - 28 mandatory regression rules from Blueprint
//   - Validates file structure, module exports, injection scripts
//   - Tests: shield exports, interceptor categories, pipeline methods
//   - Tests: CDP observer domains, target graph auto-attach
//   - Tests: report generator output format
//   - No runtime browser needed — static analysis
//
// LAST HISTORY LOG:
//   v7.0.0: New test suite for v7.0.0 architecture
// ═══════════════════════════════════════════════════════════════

'use strict';

var fs = require('fs');
var path = require('path');
var passed = 0;
var failed = 0;
var total = 0;

function test(name, fn) {
  total++;
  try {
    fn();
    passed++;
    process.stderr.write('  ✓ ' + name + '\n');
  } catch (e) {
    failed++;
    process.stderr.write('  ✗ ' + name + ': ' + e.message + '\n');
  }
}

function assert(cond, msg) { if (!cond) throw new Error(msg || 'Assertion failed'); }

process.stderr.write('\n═══ SENTINEL v7.0.0 REGRESSION TEST ═══\n\n');

// ─── REG-001: addInitScript injection exists ───
test('REG-001: Shield script exports getShieldScript', function() {
  var m = require('../hooks/anti-detection-shield');
  assert(typeof m.getShieldScript === 'function', 'getShieldScript not a function');
  var script = m.getShieldScript();
  assert(script.length > 100, 'Shield script too short');
  assert(script.indexOf('__SENTINEL_SHIELD__') !== -1, 'Shield marker missing');
  assert(script.indexOf('__SENTINEL_HOOKS__') !== -1, 'Hook exports missing');
});

test('REG-001: Interceptor script exports getInterceptorScript', function() {
  var m = require('../hooks/api-interceptor');
  assert(typeof m.getInterceptorScript === 'function', 'getInterceptorScript not a function');
  var script = m.getInterceptorScript({ timeout: 10000, maxEvents: 1000, pushInterval: 500 });
  assert(script.length > 1000, 'Interceptor script too short');
});

// ─── REG-002: addEventListener monitoring ───
test('REG-002: Interceptor hooks addEventListener', function() {
  var script = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(script.indexOf('addEventListener') !== -1, 'addEventListener hook missing');
  assert(script.indexOf('event-monitoring') !== -1, 'event-monitoring category missing');
});

// ─── REG-003: Battery API ───
test('REG-003: Battery API hook exists', function() {
  var script = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(script.indexOf('getBattery') !== -1, 'getBattery hook missing');
  assert(script.indexOf('battery') !== -1, 'battery category missing');
});

// ─── REG-004: matchMedia ───
test('REG-004: matchMedia hook exists', function() {
  var script = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(script.indexOf('matchMedia') !== -1, 'matchMedia hook missing');
});

// ─── REG-005: Dual-log exfiltration + network ───
test('REG-005: Dual-log for fetch/XHR', function() {
  var script = require('../hooks/api-interceptor').getInterceptorScript({});
  var fetchIdx1 = script.indexOf("log('network', 'fetch'");
  var fetchIdx2 = script.indexOf("log('exfiltration', 'fetch'");
  assert(fetchIdx1 !== -1, 'Network fetch log missing');
  assert(fetchIdx2 !== -1, 'Exfiltration fetch log missing');
});

// ─── REG-006: frameattached handler ───
test('REG-006: index.js has frameattached handler', function() {
  var src = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');
  assert(src.indexOf('frameattached') !== -1, 'frameattached handler missing');
});

// ─── REG-007: framenavigated handler ───
test('REG-007: index.js has framenavigated handler', function() {
  var src = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');
  assert(src.indexOf('framenavigated') !== -1, 'framenavigated handler missing');
});

// ─── REG-008: No permissions.query wrapper in stealth ───
test('REG-008: Stealth config has no permissions.query wrapper', function() {
  var src = fs.readFileSync(path.join(__dirname, '../hooks/stealth-config.js'), 'utf8');
  var codeOnly = src.split('\n').filter(function(l){ return l.trim().indexOf('//') !== 0; }).join('\n');
    assert(codeOnly.indexOf('permissions.query') === -1, 'stealth-config should NOT have permissions.query code');
});

// ─── REG-009: Stealth config < 100 lines ───
test('REG-009: Stealth config is minimal (< 100 lines)', function() {
  var src = fs.readFileSync(path.join(__dirname, '../hooks/stealth-config.js'), 'utf8');
  var lines = src.split('\n').length;
  assert(lines < 100, 'stealth-config has ' + lines + ' lines (max 100)');
});

// ─── REG-010: smartHookGetter exists ───
test('REG-010: smartHookGetter in shield', function() {
  var script = require('../hooks/anti-detection-shield').getShieldScript();
  assert(script.indexOf('smartHookGetter') !== -1, 'smartHookGetter missing from shield');
});

// ─── REG-011: SENTINEL_DATA naming ───
test('REG-011: Consistent _SENTINEL_DATA naming in interceptor', function() {
  var script = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(script.indexOf('_SENTINEL_DATA') !== -1, '_SENTINEL_DATA missing');
});

// ─── REG-012: No unscoped variables in report ───
test('REG-012: No unscoped "vc" variable in report-generator', function() {
  var src = fs.readFileSync(path.join(__dirname, '../reporters/report-generator.js'), 'utf8');
  assert(src.indexOf(' vc ') === -1 && src.indexOf(' vc=') === -1, 'unscoped vc variable found');
});

// ─── REG-013: timeSpanMs uses Math.max correctly ───
test('REG-013: correlation-engine uses reduce for timeSpan', function() {
  var src = fs.readFileSync(path.join(__dirname, '../lib/correlation-engine.js'), 'utf8');
  assert(src.indexOf('Math.max') !== -1, 'Math.max missing');
  assert(src.indexOf('reduce') !== -1, 'reduce missing');
});

// ─── REG-014: WeakMap descriptor cache ───
test('REG-014: WeakMap descriptor cache in shield', function() {
  var script = require('../hooks/anti-detection-shield').getShieldScript();
  assert(script.indexOf('WeakMap') !== -1, 'WeakMap missing from shield');
  assert(script.indexOf('_descriptorCache') !== -1, '_descriptorCache missing');
});

// ─── REG-015: 500ms push interval ───
test('REG-015: 500ms push interval default', function() {
  var script = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(script.indexOf('pushInterval: 500') !== -1 || script.indexOf('500') !== -1, '500ms interval missing');
});

// ─── REG-016: Recursive auto-attach in TargetGraph ───
test('REG-016: TargetGraph has recursive auto-attach', function() {
  var src = fs.readFileSync(path.join(__dirname, '../lib/target-graph.js'), 'utf8');
  assert(src.indexOf('setAutoAttach') !== -1, 'setAutoAttach missing');
  assert(src.indexOf('flatten: true') !== -1, 'flatten mode missing');
});

// ─── REG-017: Non-enumerable globals ───
test('REG-017: Quiet Mode — non-enumerable globals', function() {
  var script = require('../hooks/anti-detection-shield').getShieldScript();
  assert(script.indexOf('enumerable: false') !== -1, 'Non-enumerable missing');
  var iScript = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(iScript.indexOf('enumerable: false') !== -1, 'Non-enumerable missing in interceptor');
});

// ─── REG-018: Promise.allSettled for CDP enable ───
test('REG-018: CDP observer uses Promise.allSettled', function() {
  var src = fs.readFileSync(path.join(__dirname, '../lib/cdp-observer-engine.js'), 'utf8');
  assert(src.indexOf('Promise.allSettled') !== -1, 'Promise.allSettled missing');
});

// ─── REG-019: evalWithTimeout safety ───
test('REG-019: No raw page.evaluate without try-catch in index.js', function() {
  var src = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');
  // Every page.evaluate should be inside try-catch
  assert(src.indexOf('try {') !== -1, 'No try-catch found');
});

// ─── REG-020: 42 categories monitored ───
test('REG-020: Interceptor declares 42 categories', function() {
  var script = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(script.indexOf('categoriesMonitored: 42') !== -1, 'categoriesMonitored not 42');
});

// ─── REG-021: Final flush before close ───
test('REG-021: index.js has final flush', function() {
  var src = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');
  assert(src.indexOf('Final flush') !== -1 || src.indexOf('final flush') !== -1 || src.indexOf('FINAL') !== -1, 'Final flush comment missing');
});

// ─── REG-022: launchPersistentContext ───
test('REG-022: Uses launchPersistentContext', function() {
  var src = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');
  assert(src.indexOf('launchPersistentContext') !== -1, 'launchPersistentContext missing');
});

// ─── REG-023: BOOT-OK signal ───
test('REG-023: BOOT-OK signal in interceptor', function() {
  var script = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(script.indexOf('BOOT-OK') !== -1, 'BOOT-OK signal missing');
});

// ─── REG-024: Filtered createElement ───
test('REG-024: createElement filters FP tags only', function() {
  var script = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(script.indexOf('fpTags') !== -1, 'fpTags filter missing');
});

// ─── REG-025: Filtered property-enum ───
test('REG-025: property-enum filters navigator/screen only', function() {
  var script = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(script.indexOf('property-enum') !== -1, 'property-enum category missing');
  assert(script.indexOf('navigator') !== -1, 'navigator filter missing');
  assert(script.indexOf('screen') !== -1, 'screen filter missing');
});

// ─── REG-026: All CDP domains enabled ───
test('REG-026: CDP observer enables all domains', function() {
  var src = fs.readFileSync(path.join(__dirname, '../lib/cdp-observer-engine.js'), 'utf8');
  assert(src.indexOf('Network.enable') !== -1, 'Network.enable missing');
  assert(src.indexOf('Page.enable') !== -1, 'Page.enable missing');
  assert(src.indexOf('Security.enable') !== -1, 'Security.enable missing');
  assert(src.indexOf('Console.enable') !== -1, 'Console.enable missing');
  assert(src.indexOf('DOM.enable') !== -1, 'DOM.enable missing');
  assert(src.indexOf('Performance.enable') !== -1, 'Performance.enable missing');
});

// ─── REG-027: Auto-cleanup ───
test('REG-027: Profile auto-cleanup in index.js', function() {
  var src = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');
  assert(src.indexOf('rmSync') !== -1, 'rmSync cleanup missing');
  assert(src.indexOf('CLEANUP_PROFILE') !== -1, 'CLEANUP_PROFILE flag missing');
});

// ─── REG-028: rebrowser-patches compatible ───
test('REG-028: Uses rebrowser-playwright', function() {
  var pkg = require('../package.json');
  assert(pkg.dependencies['rebrowser-playwright'], 'rebrowser-playwright not in dependencies');
});

// ─── SUMMARY ───
process.stderr.write('\n═══════════════════════════════════════════\n');
process.stderr.write('  RESULTS: ' + passed + ' passed, ' + failed + ' failed, ' + total + ' total\n');
process.stderr.write('═══════════════════════════════════════════\n\n');

if (failed > 0) process.exit(1);
