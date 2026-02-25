// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — REGRESSION TEST SUITE (28 Rules)
// ═══════════════════════════════════════════════════════════════
'use strict';
var fs = require('fs');
var path = require('path');
var passed = 0, failed = 0, total = 0;

function test(name, fn) {
  total++;
  try { fn(); passed++; console.log('  \u2713 ' + name); }
  catch (e) { failed++; console.log('  \u2717 ' + name + ': ' + e.message); }
}
function assert(c, m) { if (!c) throw new Error(m || 'Assertion failed'); }

console.log('\n=== SENTINEL v7.0.0 REGRESSION TEST ===\n');

test('REG-001: Shield exports getShieldScript', function() {
  var m = require('../hooks/anti-detection-shield');
  assert(typeof m.getShieldScript === 'function');
  var s = m.getShieldScript();
  assert(s.indexOf('__SENTINEL_SHIELD__') !== -1);
  assert(s.indexOf('__SENTINEL_HOOKS__') !== -1);
});

test('REG-001: Interceptor exports getInterceptorScript', function() {
  var m = require('../hooks/api-interceptor');
  assert(typeof m.getInterceptorScript === 'function');
  var s = m.getInterceptorScript({ timeout: 10000, maxEvents: 1000, pushInterval: 500 });
  assert(s.length > 1000);
});

test('REG-002: addEventListener monitoring', function() {
  var s = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(s.indexOf('addEventListener') !== -1);
  assert(s.indexOf("'event-monitoring'") !== -1);
});

test('REG-003: Battery API', function() {
  assert(require('../hooks/api-interceptor').getInterceptorScript({}).indexOf('getBattery') !== -1);
});

test('REG-004: matchMedia', function() {
  assert(require('../hooks/api-interceptor').getInterceptorScript({}).indexOf('matchMedia') !== -1);
});

test('REG-005: Dual-log exfiltration+network', function() {
  var s = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(s.indexOf("log('exfiltration'") !== -1);
  assert(s.indexOf("log('network'") !== -1);
});

test('REG-006: frameattached handler', function() {
  assert(fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8').indexOf('frameattached') !== -1);
});

test('REG-007: framenavigated handler', function() {
  assert(fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8').indexOf('framenavigated') !== -1);
});

test('REG-008: No permissions.query in stealth-config', function() {
  var code = fs.readFileSync(path.join(__dirname, '../hooks/stealth-config.js'), 'utf8');
  var codeLines = code.split('\n').filter(function(l) { return l.trim().indexOf('//') !== 0; }).join('\n');
  assert(codeLines.indexOf('permissions.query') === -1);
});

test('REG-009: stealth-config < 100 lines', function() {
  assert(fs.readFileSync(path.join(__dirname, '../hooks/stealth-config.js'), 'utf8').split('\n').length < 100);
});

test('REG-010: smartHookGetter in shield', function() {
  assert(require('../hooks/anti-detection-shield').getShieldScript().indexOf('smartHookGetter') !== -1);
});

test('REG-011: _SENTINEL_DATA naming', function() {
  assert(require('../hooks/api-interceptor').getInterceptorScript({}).indexOf('_SENTINEL_DATA') !== -1);
});

test('REG-013: reduce + Math.max in correlation-engine', function() {
  var src = fs.readFileSync(path.join(__dirname, '../lib/correlation-engine.js'), 'utf8');
  assert(src.indexOf('Math.max') !== -1);
  assert(src.indexOf('reduce') !== -1);
});

test('REG-014: WeakMap descriptor cache in shield', function() {
  var s = require('../hooks/anti-detection-shield').getShieldScript();
  assert(s.indexOf('WeakMap') !== -1);
  assert(s.indexOf('_descriptorCache') !== -1);
});

test('REG-015: 500ms push interval', function() {
  assert(require('../hooks/api-interceptor').getInterceptorScript({}).indexOf('500') !== -1);
});

test('REG-016: setAutoAttach + flatten in target-graph', function() {
  var src = fs.readFileSync(path.join(__dirname, '../lib/target-graph.js'), 'utf8');
  assert(src.indexOf('setAutoAttach') !== -1);
  assert(src.indexOf('flatten: true') !== -1);
});

test('REG-017: Non-enumerable globals', function() {
  assert(require('../hooks/anti-detection-shield').getShieldScript().indexOf('enumerable: false') !== -1);
  assert(require('../hooks/api-interceptor').getInterceptorScript({}).indexOf('enumerable: false') !== -1);
});

test('REG-018: Promise.allSettled in CDP observer', function() {
  assert(fs.readFileSync(path.join(__dirname, '../lib/cdp-observer-engine.js'), 'utf8').indexOf('Promise.allSettled') !== -1);
});

test('REG-020: categoriesMonitored = 42', function() {
  assert(require('../hooks/api-interceptor').getInterceptorScript({}).indexOf('categoriesMonitored = 42') !== -1);
});

test('REG-021: Final flush', function() {
  assert(fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8').indexOf('Final flush') !== -1);
});

test('REG-022: launchPersistentContext', function() {
  assert(fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8').indexOf('launchPersistentContext') !== -1);
});

test('REG-023: BOOT-OK signal', function() {
  assert(require('../hooks/api-interceptor').getInterceptorScript({}).indexOf('BOOT-OK') !== -1);
});

test('REG-024: fpTags filter', function() {
  assert(require('../hooks/api-interceptor').getInterceptorScript({}).indexOf('fpTags') !== -1);
});

test('REG-025: property-enum filter', function() {
  var s = require('../hooks/api-interceptor').getInterceptorScript({});
  assert(s.indexOf("'property-enum'") !== -1);
});

test('REG-026: All CDP domains', function() {
  var src = fs.readFileSync(path.join(__dirname, '../lib/cdp-observer-engine.js'), 'utf8');
  ['Network.enable', 'Page.enable', 'Security.enable', 'Console.enable', 'DOM.enable', 'Performance.enable'].forEach(function(d) {
    assert(src.indexOf(d) !== -1, d + ' missing');
  });
});

test('REG-027: CLEANUP_PROFILE + rmSync', function() {
  var src = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');
  assert(src.indexOf('CLEANUP_PROFILE') !== -1);
  assert(src.indexOf('rmSync') !== -1);
});

test('REG-028: rebrowser-playwright in package.json', function() {
  var pkg = require('../package.json');
  assert(pkg.dependencies['rebrowser-playwright']);
});

test('CLI: --dual-mode support', function() {
  var src = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');
  assert(src.indexOf('--dual-mode') !== -1);
  assert(src.indexOf('dualMode') !== -1);
});

test('CLI: --no-headless support', function() {
  var src = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');
  assert(src.indexOf('--no-headless') !== -1);
});

console.log('\n=== RESULTS: ' + passed + ' passed, ' + failed + ' failed, ' + total + ' total ===\n');
if (failed > 0) process.exit(1);
