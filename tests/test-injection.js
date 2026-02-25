// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — INJECTION CONTENT VALIDATION TEST
// ═══════════════════════════════════════════════════════════════
'use strict';
var { getShieldScript } = require('../hooks/anti-detection-shield');
var { getInterceptorScript } = require('../hooks/api-interceptor');
var passed = 0, failed = 0;

function test(n, fn) { try { fn(); passed++; console.log('  \u2713 ' + n); } catch (e) { failed++; console.log('  \u2717 ' + n + ': ' + e.message); } }
function assert(c, m) { if (!c) throw new Error(m); }

console.log('\n=== INJECTION CONTENT VALIDATION ===\n');
var shield = getShieldScript();
var interceptor = getInterceptorScript({ timeout: 30000, maxEvents: 50000, pushInterval: 500 });

test('Shield: hookFunction', function() { assert(shield.indexOf('function hookFunction') !== -1); });
test('Shield: hookGetter', function() { assert(shield.indexOf('function hookGetter') !== -1); });
test('Shield: hookGetterSetter', function() { assert(shield.indexOf('function hookGetterSetter') !== -1); });
test('Shield: smartHookGetter', function() { assert(shield.indexOf('function smartHookGetter') !== -1); });
test('Shield: toString protection', function() { assert(shield.indexOf('toString') !== -1); });
test('Shield: prepareStackTrace', function() { assert(shield.indexOf('prepareStackTrace') !== -1); });
test('Shield: WeakMap cache', function() { assert(shield.indexOf('WeakMap') !== -1); });

var expectedCats = [
  'canvas', 'webgl', 'audio', 'font-detection', 'fingerprint', 'screen', 'storage',
  'network', 'perf-timing', 'media-devices', 'dom-probe', 'clipboard', 'geolocation',
  'service-worker', 'hardware', 'exfiltration', 'webrtc', 'math-fingerprint', 'permissions',
  'speech', 'client-hints', 'intl-fingerprint', 'css-fingerprint', 'property-enum',
  'offscreen-canvas', 'honeypot', 'credential', 'system', 'encoding', 'worker',
  'webassembly', 'keyboard-layout', 'sensor-apis', 'visualization', 'battery',
  'event-monitoring', 'blob-url', 'shared-array-buffer', 'postmessage-exfil',
  'device-info', 'cross-frame-comm'
];
expectedCats.forEach(function(cat) {
  test('Category: ' + cat, function() {
    assert(interceptor.indexOf("'" + cat + "'") !== -1, cat + ' not found');
  });
});

test('Push: SENTINEL_PUSH', function() { assert(interceptor.indexOf('SENTINEL_PUSH') !== -1); });
test('Push: setInterval', function() { assert(interceptor.indexOf('setInterval') !== -1); });
test('Push: beforeunload', function() { assert(interceptor.indexOf('beforeunload') !== -1); });
test('Push: BOOT-OK', function() { assert(interceptor.indexOf('BOOT-OK') !== -1); });

console.log('\n=== RESULTS: ' + passed + ' passed, ' + failed + ' failed ===\n');
if (failed > 0) process.exit(1);
