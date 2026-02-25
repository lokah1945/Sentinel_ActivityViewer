// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — INJECTION CONTENT VALIDATION TEST
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - Validates all 42 category hook points exist in interceptor
//   - Validates shield protection mechanisms
//   - Validates push telemetry code
//   - No browser needed — parses generated JavaScript strings
// ═══════════════════════════════════════════════════════════════

'use strict';

var { getShieldScript } = require('../hooks/anti-detection-shield');
var { getInterceptorScript } = require('../hooks/api-interceptor');

var passed = 0;
var failed = 0;

function test(name, fn) {
  try { fn(); passed++; process.stderr.write('  ✓ ' + name + '\n'); }
  catch (e) { failed++; process.stderr.write('  ✗ ' + name + ': ' + e.message + '\n'); }
}
function assert(c, m) { if (!c) throw new Error(m); }

process.stderr.write('\n═══ INJECTION CONTENT VALIDATION ═══\n\n');

var shield = getShieldScript();
var interceptor = getInterceptorScript({ timeout: 30000, maxEvents: 50000, pushInterval: 500 });

// Shield tests
test('Shield: hookFunction exists', function() { assert(shield.indexOf('function hookFunction') !== -1); });
test('Shield: hookGetter exists', function() { assert(shield.indexOf('function hookGetter') !== -1); });
test('Shield: hookGetterSetter exists', function() { assert(shield.indexOf('function hookGetterSetter') !== -1); });
test('Shield: smartHookGetter exists', function() { assert(shield.indexOf('function smartHookGetter') !== -1); });
test('Shield: toString protection', function() { assert(shield.indexOf('toString') !== -1); });
test('Shield: Error.prepareStackTrace cleanup', function() { assert(shield.indexOf('prepareStackTrace') !== -1); });
test('Shield: getOwnPropertyDescriptors protection', function() { assert(shield.indexOf('getOwnPropertyDescriptors') !== -1); });
test('Shield: WeakMap cache', function() { assert(shield.indexOf('WeakMap') !== -1); });

// Category presence tests
var expectedCategories = [
  'canvas', 'webgl', 'audio', 'font-detection', 'fingerprint',
  'screen', 'storage', 'network', 'perf-timing', 'media-devices',
  'dom-probe', 'clipboard', 'geolocation', 'service-worker',
  'hardware', 'exfiltration', 'webrtc', 'math-fingerprint',
  'permissions', 'speech', 'client-hints', 'intl-fingerprint',
  'css-fingerprint', 'property-enum', 'offscreen-canvas',
  'honeypot', 'credential', 'system', 'encoding', 'worker',
  'webassembly', 'keyboard-layout', 'sensor-apis', 'visualization',
  'battery', 'event-monitoring', 'blob-url', 'shared-array-buffer',
  'postmessage-exfil', 'device-info', 'cross-frame-comm'
];

expectedCategories.forEach(function(cat) {
  test('Category: ' + cat, function() {
    assert(interceptor.indexOf("'" + cat + "'") !== -1 || interceptor.indexOf('"' + cat + '"') !== -1,
      cat + ' category not found in interceptor');
  });
});

// Push telemetry tests
test('Push: SENTINEL_PUSH binding', function() { assert(interceptor.indexOf('SENTINEL_PUSH') !== -1); });
test('Push: pushInterval setInterval', function() { assert(interceptor.indexOf('setInterval') !== -1); });
test('Push: beforeunload flush', function() { assert(interceptor.indexOf('beforeunload') !== -1); });
test('Push: BOOT-OK signal', function() { assert(interceptor.indexOf('BOOT-OK') !== -1); });

process.stderr.write('\n═══ RESULTS: ' + passed + ' passed, ' + failed + ' failed ═══\n\n');
if (failed > 0) process.exit(1);
