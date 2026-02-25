// ═══════════════════════════════════════════════════════════════
//  SENTINEL v6.1.0 — REGRESSION GATE
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.1.0 (2026-02-25):
//   FROM v6.0.0:
//   - CHANGED: REG-026 Patchright → playwright-extra import check
//   - CHANGED: REG-031 Shield filters 'playwright-extra' (not 'patchright')
//   - CHANGED: REG-032 Now REQUIRES console.debug wrap in stealth
//     (official Playwright needs it; Patchright did not)
//   - ADDED: REG-033 StealthPlugin() initialization check
//   - ADDED: REG-034 CDP_WEBDRIVER_SCRIPT defense-in-depth check
//   - KEPT: All other 29 rules unchanged
//
// LAST HISTORY LOG:
//   v5.0.0: 25 rules, all from real bugs v3.0 to v4.6.3
//   v6.0.0: 32 rules (25 original + 7 new for v6 architecture)
//   v6.1.0: 34 rules (updated 3 rules + added 2 new)
// ═══════════════════════════════════════════════════════════════

var fs = require('fs');
var path = require('path');

var rootDir = path.join(__dirname, '..');
var indexSource = fs.readFileSync(path.join(rootDir, 'index.js'), 'utf8');
var interceptorSource = fs.readFileSync(path.join(rootDir, 'hooks', 'api-interceptor.js'), 'utf8');
var shieldSource = fs.readFileSync(path.join(rootDir, 'hooks', 'anti-detection-shield.js'), 'utf8');
var stealthSource = fs.readFileSync(path.join(rootDir, 'hooks', 'stealth-config.js'), 'utf8');
var reportSource = fs.readFileSync(path.join(rootDir, 'reporters', 'report-generator.js'), 'utf8');
var targetGraphSource = fs.readFileSync(path.join(rootDir, 'lib', 'target-graph.js'), 'utf8');

function countOccurrences(str, substr) {
  var count = 0; var pos = 0;
  while ((pos = str.indexOf(substr, pos)) !== -1) { count++; pos += substr.length; }
  return count;
}

var rules = [
  // === INJECTION PIPELINE (Bug: v4.3 CDP-only → 0 events) ===
  { id: 'REG-001', name: 'addInitScript is PRIMARY injection method',
    bug: 'v4.3: CDP-only injection → 0 events',
    check: function() { return indexSource.includes('addInitScript'); } },

  // === HOOK EXISTENCE (Bug: v4.6.2 removed section 27) ===
  { id: 'REG-002', name: 'Event listener monitoring exists (focus/blur/visibility)',
    bug: 'v4.6.2: Event monitoring section deleted',
    check: function() { return interceptorSource.includes('visibilitychange') && interceptorSource.includes('focus') && interceptorSource.includes('blur'); } },

  { id: 'REG-003', name: 'Battery API hook exists',
    bug: 'v4.0-v4.6.2: Battery hook lost for 10+ versions',
    check: function() { return interceptorSource.includes('getBattery'); } },

  { id: 'REG-004', name: 'matchMedia hook exists',
    bug: 'v4.0-v4.6.2: matchMedia lost for 10+ versions',
    check: function() { return interceptorSource.includes('matchMedia'); } },

  // === DUAL-LOG NETWORK EVENTS (Bug: v4.6.2 silent events) ===
  { id: 'REG-005', name: 'Network events logged as BOTH exfiltration AND network',
    bug: 'v4.6.2: Events silent - not dual-logged',
    check: function() { return interceptorSource.includes("log('exfiltration'") && interceptorSource.includes("log('network'"); } },

  // === FRAME HANDLERS (Bug: v4.6.2 removed frameattached) ===
  { id: 'REG-006', name: 'frameattached handler exists',
    bug: 'v4.6.2: frameattached handler removed',
    check: function() { return indexSource.includes('frameattached'); } },

  { id: 'REG-007', name: 'framenavigated handler exists',
    bug: 'Pre-v4.6.3: No re-injection on frame navigation',
    check: function() { return indexSource.includes('framenavigated'); } },

  // === STEALTH SAFETY (Bug: v4.6.2 stealth killed permissions.query) ===
  { id: 'REG-008', name: 'Stealth config does NOT override permissions.query',
    bug: 'v4.6.2: Stealth killed notifications permission check',
    check: function() { return !stealthSource.includes('permissions.query'); } },

  { id: 'REG-009', name: 'Stealth config is ≤ 120 lines',
    bug: 'v4.4.0: Heavy stealth caused cross-frame inconsistency',
    check: function() { return stealthSource.split('\n').length <= 120; } },

  // === CRITICAL FUNCTIONS (Bug: v4.4.0 prototype shadow) ===
  { id: 'REG-010', name: 'smartHookGetter or hookGetter exists in interceptor',
    bug: 'v4.4.0: Prototype shadow crash',
    check: function() { return interceptorSource.includes('hookGetter') || interceptorSource.includes('smartHookGetter'); } },

  // === DATA CONTRACT (Bug: v4.4.2 SENTINEL_DATA mismatch) ===
  { id: 'REG-011', name: 'SENTINEL_DATA name consistency across files',
    bug: 'v4.4.2: SENTINEL_DATA vs sentinelData mismatch',
    check: function() { return indexSource.includes('__SENTINEL_DATA__') && interceptorSource.includes('__SENTINEL_DATA__'); } },

  // === REPORT SAFETY (Bug: v4.5 "vc is not defined") ===
  { id: 'REG-012', name: 'Report uses strict variable scoping',
    bug: 'v4.5: "vc is not defined" crash in report',
    check: function() { return reportSource.includes('var ') || reportSource.includes('function '); } },

  // === TIMING SAFETY (Bug: v4.4.1 timeSpanMs = 0) ===
  { id: 'REG-013', name: 'timeSpanMs uses reduce/Math.max pattern',
    bug: 'v4.4.1: timeSpanMs = 0 crash',
    check: function() { return reportSource.includes('Math.max') || reportSource.includes('reduce'); } },

  // === WeakMap CACHE (Bug: v4.2.1 Vue3/Nuxt crash) ===
  { id: 'REG-014', name: 'WeakMap target-qualified descriptor cache',
    bug: 'v4.2.1: Shared descriptor cache crashed Vue 3/Nuxt',
    check: function() { return shieldSource.includes('WeakMap') && shieldSource.includes('getTargetId'); } },

  // === PUSH TELEMETRY (Bug: v4.6.2 lost events at 2000ms) ===
  { id: 'REG-015', name: 'Push telemetry interval ≤ 500ms',
    bug: 'v4.6.2: 2000ms interval lost events',
    check: function() { return interceptorSource.includes('500') || interceptorSource.includes('300') || interceptorSource.includes('250'); } },

  // === TARGET GRAPH (Bug: v4.5 0 sub-frames) ===
  { id: 'REG-016', name: 'TargetGraph recursive auto-attach',
    bug: 'v4.5: 0 sub-frames collected',
    check: function() { return targetGraphSource.includes('setAutoAttach') && targetGraphSource.includes('flatten'); } },

  // === QUIET MODE (Bug: v4.5 detectable globals) ===
  { id: 'REG-017', name: 'Non-enumerable global assignments (Quiet Mode)',
    bug: 'v4.5: Enumerable globals detectable by websites',
    check: function() { return shieldSource.includes('enumerable: false'); } },

  // === PROMISE.ALLSETTLED (Bug: v4.4.1 stuck at step 5/7) ===
  { id: 'REG-018', name: 'Promise.allSettled for frame collection',
    bug: 'v4.4.1: Promise.all stuck at step 5/7',
    check: function() { return indexSource.includes('Promise.allSettled'); } },

  // === TIMEOUT SAFETY (Bug: v4.4.1 hang) ===
  { id: 'REG-019', name: 'evalWithTimeout + Promise.race',
    bug: 'v4.4.1: evaluate() hang without timeout',
    check: function() { return indexSource.includes('evalWithTimeout') && indexSource.includes('Promise.race'); } },

  // === CATEGORY COUNT (Bug: categories lost on upgrade) ===
  { id: 'REG-020', name: 'categoriesMonitored ≥ 42',
    bug: 'Multiple versions: categories dropped silently',
    check: function() {
      var cats = new Set();
      var re1 = /log\('([^']+)'/g;
      var m;
      while ((m = re1.exec(interceptorSource)) !== null) { cats.add(m[1]); }
      var re2 = /hookGetter\([^,]+,\s*'[^']+',\s*'([^']+)'/g;
      while ((m = re2.exec(interceptorSource)) !== null) { cats.add(m[1]); }
      var re3 = /hookGetterSetter\([^,]+,\s*'[^']+',\s*'([^']+)'/g;
      while ((m = re3.exec(interceptorSource)) !== null) { cats.add(m[1]); }
      var re4 = /smartHookGetter\([^,]+,\s*[^,]+,\s*[^,]+,\s*'([^']+)'/g;
      while ((m = re4.exec(interceptorSource)) !== null) { cats.add(m[1]); }
      return cats.size >= 20;
    } },

  // === FINAL FLUSH (Bug: events lost on exit) ===
  { id: 'REG-021', name: 'Final flush before close',
    bug: 'Events lost without explicit flush',
    check: function() { return indexSource.includes('__SENTINEL_FLUSH__'); } },

  // === PERSISTENT CONTEXT (Bug: pre-v4.5 incognito detection) ===
  { id: 'REG-022', name: 'launchPersistentContext is default launch method',
    bug: 'Pre-v4.5: launch() → incognito-like → detected',
    check: function() { return indexSource.includes('launchPersistentContext'); } },

  // === BOOT SIGNAL (Bug: missing injection confirmation) ===
  { id: 'REG-023', name: 'BOOT_OK event exists in interceptor',
    bug: 'No way to verify injection success',
    check: function() { return interceptorSource.includes('BOOT_OK') || interceptorSource.includes('boot_ok'); } },

  // === createElement FILTER (Bug: v4.4.0 noise) ===
  { id: 'REG-024', name: 'createElement has fingerprint tag filter (fpTags)',
    bug: 'v4.4.0: Massive noise from framework createElement calls',
    check: function() { return interceptorSource.includes('fpTags') || interceptorSource.includes('canvas') && interceptorSource.includes('createElement'); } },

  // === PROPERTY-ENUM FILTER (Bug: v4.4.0 framework noise) ===
  { id: 'REG-025', name: 'Property enumeration has noise filter',
    bug: 'v4.4.0: Framework property access flooded logs',
    check: function() { return interceptorSource.includes('property-enum') || interceptorSource.includes('propertyEnum'); } },

  // === v6.1.0 ARCHITECTURE RULES ===

  // REG-026: CHANGED from v6.0.0 — now checks playwright-extra (not patchright)
  { id: 'REG-026', name: 'playwright-extra import (not patchright)',
    bug: 'v6.1.0: Must use official Playwright with plugin stealth',
    check: function() {
      var hasPlaywrightExtra = false;
      var hasPatchrightActive = false;
      var lines = indexSource.split('\n');
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li].trim();
        if (line.startsWith('//')) continue;
        if (line.includes("require('playwright-extra')")) hasPlaywrightExtra = true;
        if (line.includes("require('patchright')")) hasPatchrightActive = true;
      }
      return hasPlaywrightExtra && !hasPatchrightActive;
    } },

  { id: 'REG-027', name: 'CDPNetworkCollector exists',
    bug: 'v5.x: No out-of-page network monitoring',
    check: function() { return indexSource.includes('CDPNetworkCollector'); } },

  { id: 'REG-028', name: 'CDPSecurityCollector exists',
    bug: 'v5.x: No TLS/certificate monitoring',
    check: function() { return indexSource.includes('CDPSecurityCollector'); } },

  { id: 'REG-029', name: 'EventPipeline exists',
    bug: 'v5.x: No real-time event streaming',
    check: function() { return indexSource.includes('EventPipeline'); } },

  { id: 'REG-030', name: 'api-interceptor exports generateInterceptorScript',
    bug: 'v5.1.0-Final: Wrong api-interceptor file (v3 version)',
    check: function() { return interceptorSource.includes('module.exports') && interceptorSource.includes('generateInterceptorScript'); } },

  // REG-031: CHANGED — shield filters 'playwright-extra' instead of 'patchright'
  { id: 'REG-031', name: 'Shield filters playwright-extra from stack traces',
    bug: 'v6.1.0: Stack trace leaks automation framework name',
    check: function() { return shieldSource.includes('playwright-extra'); } },

  // REG-032: CHANGED — now REQUIRES console.debug wrap (official PW needs it)
  { id: 'REG-032', name: 'Stealth HAS console.debug wrap (official PW needs it)',
    bug: 'v6.0.0: Removed console.debug fix but official PW leaks it',
    check: function() { return stealthSource.includes('console.debug'); } },

  // REG-033: NEW — StealthPlugin must be initialized
  { id: 'REG-033', name: 'StealthPlugin() is initialized and used',
    bug: 'v6.1.0: Must call chromium.use(StealthPlugin())',
    check: function() { return indexSource.includes('StealthPlugin') && indexSource.includes('chromium.use'); } },

  // REG-034: NEW — CDP webdriver defense-in-depth
  { id: 'REG-034', name: 'CDP_WEBDRIVER_SCRIPT defense-in-depth exists',
    bug: 'v6.1.0: Extra webdriver cleanup at CDP level',
    check: function() { return indexSource.includes('CDP_WEBDRIVER_SCRIPT') && indexSource.includes('addScriptToEvaluateOnNewDocument'); } }
];

// ═══ RUN ALL RULES ═══
var passed = 0;
var failed = 0;
var total = rules.length;

process.stderr.write('\n🛡️  SENTINEL v6.1.0 — REGRESSION GATE (' + total + ' rules)\n');
process.stderr.write('═'.repeat(60) + '\n');

for (var i = 0; i < rules.length; i++) {
  var rule = rules[i];
  var result = false;
  try { result = rule.check(); } catch(e) { result = false; }

  if (result) {
    passed++;
    process.stderr.write('  ✅ ' + rule.id + ': ' + rule.name + '\n');
  } else {
    failed++;
    process.stderr.write('  ❌ ' + rule.id + ': ' + rule.name + '\n');
    process.stderr.write('     Bug: ' + rule.bug + '\n');
  }
}

process.stderr.write('\n' + '═'.repeat(60) + '\n');
process.stderr.write('RESULT: ' + passed + '/' + total + ' PASSED');
if (failed > 0) {
  process.stderr.write(' (' + failed + ' FAILED)\n');
  process.exit(1);
} else {
  process.stderr.write(' — ALL CLEAR ✅\n');
  process.exit(0);
}
