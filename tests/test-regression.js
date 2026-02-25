// ═══════════════════════════════════════════════════════════════
//  SENTINEL v6.0.0 — REGRESSION GATE
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.0.0 (2026-02-25):
//   FROM v5.0.0:
//   - UPDATED: Version checks from v5 to v6
//   - ADDED: REG-026 Patchright import check
//   - ADDED: REG-027 CDPNetworkCollector existence check
//   - ADDED: REG-028 CDPSecurityCollector existence check
//   - ADDED: REG-029 EventPipeline existence check
//   - ADDED: REG-030 api-interceptor exports generateInterceptorScript (not getInterceptorScript)
//   - ADDED: REG-031 Patchright in shield stack filter
//   - ADDED: REG-032 No console.debug wrap in stealth (Patchright handles it)
//   - KEPT: All 25 original regression rules from v5
//
// LAST HISTORY LOG:
//   v5.0.0: 25 rules, all from real bugs v3.0 to v4.6.3
//   v6.0.0: 32 rules (25 original + 7 new for v6 architecture)
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
    bug: 'v4.0-v4.6.2: matchMedia hook lost',
    check: function() { return interceptorSource.includes('matchMedia'); } },

  { id: 'REG-005', name: 'Network dual-log (exfiltration AND network)',
    bug: 'v4.6.2: Network events silent (0 events)',
    check: function() { return interceptorSource.includes("'network'") && interceptorSource.includes("'exfiltration'"); } },

  // === FRAME HANDLING (Bug: v4.6.2 removed frameattached) ===
  { id: 'REG-006', name: 'frameattached handler exists',
    bug: 'v4.6.2: frameattached handler removed → 0 dynamic iframes monitored',
    check: function() { return indexSource.includes('frameattached'); } },

  { id: 'REG-007', name: 'framenavigated handler exists',
    bug: 'Pre-v4.6.3: No re-injection on frame navigation',
    check: function() { return indexSource.includes('framenavigated'); } },

  // === STEALTH CONFLICTS (Bug: v4.6.2 stealth overwrites permissions) ===
  { id: 'REG-008', name: 'Stealth config has NO permissions.query wrapper',
    bug: 'v4.6.2: Stealth permissions.query wrapper blocked interceptor hook',
    check: function() { return !stealthSource.includes('permissions.query'); } },

  { id: 'REG-009', name: 'Stealth config ≤ 100 lines (minimal principle)',
    bug: 'v4.4.0: Heavy stealth (11KB) caused prototype shadow',
    check: function() { return stealthSource.split('\n').length <= 100; } },

  // === SMARTHOOKGETTER (Bug: v4.4.0 prototype shadow) ===
  { id: 'REG-010', name: 'smartHookGetter function exists in interceptor',
    bug: 'v4.4.0: Instance patches shadow prototype hooks → 95% hooks fail',
    check: function() { return interceptorSource.includes('smartHookGetter'); } },

  // === VARIABLE NAMING (Bug: v4.4.2 mismatch) ===
  { id: 'REG-011', name: 'SENTINEL_DATA consistent between index and interceptor',
    bug: 'v4.4.2-fail: Variable name mismatch → only 2 events',
    check: function() { return indexSource.includes('SENTINEL_DATA') && interceptorSource.includes('SENTINEL_DATA'); } },

  // === REPORT BUGS ===
  { id: 'REG-012', name: 'Report generator uses strict variable scoping',
    bug: 'v4.5: "vc is not defined" → HTML report crash',
    check: function() { return reportSource.includes('catRows') && reportSource.includes('vcRows'); } },

  { id: 'REG-013', name: 'timeSpanMs uses reduce/Math.max pattern',
    bug: 'v4.4.1: timeSpanMs = 0 (used last event instead of max)',
    check: function() { return reportSource.includes('Math.max') || reportSource.includes('Math.min'); } },

  // === DESCRIPTOR CACHE (Bug: v4.2.1 unqualified key) ===
  { id: 'REG-014', name: 'WeakMap in shield (target-qualified cache)',
    bug: 'v4.2.1: Unqualified descriptor cache key → Vue 3/Nuxt crash',
    check: function() { return shieldSource.includes('WeakMap'); } },

  // === PUSH TELEMETRY ===
  { id: 'REG-015', name: 'Push telemetry interval ≤ 500ms',
    bug: 'v4.6.2: 2000ms interval → lost events',
    check: function() {
      var match = interceptorSource.match(/setInterval[\s\S]*?},\s*(\d+)\s*\)/);
      return match && parseInt(match[1]) <= 500;
    } },

  // === TARGET GRAPH ===
  { id: 'REG-016', name: 'TargetGraph / recursive auto-attach exists',
    bug: 'v4.5: 0 sub-frames checked despite 10-12 frames detected',
    check: function() { return indexSource.includes('TargetGraph') && fs.existsSync(path.join(rootDir, 'lib', 'target-graph.js')); } },

  // === QUIET MODE ===
  { id: 'REG-017', name: 'Non-enumerable globals defined (Quiet Mode)',
    bug: 'v4.5: SENTINEL_DATA enumerable → detectable by anti-tampering probes',
    check: function() { return shieldSource.includes('enumerable') && interceptorSource.includes('enumerable: false'); } },

  // === ANTI-STUCK ===
  { id: 'REG-018', name: 'Promise.allSettled for frame collection',
    bug: 'v4.4.1: Stuck at step 5/7 during collection',
    check: function() { return indexSource.includes('Promise.allSettled'); } },

  { id: 'REG-019', name: 'evalWithTimeout wrapper exists',
    bug: 'v4.4.1: Frame evaluation hangs indefinitely',
    check: function() { return indexSource.includes('evalWithTimeout') && indexSource.includes('Promise.race'); } },

  // === 42 CATEGORIES ===
  { id: 'REG-020', name: 'categoriesMonitored ≥ 42',
    bug: 'Various: Categories lost during upgrades',
    check: function() {
      var match = interceptorSource.match(/categoriesMonitored\s*=\s*(\d+)/);
      return match && parseInt(match[1]) >= 42;
    } },

  // === FINAL FLUSH ===
  { id: 'REG-021', name: 'Final flush before browser close',
    bug: 'Events lost when browser closes before last push interval',
    check: function() { return indexSource.includes('SENTINEL_FLUSH') || interceptorSource.includes('FINAL_FLUSH') || interceptorSource.includes('SENTINEL_FLUSH'); } },

  // === PERSISTENT CONTEXT ===
  { id: 'REG-022', name: 'launchPersistentContext as default',
    bug: 'Pre-v4.5: newContext detected as incognito by BrowserScan',
    check: function() { return indexSource.includes('launchPersistentContext'); } },

  // === BOOT_OK ===
  { id: 'REG-023', name: 'BOOT_OK event in interceptor',
    bug: 'Missing injection confirmation signal',
    check: function() { return interceptorSource.includes('BOOT_OK'); } },

  // === FILTERED HOOKS ===
  { id: 'REG-024', name: 'createElement filter (fingerprint tags only)',
    bug: 'v4.4.0: Unfiltered createElement → noise from every <div>/<span>',
    check: function() { return interceptorSource.includes('fpTags') && interceptorSource.includes('indexOf'); } },

  { id: 'REG-025', name: 'Property-enum filter (navigator/screen only)',
    bug: 'v4.4.0: Unfiltered Object.keys → catches all framework calls',
    check: function() { return interceptorSource.includes('navigator') && interceptorSource.includes('screen') && interceptorSource.includes('Navigator.prototype'); } },

  // ═══ v6.0.0 NEW RULES ═══

  { id: 'REG-026', name: 'Patchright is the browser driver (not plain playwright)',
    bug: 'v5.x: playwright leaks Runtime.enable → BrowserScan detects automation',
    check: function() { return indexSource.includes("require('patchright')"); } },

  { id: 'REG-027', name: 'CDPNetworkCollector exists and is imported',
    bug: 'v5.x: No out-of-page network monitoring (only Playwright request/response)',
    check: function() {
      return indexSource.includes('CDPNetworkCollector') &&
             fs.existsSync(path.join(rootDir, 'collectors', 'cdp-network-collector.js'));
    } },

  { id: 'REG-028', name: 'CDPSecurityCollector exists and is imported',
    bug: 'v5.x: No TLS/certificate state monitoring',
    check: function() {
      return indexSource.includes('CDPSecurityCollector') &&
             fs.existsSync(path.join(rootDir, 'collectors', 'cdp-security-collector.js'));
    } },

  { id: 'REG-029', name: 'EventPipeline exists and is imported',
    bug: 'v5.x: No real-time event streaming backbone',
    check: function() {
      return indexSource.includes('EventPipeline') &&
             fs.existsSync(path.join(rootDir, 'lib', 'event-pipeline.js'));
    } },

  { id: 'REG-030', name: 'api-interceptor exports generateInterceptorScript (NOT getInterceptorScript)',
    bug: 'v5.1.0-Final: Wrong api-interceptor (v3 version, exports getInterceptorScript)',
    check: function() {
      return interceptorSource.includes('module.exports = { generateInterceptorScript }') &&
             !interceptorSource.includes('module.exports = { getInterceptorScript }');
    } },

  { id: 'REG-031', name: 'Shield stack filter includes patchright',
    bug: 'v5.x: Stack traces leak patchright frame filenames',
    check: function() { return shieldSource.includes('patchright'); } },

  { id: 'REG-032', name: 'No console.debug wrap in stealth (Patchright handles CDP leaks)',
    bug: 'v5.1.0-Final: console.debug wrap was detectable by prototype chain checks',
    check: function() {
      var lines = stealthSource.split('\n');
      for (var li = 0; li < lines.length; li++) {
        var line = lines[li].trim();
        if (line.startsWith('//')) continue;
        if (line.includes('console.debug')) return false;
      }
      return true;
    } }
];

// ─── Run all rules ───
process.stderr.write('\n🛡️  SENTINEL v6.0.0 — REGRESSION GATE\n');
process.stderr.write('   ' + rules.length + ' rules — each from a real historical bug\n\n');

var passed = 0;
var failed = 0;
var failures = [];

for (var i = 0; i < rules.length; i++) {
  var rule = rules[i];
  var ok = false;
  try { ok = rule.check(); } catch(e) { ok = false; }

  if (ok) {
    passed++;
    process.stderr.write('  ✅ ' + rule.id + ': ' + rule.name + '\n');
  } else {
    failed++;
    failures.push(rule);
    process.stderr.write('  ❌ ' + rule.id + ': ' + rule.name + '\n');
    process.stderr.write('     Bug: ' + rule.bug + '\n');
  }
}

process.stderr.write('\n══════════════════════════════\n');
process.stderr.write('Results: ' + passed + '/' + rules.length + ' PASSED');
if (failed > 0) {
  process.stderr.write(', ' + failed + ' FAILED\n');
  process.stderr.write('\n❌ REGRESSION GATE FAILED — Deploy BLOCKED\n');
  process.stderr.write('Fix the following before deploying:\n');
  for (var fi = 0; fi < failures.length; fi++) {
    process.stderr.write('  - ' + failures[fi].id + ': ' + failures[fi].name + ' (' + failures[fi].bug + ')\n');
  }
  process.exit(1);
} else {
  process.stderr.write('\n\n✅ ALL REGRESSION RULES PASSED — Safe to deploy\n');
}
