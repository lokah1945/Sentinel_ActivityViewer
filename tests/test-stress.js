// ═══════════════════════════════════════════════════════════════
//  SENTINEL v5.0.0 — STRESS TEST (1000 iterations)
//  Validates script generation + report generation integrity
// ═══════════════════════════════════════════════════════════════

var { generateShieldScript } = require('../hooks/anti-detection-shield');
var { generateStealthScript } = require('../hooks/stealth-config');
var { generateInterceptorScript } = require('../hooks/api-interceptor');
var { TargetGraph } = require('../lib/target-graph');
var { generateReports } = require('../reporters/report-generator');
var fs = require('fs');
var path = require('path');
var os = require('os');

var ITERATIONS = 1000;
var errors = 0;
var startTime = Date.now();

process.stderr.write('\n🛡️  SENTINEL v5.0.0 — STRESS TEST (' + ITERATIONS + ' iterations)\n\n');

for (var i = 1; i <= ITERATIONS; i++) {
  try {
    // 1. Script generation
    var shield = generateShieldScript();
    var stealth = generateStealthScript();
    var interceptor = generateInterceptorScript();

    if (typeof shield !== 'string' || shield.length < 100) throw new Error('Shield script invalid');
    if (typeof stealth !== 'string' || stealth.length < 50) throw new Error('Stealth script invalid');
    if (typeof interceptor !== 'string' || interceptor.length < 1000) throw new Error('Interceptor script invalid');

    // 2. Validate JS syntax
    try { new Function(shield); } catch(e) { throw new Error('Shield JS syntax error: ' + e.message); }
    try { new Function(stealth); } catch(e) { throw new Error('Stealth JS syntax error: ' + e.message); }
    try { new Function(interceptor); } catch(e) { throw new Error('Interceptor JS syntax error: ' + e.message); }

    // 3. Check interceptor invariants
    if (!interceptor.includes('BOOT_OK')) throw new Error('BOOT_OK missing');
    if (!interceptor.includes('categoriesMonitored')) throw new Error('categoriesMonitored missing');
    if (!interceptor.includes('smartHookGetter')) throw new Error('smartHookGetter missing');
    if (!interceptor.includes('SENTINEL_PUSH')) throw new Error('SENTINEL_PUSH missing');
    if (!interceptor.includes('getBattery')) throw new Error('getBattery missing');
    if (!interceptor.includes('matchMedia')) throw new Error('matchMedia missing');
    if (!interceptor.includes('visibilitychange')) throw new Error('visibilitychange missing');

    // 4. Check quiet mode
    if (!interceptor.includes('enumerable: false')) throw new Error('Quiet mode missing');
    if (!shield.includes('enumerable: false')) throw new Error('Shield quiet mode missing');
    if (stealth.includes('console.log')) throw new Error('Console.log in stealth!');

    // 5. Report generation with random events
    var eventCount = Math.floor(Math.random() * 200);
    var cats = ['canvas','webgl','audio','font-detection','fingerprint','screen','storage','network','webrtc','math-fingerprint','battery','css-fingerprint'];
    var events = [];
    for (var j = 0; j < eventCount; j++) {
      events.push({
        ts: Date.now() - Math.floor(Math.random() * 30000),
        cat: cats[Math.floor(Math.random() * cats.length)],
        api: 'test_api_' + j,
        risk: ['critical','high','medium','low'][Math.floor(Math.random() * 4)],
        val: 'test_value_' + Math.random(),
        detail: 'test detail',
        src: 'test',
        dir: Math.random() > 0.5 ? 'call' : 'response',
        fid: 'main'
      });
    }

    var tmpDir = path.join(os.tmpdir(), 'sentinel-stress-' + i);
    fs.mkdirSync(tmpDir, { recursive: true });

    var result = generateReports({
      events: events,
      networkLog: [],
      injectionFlags: { layer1: true, layer2: true },
      targetGraph: { inventory: [{ targetId: 'main', type: 'page', url: 'test', networkEnabled: true, injected: true, bootOk: true, eventsCollected: eventCount, skipReason: '' }], totalTargets: 1, workerEvents: 0 },
      frameInfo: [{ url: 'test', name: 'main' }],
      mode: 'stress-test',
      target: 'https://test.example.com'
    }, tmpDir);

    // Validate report outputs
    if (!fs.existsSync(result.jsonPath)) throw new Error('JSON report not created');
    if (!fs.existsSync(result.htmlPath)) throw new Error('HTML report not created');

    var jsonContent = fs.readFileSync(result.jsonPath, 'utf8');
    var parsed = JSON.parse(jsonContent);
    if (!parsed.version || parsed.version !== 'sentinel-v5.0.0') throw new Error('Wrong version in report');
    if (parsed.categoriesMonitored !== 42) throw new Error('categoriesMonitored not 42');

    var htmlContent = fs.readFileSync(result.htmlPath, 'utf8');
    if (htmlContent.includes('vc is not defined') || htmlContent.includes('undefined is not')) throw new Error('vc bug detected!');
    if (!htmlContent.includes('Sentinel v5.0.0')) throw new Error('Version missing in HTML');

    // Check timeSpanMs correctness
    if (eventCount > 1 && parsed.timeSpanMs === 0) throw new Error('timeSpanMs is 0 with ' + eventCount + ' events');

    // Cleanup
    fs.rmSync(tmpDir, { recursive: true, force: true });

  } catch (e) {
    errors++;
    process.stderr.write('  ❌ Iteration ' + i + ': ' + e.message + '\n');
  }

  if (i % 100 === 0) {
    process.stderr.write('  ' + i + '/' + ITERATIONS + ' — ' + errors + ' errors\n');
  }
}

var elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
process.stderr.write('\n══════════════════════════════\n');
process.stderr.write('STRESS TEST COMPLETE: ' + ITERATIONS + '/' + ITERATIONS + ' in ' + elapsed + 's\n');
if (errors === 0) {
  process.stderr.write('✅ ZERO ERRORS across ' + ITERATIONS + ' iterations!\n');
} else {
  process.stderr.write('❌ ' + errors + ' ERRORS detected\n');
  process.exit(1);
}
