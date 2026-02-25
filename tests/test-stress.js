// ═══════════════════════════════════════════════════════════════
//  SENTINEL v6.0.0 — STRESS TEST (1000 iterations)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.0.0 (2026-02-25):
//   FROM v5.0.0:
//   - UPDATED: Version checks from v5 to v6
//   - ADDED: EventPipeline stress test (dedup, batch, stats)
//   - KEPT: Script generation + report generation stress tests
//
// LAST HISTORY LOG:
//   v5.0.0: 1000 iterations, script gen + report gen
//   v6.0.0: Added EventPipeline tests
// ═══════════════════════════════════════════════════════════════

var { generateShieldScript } = require('../hooks/anti-detection-shield');
var { generateStealthScript } = require('../hooks/stealth-config');
var { generateInterceptorScript } = require('../hooks/api-interceptor');
var { TargetGraph } = require('../lib/target-graph');
var { generateReports } = require('../reporters/report-generator');
var { EventPipeline } = require('../lib/event-pipeline');
var fs = require('fs');
var path = require('path');
var os = require('os');

var ITERATIONS = 1000;
var errors = 0;
var startTime = Date.now();

process.stderr.write('\n🛡️  SENTINEL v6.0.0 — STRESS TEST (' + ITERATIONS + ' iterations)\n\n');

for (var i = 0; i < ITERATIONS; i++) {
  try {
    // Script generation integrity
    var shield = generateShieldScript();
    var stealth = generateStealthScript();
    var interceptor = generateInterceptorScript();

    if (typeof shield !== 'string' || shield.length < 100) throw new Error('Shield script too short');
    if (typeof stealth !== 'string' || stealth.length < 50) throw new Error('Stealth script too short');
    if (typeof interceptor !== 'string' || interceptor.length < 500) throw new Error('Interceptor script too short');

    // Validate script syntax (basic check)
    if (!shield.includes('SENTINEL_SHIELD')) throw new Error('Shield missing SENTINEL_SHIELD');
    if (!interceptor.includes('SENTINEL_DATA')) throw new Error('Interceptor missing SENTINEL_DATA');
    if (!interceptor.includes('categoriesMonitored')) throw new Error('Interceptor missing categoriesMonitored');

    // EventPipeline stress test
    var pipeline = new EventPipeline({ maxEvents: 10000 });
    var cats = ['canvas','webgl','audio','font-detection','fingerprint','storage','network','screen','webrtc','exfiltration','permissions','speech'];
    var risks = ['low','medium','high','critical'];
    var eventCount = 50 + Math.floor(Math.random() * 200);

    for (var j = 0; j < eventCount; j++) {
      pipeline.push({
        ts: Date.now() + j,
        cat: cats[j % cats.length],
        api: 'test-api-' + (j % 20),
        risk: risks[j % risks.length],
        source: 'stress-test-' + i,
        detail: 'test detail ' + j,
        val: 'test_value_' + Math.random(),
        dir: Math.random() > 0.5 ? 'call' : 'response',
        fid: 'main'
      });
    }

    var stats = pipeline.getStats();
    if (stats.total < 1) throw new Error('Pipeline empty after ' + eventCount + ' pushes');
    if (Object.keys(stats.categories).length < 1) throw new Error('Pipeline no categories');

    // Test dedup
    var firstEvent = pipeline.getAll()[0];
    pipeline.push(firstEvent); // should be deduped
    var statsAfter = pipeline.getStats();
    if (statsAfter.total !== stats.total) throw new Error('Dedup failed');

    // Report generation
    var events = [];
    for (var ej = 0; ej < eventCount; ej++) {
      events.push({
        ts: Date.now() + ej * 10,
        cat: cats[ej % cats.length],
        api: 'test-api-' + ej,
        risk: risks[ej % risks.length],
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

    if (!fs.existsSync(result.jsonPath)) throw new Error('JSON report not created');
    if (!fs.existsSync(result.htmlPath)) throw new Error('HTML report not created');

    var jsonContent = fs.readFileSync(result.jsonPath, 'utf8');
    var parsed = JSON.parse(jsonContent);
    if (!parsed.version || parsed.version !== 'sentinel-v6.0.0') throw new Error('Wrong version in report: ' + parsed.version);
    if (parsed.categoriesMonitored !== 42) throw new Error('categoriesMonitored not 42');

    var htmlContent = fs.readFileSync(result.htmlPath, 'utf8');
    if (htmlContent.includes('vc is not defined') || htmlContent.includes('undefined is not')) throw new Error('vc bug detected!');
    if (!htmlContent.includes('Sentinel v6.0.0')) throw new Error('Version missing in HTML');

    if (eventCount > 1 && parsed.timeSpanMs === 0) throw new Error('timeSpanMs is 0 with ' + eventCount + ' events');

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
