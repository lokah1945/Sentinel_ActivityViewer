// ═══════════════════════════════════════════════════════════════
//  SENTINEL v6.0.0 — UNIFIED REPORT GENERATOR
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.0.0 (2026-02-25):
//   FROM v5.0.0:
//   - CHANGED: Version strings to v6.0.0
//   - KEPT: ALL C-RPT-01 through C-RPT-10 contracts
//   - KEPT: JSON + HTML (dark theme) + CTX reports
//   - KEPT: strict scoping (no vc leak), timeSpanMs reduce pattern
//
// LAST HISTORY LOG:
//   v5.0.0: JSON + HTML + CTX, 1H5W summary (322 lines)
//   v6.0.0: Version bump, no logic changes
//
// CONTRACT: C-RPT-01 through C-RPT-10
// ═══════════════════════════════════════════════════════════════

var fs = require('fs');
var path = require('path');
var correlationEngine = require('../lib/correlation-engine');
var signatureDb = require('../lib/signature-db');

function generateReports(data, outputDir) {
  var events = data.events || [];
  var networkLog = data.networkLog || [];
  var injectionFlags = data.injectionFlags || {};
  var targetGraph = data.targetGraph || { inventory: [], totalTargets: 0, workerEvents: 0 };
  var frameInfo = data.frameInfo || [];
  var mode = data.mode || 'observe';
  var target = data.target || 'unknown';
  var version = 'sentinel-v6.1.0';
  var scanDate = new Date().toISOString();
  var timestamp = Date.now();

  // ─── [C-RPT-04] timeSpanMs = max(ts) - min(ts) via reduce ───
  var timeSpanMs = 0;
  if (events.length > 1) {
    var minTs = events.reduce(function(m, e) { return Math.min(m, e.ts || Infinity); }, Infinity);
    var maxTs = events.reduce(function(m, e) { return Math.max(m, e.ts || 0); }, 0);
    timeSpanMs = maxTs - minTs;
  }

  // Category breakdown
  var categories = {};
  for (var i = 0; i < events.length; i++) {
    var cat = events[i].cat || 'unknown';
    if (!categories[cat]) categories[cat] = { count: 0, risk: events[i].risk || 'medium', events: [] };
    categories[cat].count++;
    categories[cat].events.push(events[i]);
  }

  // Value captures
  var valueCaptures = [];
  for (var vi = 0; vi < events.length; vi++) {
    if (events[vi].val && events[vi].val !== 'undefined' && events[vi].val !== 'null' && events[vi].val !== '[unserializable]') {
      valueCaptures.push({
        ts: events[vi].ts,
        cat: events[vi].cat,
        api: events[vi].api,
        val: events[vi].val,
        dir: events[vi].dir || 'call'
      });
    }
  }

  // Correlation analysis
  var correlation = correlationEngine.analyzeCorrelation(events);

  // Network conversation
  var networkConversation = { pairs: [], totalRequests: 0, totalResponses: 0 };
  if (networkLog.length > 0) {
    var reqMap = {};
    for (var ni = 0; ni < networkLog.length; ni++) {
      var entry = networkLog[ni];
      if (entry.type === 'request') {
        reqMap[entry.url] = entry;
        networkConversation.totalRequests++;
      } else if (entry.type === 'response') {
        networkConversation.totalResponses++;
        var req = reqMap[entry.url];
        networkConversation.pairs.push({
          url: entry.url,
          method: req ? req.method : 'GET',
          requestHeaders: req ? req.headers : {},
          postData: req ? req.postData : '',
          responseStatus: entry.status,
          responseHeaders: entry.headers || {},
          responseBody: entry.body || '',
          responseSize: entry.size || 0,
          resourceType: req ? req.resourceType : ''
        });
      }
    }
  }

  // [C-RPT-05] Coverage proof — per-target inventory
  var coveredTargets = targetGraph.inventory.filter(function(t) { return t.injected && !t.skipReason; }).length;
  var totalTargets = targetGraph.inventory.length || 1;
  var frameCoverage = Math.round((coveredTargets / totalTargets) * 100);

  var categoriesDetected = Object.keys(categories).length;
  var coveragePercent = Math.round((categoriesDetected / 42) * 100 * 10) / 10;

  // [C-RPT-01] Build JSON report
  var jsonReport = {
    version: version,
    target: target,
    scanDate: scanDate,
    mode: mode,
    totalEvents: events.length,
    categoriesDetected: categoriesDetected + '/42',
    categoriesMonitored: 42,
    timeSpanMs: timeSpanMs,
    riskScore: correlation.riskScore + '/100',
    coveragePercent: coveragePercent,
    frameCoverage: frameCoverage,
    injectionFlags: injectionFlags,
    coverageProof: {
      targetGraph: targetGraph,
      frameCoverage: frameCoverage + '%',
      categoryCoverage: coveragePercent + '%'
    },
    categories: categories,
    networkConversation: networkConversation,
    valueCaptures: valueCaptures.slice(0, 200),
    correlation: correlation,
    forensic1H5W: generate1H5W(events, networkLog, correlation, target),
    threats: correlation.threats
  };

  // [C-RPT-03] Build CTX report
  var ctxReport = {
    version: version, target: target, scanDate: scanDate, mode: mode,
    frames: frameInfo,
    injectionStatus: injectionFlags,
    targetGraph: targetGraph,
    coverageProof: jsonReport.coverageProof
  };

  // Ensure output directory
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  var prefix = 'sentinel-' + mode + '-' + timestamp;

  // Write JSON
  var jsonPath = path.join(outputDir, prefix + '-report.json');
  fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2));

  // Write CTX
  var ctxPath = path.join(outputDir, prefix + '-context.json');
  fs.writeFileSync(ctxPath, JSON.stringify(ctxReport, null, 2));

  // [C-RPT-02] Write HTML
  var htmlPath = path.join(outputDir, prefix + '-report.html');
  var html = generateHTML(jsonReport, networkConversation, targetGraph, valueCaptures, correlation);
  fs.writeFileSync(htmlPath, html);

  return { jsonPath: jsonPath, htmlPath: htmlPath, ctxPath: ctxPath, report: jsonReport };
}

function generate1H5W(events, networkLog, correlation, target) {
  var who = [];
  var what = {};
  var when = [];
  var where = { origins: [], destinations: [] };
  var why = [];
  var how = [];

  // WHO — unique sources
  var sources = {};
  for (var i = 0; i < events.length; i++) {
    var src = events[i].src || 'unknown';
    if (!sources[src]) { sources[src] = 0; }
    sources[src]++;
  }
  who = Object.keys(sources).slice(0, 10).map(function(s) { return { source: s.substring(0, 200), eventCount: sources[s] }; });

  // WHAT — category breakdown
  for (var wi = 0; wi < events.length; wi++) {
    if (!what[events[wi].cat]) what[events[wi].cat] = 0;
    what[events[wi].cat]++;
  }

  // WHEN — burst timeline
  when = (correlation.bursts || []).map(function(b) {
    return { startMs: b.startTs, events: b.eventCount, categories: b.categories };
  });

  // WHERE — from network log
  for (var whi = 0; whi < networkLog.length; whi++) {
    var url = networkLog[whi].url || '';
    try {
      var hostname = url.split('/')[2] || url;
      if (networkLog[whi].type === 'request') { if (where.destinations.indexOf(hostname) < 0) where.destinations.push(hostname); }
      else { if (where.origins.indexOf(hostname) < 0) where.origins.push(hostname); }
    } catch(e) {}
  }

  // WHY — attribution
  why = (correlation.libraryAttribution || []).map(function(a) {
    return { library: a.library, confidence: a.confidence, match: a.matchedCategories };
  });

  // HOW — techniques used
  var catList = Object.keys(what);
  for (var hi = 0; hi < catList.length; hi++) {
    if (what[catList[hi]] > 5) {
      how.push({ technique: catList[hi], eventCount: what[catList[hi]] });
    }
  }

  return { who: who, what: what, when: when, where: where, why: why, how: how };
}

// [C-RPT-02/08/09] HTML generation — strict scoping, Object.entries().map()
function generateHTML(report, networkConv, targetGraph, valueCaptures, correlation) {
  var catRows = Object.keys(report.categories).map(function(catName) {
    var catData = report.categories[catName];
    var riskClass = catData.risk === 'critical' ? 'risk-critical' : catData.risk === 'high' ? 'risk-high' : 'risk-med';
    return '<tr><td>' + escHtml(catName) + '</td><td>' + catData.count + '</td><td class="' + riskClass + '">' + escHtml(catData.risk) + '</td></tr>';
  }).join('\n');

  // [C-RPT-08] Separate variable for value captures — NO 'vc' leak
  var vcRows = valueCaptures.slice(0, 50).map(function(entry) {
    return '<tr><td>' + entry.ts + '</td><td>' + escHtml(entry.cat) + '</td><td>' + escHtml(entry.api) + '</td><td>' + escHtml(String(entry.val).substring(0, 100)) + '</td><td>' + (entry.dir || 'call') + '</td></tr>';
  }).join('\n');

  var networkRows = (networkConv.pairs || []).slice(0, 50).map(function(pair) {
    return '<tr><td><span class="badge">' + escHtml(pair.method) + '</span></td><td class="url-cell">' + escHtml((pair.url || '').substring(0, 80)) + '</td><td>' + (pair.responseStatus || '') + '</td><td>' + escHtml(String(pair.responseSize || '')) + '</td></tr>';
  }).join('\n');

  var targetRows = (targetGraph.inventory || []).map(function(t) {
    return '<tr><td>' + escHtml(t.targetId) + '</td><td>' + escHtml(t.type) + '</td><td class="url-cell">' + escHtml((t.url || '').substring(0, 60)) + '</td><td>' + (t.injected ? '✅' : '❌') + '</td><td>' + (t.bootOk ? '✅' : '❌') + '</td><td>' + escHtml(t.skipReason || '') + '</td></tr>';
  }).join('\n');

  var threatRows = (report.threats || []).slice(0, 30).map(function(t) {
    var riskClass = t.risk === 'critical' ? 'risk-critical' : t.risk === 'high' ? 'risk-high' : 'risk-med';
    return '<tr><td class="' + riskClass + '">' + escHtml(t.risk) + '</td><td>' + escHtml(t.category) + '</td><td>' + escHtml(t.api) + '</td><td>' + escHtml((t.detail || '').substring(0, 120)) + '</td></tr>';
  }).join('\n');

  var burstRows = (correlation.bursts || []).map(function(b) {
    return '<tr><td>' + b.startTs + '</td><td>' + b.eventCount + '</td><td>' + b.categories + '</td><td>' + (b.topCategories || []).join(', ') + '</td></tr>';
  }).join('\n');

  var libRows = (correlation.libraryAttribution || []).map(function(a) {
    return '<tr><td>' + escHtml(a.library) + '</td><td>' + a.matchedCategories + '</td><td>' + (a.urlMatch ? '✅' : '❌') + '</td><td>' + escHtml(a.confidence) + '</td></tr>';
  }).join('\n');

  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">' +
    '<title>Sentinel v6.1.0 — ' + escHtml(report.target) + '</title>' +
    '<style>' + getCSS() + '</style></head><body>' +
    '<div class="container">' +
    '<header><h1>🛡️ Sentinel v6.1.0 — Unified Forensic Engine</h1>' +
    '<p class="subtitle">Target: <strong>' + escHtml(report.target) + '</strong> | Mode: <strong>' + escHtml(report.mode) + '</strong> | ' + escHtml(report.scanDate) + '</p></header>' +

    // KPI Cards
    '<div class="kpi-grid">' +
    kpiCard('Total Events', report.totalEvents, report.totalEvents > 1000 ? 'good' : report.totalEvents > 500 ? 'warn' : 'bad') +
    kpiCard('Risk Score', report.riskScore, 'bad') +
    kpiCard('Categories', report.categoriesDetected, '') +
    kpiCard('Duration', Math.round(report.timeSpanMs / 1000 * 10) / 10 + 's', '') +
    kpiCard('Frame Coverage', report.frameCoverage + '%', report.frameCoverage >= 80 ? 'good' : 'warn') +
    kpiCard('Threats', report.threats.length, report.threats.length > 10 ? 'bad' : 'warn') +
    kpiCard('Network Pairs', (networkConv.pairs || []).length, '') +
    kpiCard('Target Graph', (targetGraph.inventory || []).length + ' targets', '') +
    '</div>' +

    // Injection Status
    '<section><h2>Injection Status</h2><div class="flags">' +
    Object.keys(report.injectionFlags).map(function(k) {
      return '<span class="flag ' + (report.injectionFlags[k] ? 'flag-ok' : 'flag-fail') + '">' + k + ': ' + report.injectionFlags[k] + '</span>';
    }).join(' ') +
    '</div></section>' +

    // Categories
    '<section><h2>Categories Detected (' + report.categoriesDetected + ')</h2>' +
    '<table><thead><tr><th>Category</th><th>Events</th><th>Risk</th></tr></thead><tbody>' + catRows + '</tbody></table></section>' +

    // Threats
    '<section><h2>Threats (' + report.threats.length + ')</h2>' +
    '<table><thead><tr><th>Risk</th><th>Category</th><th>API</th><th>Detail</th></tr></thead><tbody>' + threatRows + '</tbody></table></section>' +

    // Bursts
    '<section><h2>Fingerprint Bursts (' + (correlation.bursts || []).length + ')</h2>' +
    '<table><thead><tr><th>Start (ts)</th><th>Events</th><th>Categories</th><th>Top Categories</th></tr></thead><tbody>' + burstRows + '</tbody></table></section>' +

    // Library Attribution
    '<section><h2>Library Attribution</h2>' +
    '<table><thead><tr><th>Library</th><th>Matched</th><th>URL Match</th><th>Confidence</th></tr></thead><tbody>' + libRows + '</tbody></table></section>' +

    // Network Conversation
    '<section><h2>Network Conversation (' + (networkConv.pairs || []).length + ' pairs)</h2>' +
    '<table><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Size</th></tr></thead><tbody>' + networkRows + '</tbody></table></section>' +

    // Target Graph Inventory
    '<section><h2>Target Graph Inventory (' + (targetGraph.inventory || []).length + ' targets)</h2>' +
    '<table><thead><tr><th>ID</th><th>Type</th><th>URL</th><th>Injected</th><th>Boot</th><th>Skip Reason</th></tr></thead><tbody>' + targetRows + '</tbody></table></section>' +

    // Value Captures
    '<section><h2>Value Captures (top 50)</h2>' +
    '<table><thead><tr><th>Timestamp</th><th>Category</th><th>API</th><th>Value</th><th>Direction</th></tr></thead><tbody>' + vcRows + '</tbody></table></section>' +

    // Entropy
    '<section><h2>Entropy Analysis</h2>' +
    '<p>Category entropy: <strong>' + correlation.entropy.category + '</strong> | API entropy: <strong>' + correlation.entropy.api + '</strong></p></section>' +

    // 1H5W
    '<section><h2>1H5W Forensic Summary</h2>' +
    '<div class="h5w-box"><h3>WHO</h3><pre>' + escHtml(JSON.stringify(report.forensic1H5W.who, null, 1).substring(0, 500)) + '</pre></div>' +
    '<div class="h5w-box"><h3>WHAT</h3><pre>' + escHtml(JSON.stringify(report.forensic1H5W.what, null, 1).substring(0, 500)) + '</pre></div>' +
    '<div class="h5w-box"><h3>WHERE</h3><pre>' + escHtml(JSON.stringify(report.forensic1H5W.where, null, 1).substring(0, 500)) + '</pre></div>' +
    '<div class="h5w-box"><h3>WHY</h3><pre>' + escHtml(JSON.stringify(report.forensic1H5W.why, null, 1).substring(0, 300)) + '</pre></div>' +
    '</div>' +

    '<footer><p>Sentinel v6.1.0 Unified Forensic Engine — Generated ' + new Date().toISOString() + '</p></footer>' +
    '</div></body></html>';
}

function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function kpiCard(label, value, type) {
  return '<div class="kpi ' + (type || '') + '"><div class="kpi-value">' + value + '</div><div class="kpi-label">' + label + '</div></div>';
}

function getCSS() {
  return '*{margin:0;padding:0;box-sizing:border-box}body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Noto Sans,Helvetica,Arial,sans-serif;line-height:1.6}.container{max-width:1200px;margin:0 auto;padding:20px}header{text-align:center;padding:30px 0;border-bottom:1px solid #30363d}h1{color:#58a6ff;font-size:1.8em}h2{color:#58a6ff;margin:20px 0 10px;font-size:1.3em;border-bottom:1px solid #21262d;padding-bottom:5px}.subtitle{color:#8b949e;margin-top:8px}.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin:20px 0}.kpi{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}.kpi.good{border-color:#238636}.kpi.warn{border-color:#d29922}.kpi.bad{border-color:#da3633}.kpi-value{font-size:1.6em;font-weight:bold;color:#f0f6fc}.kpi-label{color:#8b949e;font-size:0.85em;margin-top:4px}table{width:100%;border-collapse:collapse;margin:10px 0;font-size:0.9em}th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #21262d}th{background:#161b22;color:#58a6ff;font-weight:600}tr:hover{background:#161b22}.url-cell{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.badge{background:#238636;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em}.risk-critical{color:#ff7b72;font-weight:bold}.risk-high{color:#ffa657}.risk-med{color:#d29922}.flags{display:flex;flex-wrap:wrap;gap:8px}.flag{padding:4px 10px;border-radius:4px;font-size:0.85em}.flag-ok{background:#0d4429;color:#3fb950;border:1px solid #238636}.flag-fail{background:#3d1e20;color:#ff7b72;border:1px solid #da3633}section{margin:25px 0}.h5w-box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;margin:8px 0}.h5w-box h3{color:#ffa657;margin-bottom:6px}.h5w-box pre{color:#c9d1d9;white-space:pre-wrap;font-size:0.85em;max-height:200px;overflow-y:auto}footer{text-align:center;color:#484f58;padding:30px 0;border-top:1px solid #21262d;margin-top:30px}';
}

module.exports = { generateReports };
