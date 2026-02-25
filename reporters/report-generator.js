// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — REPORT GENERATOR (JSON + HTML + CTX)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - FROM v6.4: Full report generation with JSON, HTML, context
//   - REG-012: No unscoped 'vc' variable
//   - NEW: Dual-telemetry stats in report
//   - NEW: Hook vs CDP source breakdown
//   - NEW: Category coverage percentage
// ═══════════════════════════════════════════════════════════════

'use strict';

var fs = require('fs');
var path = require('path');

function ReportGenerator(version) {
  this._version = version;
}

ReportGenerator.prototype.save = function(mode, timestamp, events, analysis, contextData) {
  var outputDir = path.join(process.cwd(), 'output');
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  var baseName = 'sentinel-' + mode + '-' + timestamp;

  // JSON report
  var jsonPath = path.join(outputDir, baseName + '-report.json');
  var jsonReport = {
    version: this._version,
    mode: mode,
    timestamp: timestamp,
    scanDate: new Date(timestamp).toISOString(),
    totalEvents: events.length,
    categoryCount: analysis.categoryCount,
    riskScore: analysis.riskScore,
    timeSpanMs: analysis.timeSpanMs,
    hookStats: analysis.hookStats,
    libraryDetections: analysis.libraryDetections,
    categories: analysis.categories,
    bursts: analysis.bursts,
    timeline: analysis.timeline,
    events: events
  };
  fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2));

  // Context file
  var ctxPath = path.join(outputDir, baseName + '-context.json');
  fs.writeFileSync(ctxPath, JSON.stringify(contextData, null, 2));

  // HTML report
  var htmlPath = path.join(outputDir, baseName + '-report.html');
  var html = this._generateHTML(mode, timestamp, events, analysis, contextData);
  fs.writeFileSync(htmlPath, html);

  return { json: jsonPath, html: htmlPath, context: ctxPath };
};

ReportGenerator.prototype._generateHTML = function(mode, timestamp, events, analysis, ctx) {
  var catRows = '';
  for (var i = 0; i < analysis.categories.length; i++) {
    var cat = analysis.categories[i];
    var srcStr = '';
    if (cat.sources) {
      var srcParts = [];
      for (var sk in cat.sources) { if (cat.sources.hasOwnProperty(sk)) srcParts.push(sk + ':' + cat.sources[sk]); }
      srcStr = srcParts.join(', ');
    }
    var riskStr = '';
    if (cat.risks) {
      var riskParts = [];
      for (var rk in cat.risks) { if (cat.risks.hasOwnProperty(rk)) riskParts.push(rk + ':' + cat.risks[rk]); }
      riskStr = riskParts.join(', ');
    }
    catRows += '<tr><td>' + cat.name + '</td><td>' + cat.count + '</td><td>' + srcStr + '</td><td>' + riskStr + '</td></tr>';
  }

  var libRows = '';
  for (var j = 0; j < analysis.libraryDetections.length; j++) {
    var lib = analysis.libraryDetections[j];
    libRows += '<tr><td>' + lib.name + '</td><td>' + (lib.detail || '') + '</td></tr>';
  }

  var eventRows = '';
  var maxDisplay = Math.min(events.length, 5000);
  for (var k = 0; k < maxDisplay; k++) {
    var ev = events[k];
    var riskClass = ev.risk === 'critical' ? 'risk-critical' : ev.risk === 'high' ? 'risk-high' : ev.risk === 'medium' ? 'risk-medium' : '';
    eventRows += '<tr class="' + riskClass + '">'
      + '<td>' + new Date(ev.ts).toISOString().slice(11, 23) + '</td>'
      + '<td>' + (ev.src || '') + '</td>'
      + '<td>' + (ev.cat || '') + '</td>'
      + '<td>' + (ev.api || '') + '</td>'
      + '<td>' + (ev.risk || '') + '</td>'
      + '<td>' + ((ev.detail || '').slice(0, 200)) + '</td>'
      + '</tr>';
  }

  var hookPct = analysis.hookStats ? analysis.hookStats.hookRatio : '0%';
  var catCoverage = ctx.categoryCoverage || '0%';

  return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>SENTINEL ' + this._version + ' - ' + mode + '</title>'
    + '<style>'
    + 'body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:20px;}'
    + 'h1{color:#58a6ff;}h2{color:#79c0ff;margin-top:30px;}'
    + 'table{border-collapse:collapse;width:100%;margin:10px 0;}'
    + 'th,td{border:1px solid #30363d;padding:6px 10px;text-align:left;font-size:12px;}'
    + 'th{background:#161b22;color:#58a6ff;}'
    + 'tr:hover{background:#161b22;}'
    + '.risk-critical{background:#3d1014;}'.concat('.risk-high{background:#2d1b00;}')
    + '.risk-medium{background:#1c2330;}'
    + '.stat-box{display:inline-block;background:#161b22;padding:15px 25px;margin:5px;border-radius:8px;border:1px solid #30363d;}'
    + '.stat-num{font-size:24px;font-weight:bold;color:#58a6ff;}'
    + '.stat-label{font-size:11px;color:#8b949e;margin-top:5px;}'
    + '</style></head><body>'
    + '<h1>' + this._version + ' &mdash; ' + mode.toUpperCase() + ' REPORT</h1>'
    + '<p>Target: <b>' + (ctx.target || '') + '</b> | Date: ' + new Date(timestamp).toISOString() + '</p>'
    + '<p>Engine: ' + (ctx.engine || 'hybrid') + ' | Headless: ' + ctx.headless + ' | Stealth: ' + ctx.stealthEnabled + '</p>'
    + '<div>'
    + '<div class="stat-box"><div class="stat-num">' + events.length + '</div><div class="stat-label">Total Events</div></div>'
    + '<div class="stat-box"><div class="stat-num">' + analysis.categoryCount + '/42</div><div class="stat-label">Categories</div></div>'
    + '<div class="stat-box"><div class="stat-num">' + analysis.riskScore + '</div><div class="stat-label">Risk Score</div></div>'
    + '<div class="stat-box"><div class="stat-num">' + catCoverage + '</div><div class="stat-label">Coverage</div></div>'
    + '<div class="stat-box"><div class="stat-num">' + hookPct + '</div><div class="stat-label">Hook Events</div></div>'
    + '<div class="stat-box"><div class="stat-num">' + analysis.libraryDetections.length + '</div><div class="stat-label">Libraries</div></div>'
    + '</div>'
    + '<h2>Categories (' + analysis.categoryCount + ')</h2>'
    + '<table><tr><th>Category</th><th>Count</th><th>Sources</th><th>Risks</th></tr>' + catRows + '</table>'
    + (libRows ? '<h2>Libraries Detected</h2><table><tr><th>Library</th><th>Detail</th></tr>' + libRows + '</table>' : '')
    + '<h2>Events (showing ' + maxDisplay + ' of ' + events.length + ')</h2>'
    + '<table><tr><th>Time</th><th>Src</th><th>Category</th><th>API</th><th>Risk</th><th>Detail</th></tr>' + eventRows + '</table>'
    + '</body></html>';
};

module.exports = { ReportGenerator: ReportGenerator };
