// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — UNIFIED REPORT GENERATOR
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - FROM v6.4: report-generator.js HTML/JSON/CTX structure
//   - NEW: Hook stats section in HTML (hookEvents, hookCategories)
//   - NEW: Source breakdown (hook vs CDP vs page)
//   - NEW: Dual-telemetry dashboard KPIs
//   - FIX: REG-012 — No unscoped `vc` variable in report
//   - FIX: HTML responsive design preserved from v6.4
//
// LAST HISTORY LOG:
//   v6.4.0: report-generator.js (lib/) — CDP-only stats
//   v7.0.0: Enhanced with dual-telemetry stats
// ═══════════════════════════════════════════════════════════════

'use strict';

var fs = require('fs');
var path = require('path');

class ReportGenerator {
  constructor(version) {
    this.version = version;
    this.outputDir = path.join(process.cwd(), 'output');
    if (!fs.existsSync(this.outputDir)) fs.mkdirSync(this.outputDir, { recursive: true });
  }

  save(mode, ts, events, analysis, context) {
    var base = 'sentinel-' + mode + '-' + ts;
    var jp = path.join(this.outputDir, base + '-report.json');
    var hp = path.join(this.outputDir, base + '-report.html');
    var cp = path.join(this.outputDir, base + '-context.json');

    fs.writeFileSync(jp, JSON.stringify({
      version: this.version,
      target: context.target,
      mode: mode,
      timestamp: new Date(ts).toISOString(),
      events: events,
      analysis: analysis
    }, null, 2));

    fs.writeFileSync(cp, JSON.stringify(context, null, 2));
    fs.writeFileSync(hp, this._html(analysis, context, events));

    return { json: jp, html: hp, context: cp };
  }

  _html(analysis, ctx, events) {
    var cats = analysis.categories || [];
    var threats = analysis.threats || [];
    var libs = analysis.libraryDetections || [];
    var netConv = analysis.networkConversation || [];
    var cookies = analysis.cookies || {};
    var ws = analysis.websockets || [];
    var tp = analysis.thirdParties || [];
    var entropy = analysis.entropy || {};
    var h5w = analysis.h5w || {};
    var riskScore = analysis.riskScore || 0;
    var hookStats = analysis.hookStats || {};
    var pStats = analysis.pipelineStats || {};
    var bursts = analysis.bursts || [];
    var exfil = analysis.exfiltration || [];
    var timeline = analysis.timeline || [];

    var h = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">';
    h += '<title>' + this.version + ' ' + ctx.target + '</title>';
    h += '<style>';
    h += '*{margin:0;padding:0;box-sizing:border-box}body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.6}';
    h += '.c{max-width:1400px;margin:0 auto;padding:20px}header{text-align:center;padding:30px 0;border-bottom:1px solid #30363d}';
    h += 'h1{color:#58a6ff;font-size:1.8em}h2{color:#58a6ff;margin:20px 0 10px;font-size:1.2em;border-bottom:1px solid #21262d;padding-bottom:5px}';
    h += '.sub{color:#8b949e;margin-top:8px}.kg{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin:16px 0}';
    h += '.k{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;text-align:center}';
    h += '.k.g{border-color:#238636}.k.w{border-color:#d29922}.k.b{border-color:#da3633}';
    h += '.kv{font-size:1.5em;font-weight:bold;color:#f0f6fc}.kl{color:#8b949e;font-size:0.8em;margin-top:4px}';
    h += 'table{width:100%;border-collapse:collapse;margin:8px 0;font-size:0.85em}';
    h += 'th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #21262d}th{background:#161b22;color:#58a6ff;font-weight:600}';
    h += 'tr:hover{background:#161b22}.bd{background:#238636;color:#fff;padding:2px 6px;border-radius:4px;font-size:0.75em}';
    h += '.rc{color:#ff7b72;font-weight:bold}.rh{color:#ffa657}.rm{color:#d29922}.rl{color:#8b949e}';
    h += '.u{max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}';
    h += '.hb{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px;margin:6px 0}';
    h += '.hb h3{color:#ffa657;margin-bottom:4px;font-size:1em}';
    h += '.hybrid{background:#0d4429;color:#3fb950;padding:4px 12px;border-radius:6px;display:inline-block;margin:8px 0;font-weight:bold}';
    h += 'footer{text-align:center;color:#484f58;padding:20px 0;border-top:1px solid #21262d;margin-top:20px;font-size:0.85em}';
    h += '</style></head><body><div class="c">';

    // ─── HEADER ───
    h += '<header>';
    h += '<h1>\uD83D\uDEE1\uFE0F ' + this.version + ' \u2014 Hybrid Dual-Telemetry CCTV</h1>';
    h += '<p class="sub">Target: <strong>' + ctx.target + '</strong> | Mode: <strong>' + ctx.mode + '</strong> | ' + ctx.scanDate + '</p>';
    h += '<span class="hybrid">HOOK + CDP DUAL ENGINE</span>';
    h += '</header>';

    // ─── KPI DASHBOARD ───
    h += '<h2>\uD83D\uDCCA Dashboard</h2><div class="kg">';
    h += this._kpi(events.length, 'Total Events', events.length >= 1500 ? 'g' : events.length >= 500 ? 'w' : 'b');
    h += this._kpi(cats.length, 'Categories', cats.length >= 30 ? 'g' : cats.length >= 15 ? 'w' : 'b');
    h += this._kpi(riskScore, 'Risk Score', riskScore >= 50 ? 'b' : riskScore >= 20 ? 'w' : 'g');
    h += this._kpi(pStats.hookEvents || 0, 'Hook Events', 'w');
    h += this._kpi(pStats.cdpEvents || 0, 'CDP Events', 'w');
    h += this._kpi(pStats.pageEvents || 0, 'Page Events', 'w');
    h += this._kpi(libs.length, 'Libraries', libs.length > 0 ? 'b' : 'g');
    h += this._kpi(hookStats.totalCategories || 0, 'Cat Coverage', '');
    h += '</div>';

    // ─── HOOK VS CDP BREAKDOWN ───
    if (hookStats.hookEventCount || hookStats.cdpEventCount) {
      h += '<h2>\uD83D\uDD0D Source Telemetry Breakdown</h2>';
      h += '<div class="hb">';
      h += '<h3>Hook Layer: ' + (hookStats.hookEventCount || 0) + ' events in ' + (hookStats.hookCategories || []).length + ' categories</h3>';
      h += '<p style="color:#8b949e;font-size:0.85em">' + (hookStats.hookCategories || []).join(', ') + '</p>';
      h += '</div>';
      h += '<div class="hb">';
      h += '<h3>CDP Observer: ' + (hookStats.cdpEventCount || 0) + ' events in ' + (hookStats.cdpCategories || []).length + ' categories</h3>';
      h += '<p style="color:#8b949e;font-size:0.85em">' + (hookStats.cdpCategories || []).join(', ') + '</p>';
      h += '</div>';
    }

    // ─── CATEGORIES TABLE ───
    h += '<h2>\uD83D\uDCDD Event Categories (' + cats.length + ')</h2>';
    h += '<table><tr><th>Category</th><th>Events</th><th>Risk</th><th>Sources</th></tr>';
    for (var i = 0; i < cats.length; i++) {
      var c = cats[i];
      var rc = c.risk === 'critical' ? 'rc' : c.risk === 'high' ? 'rh' : c.risk === 'medium' ? 'rm' : 'rl';
      var srcStr = Object.entries(c.sources || {}).map(function(e) { return e[0] + ':' + e[1]; }).join(', ');
      h += '<tr><td>' + c.name + '</td><td>' + c.events + '</td><td class="' + rc + '">' + c.risk + '</td><td>' + srcStr + '</td></tr>';
    }
    h += '</table>';

    // ─── THREATS ───
    if (threats.length > 0) {
      h += '<h2>\u26A0\uFE0F Threats (' + threats.length + ')</h2>';
      h += '<table><tr><th>Risk</th><th>Category</th><th>API</th><th>Detail</th><th>Src</th></tr>';
      for (var i = 0; i < Math.min(threats.length, 100); i++) {
        var t = threats[i];
        var tc = t.risk === 'critical' ? 'rc' : 'rh';
        h += '<tr><td class="' + tc + '">' + t.risk + '</td><td>' + t.category + '</td><td>' + t.api + '</td><td class="u">' + (t.detail || '').slice(0, 120) + '</td><td>' + (t.src || '') + '</td></tr>';
      }
      h += '</table>';
    }

    // ─── LIBRARIES ───
    if (libs.length > 0) {
      h += '<h2>\uD83D\uDCDA Detected Libraries (' + libs.length + ')</h2>';
      h += '<table><tr><th>Library</th><th>Confidence</th><th>Patterns</th><th>URL</th></tr>';
      for (var i = 0; i < libs.length; i++) {
        var l = libs[i];
        h += '<tr><td><strong>' + l.name + '</strong></td><td>' + l.confidence + '</td><td>' + (l.patterns || []).join(', ') + '</td><td class="u">' + (l.url || '').slice(0, 100) + '</td></tr>';
      }
      h += '</table>';
    }

    // ─── NETWORK CONVERSATION ───
    h += '<h2>\uD83C\uDF10 Network Conversation (' + netConv.length + ')</h2>';
    h += '<table><tr><th>Method</th><th>URL</th><th>Status</th><th>Size</th><th>Type</th><th>IP</th></tr>';
    for (var i = 0; i < Math.min(netConv.length, 200); i++) {
      var n = netConv[i];
      h += '<tr><td>' + (n.method || '') + '</td><td class="u">' + (n.url || '').slice(0, 120) + '</td><td>' + (n.status || '') + '</td><td>' + (n.size || '') + '</td><td>' + (n.type || '') + '</td><td>' + (n.ip || '') + '</td></tr>';
    }
    h += '</table>';

    // ─── EXFILTRATION ───
    if (exfil.length > 0) {
      h += '<h2>\uD83D\uDEA8 Exfiltration (' + exfil.length + ')</h2>';
      h += '<table><tr><th>Method</th><th>Detail</th><th>Risk</th><th>Source</th></tr>';
      for (var i = 0; i < Math.min(exfil.length, 100); i++) {
        var e = exfil[i];
        h += '<tr><td>' + (e.method || '') + '</td><td class="u">' + (e.detail || '').slice(0, 120) + '</td><td>' + (e.risk || '') + '</td><td>' + (e.src || '') + '</td></tr>';
      }
      h += '</table>';
    }

    // ─── COOKIES ───
    h += '<h2>\uD83C\uDF6A Cookies & Storage</h2>';
    h += '<div class="kg">';
    h += this._kpi(cookies.cookiesSet || 0, 'Cookies Set', '');
    h += this._kpi(cookies.cookiesSent || 0, 'Cookies Sent', '');
    h += this._kpi(cookies.storageAccess || 0, 'Storage Access', '');
    h += '</div>';

    // ─── THIRD PARTIES ───
    if (tp.length > 0) {
      h += '<h2>\uD83C\uDF0D Third Parties (' + tp.length + ')</h2>';
      h += '<table><tr><th>Domain</th><th>Requests</th><th>Types</th></tr>';
      for (var i = 0; i < Math.min(tp.length, 50); i++) {
        h += '<tr><td>' + tp[i].domain + '</td><td>' + tp[i].requests + '</td><td>' + (tp[i].types || []).join(', ') + '</td></tr>';
      }
      h += '</table>';
    }

    // ─── 5W1H ───
    h += '<h2>\uD83D\uDD0E 5W1H Forensic Summary</h2>';
    if (h5w.who) {
      h += '<div class="hb"><h3>WHO</h3><p>Origins: ' + (h5w.who.origins || []).join(', ') + ' | Events: ' + (h5w.who.eventCount || 0) + '</p></div>';
    }
    if (h5w.what) {
      h += '<div class="hb"><h3>WHAT</h3><p>' + Object.entries(h5w.what || {}).map(function(e) { return e[0] + ': ' + e[1]; }).join(', ') + '</p></div>';
    }
    if (h5w.when) {
      h += '<div class="hb"><h3>WHEN</h3><p>Duration: ' + (h5w.when.durationMs || 0) + 'ms | Start: ' + (h5w.when.start || '') + '</p></div>';
    }
    if (h5w.where) {
      h += '<div class="hb"><h3>WHERE</h3><p>Frames: ' + (h5w.where.frames || []).length + ' | Origins: ' + (h5w.where.origins || []).join(', ') + '</p></div>';
    }
    if (h5w.why) {
      h += '<div class="hb"><h3>WHY</h3><p>Libraries: ' + (h5w.why.librariesDetected || []).join(', ') + ' | Cookies: ' + (h5w.why.cookiesSet || 0) + ' | Exfiltration: ' + (h5w.why.exfiltrationAttempts || 0) + '</p></div>';
    }
    if (h5w.how) {
      h += '<div class="hb"><h3>HOW</h3><p>Data channels: ' + (h5w.how.dataChannels || []).join(', ') + '</p></div>';
    }

    // ─── ENTROPY ───
    h += '<h2>\uD83E\uDDE0 Entropy Analysis</h2>';
    h += '<div class="kg">';
    h += this._kpi(entropy.categoryEntropy || 0, 'Category Entropy', '');
    h += this._kpi(entropy.apiEntropy || 0, 'API Entropy', '');
    h += '</div>';

    // ─── FOOTER ───
    h += '<footer><p>' + this.version + ' | Hybrid Dual-Telemetry CCTV | Generated ' + new Date().toISOString() + '</p>';
    h += '<p>Hook Events: ' + (pStats.hookEvents || 0) + ' | CDP Events: ' + (pStats.cdpEvents || 0) + ' | Page Events: ' + (pStats.pageEvents || 0) + ' | Total Deduped: ' + (pStats.totalDeduped || events.length) + '</p>';
    h += '</footer></div></body></html>';

    return h;
  }

  _kpi(val, label, cls) {
    return '<div class="k ' + (cls || '') + '"><div class="kv">' + val + '</div><div class="kl">' + label + '</div></div>';
  }
}

module.exports = { ReportGenerator };
