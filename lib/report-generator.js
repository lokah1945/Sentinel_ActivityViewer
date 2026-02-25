/**
 * ReportGenerator v6.2.0
 * 
 * Generates JSON + HTML reports from forensic analysis.
 */

'use strict';

const fs = require('fs');
const path = require('path');

class ReportGenerator {
  constructor(version) {
    this.version = version;
    this.outputDir = path.join(process.cwd(), 'output');
    if (!fs.existsSync(this.outputDir)) {
      fs.mkdirSync(this.outputDir, { recursive: true });
    }
  }

  save(mode, ts, events, analysis, context) {
    const baseName = `sentinel-${mode}-${ts}`;
    const jsonPath = path.join(this.outputDir, `${baseName}-report.json`);
    const htmlPath = path.join(this.outputDir, `${baseName}-report.html`);
    const ctxPath = path.join(this.outputDir, `${baseName}-context.json`);

    // JSON report
    const jsonReport = {
      version: this.version,
      target: context.target,
      mode,
      timestamp: new Date(ts).toISOString(),
      events,
      analysis,
    };
    fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2));

    // Context
    fs.writeFileSync(ctxPath, JSON.stringify(context, null, 2));

    // HTML report
    const html = this._generateHTML(analysis, context, events);
    fs.writeFileSync(htmlPath, html);

    return { json: jsonPath, html: htmlPath, context: ctxPath };
  }

  _generateHTML(analysis, context, events) {
    const { categories, threats, libraryAttribution, bursts, entropy, h5w, valueCaptures, riskScore, injectionStatus } = analysis;
    const duration = ((context.scanDate ? Date.now() - new Date(context.scanDate).getTime() : 0) / 1000).toFixed(1);

    let html = `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${this.version} ${context.target}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.6}
.container{max-width:1200px;margin:0 auto;padding:20px}
header{text-align:center;padding:30px 0;border-bottom:1px solid #30363d}
h1{color:#58a6ff;font-size:1.8em}h2{color:#58a6ff;margin:20px 0 10px;font-size:1.3em;border-bottom:1px solid #21262d;padding-bottom:5px}
.subtitle{color:#8b949e;margin-top:8px}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin:20px 0}
.kpi{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}
.kpi.good{border-color:#238636}.kpi.warn{border-color:#d29922}.kpi.bad{border-color:#da3633}
.kpi-value{font-size:1.6em;font-weight:bold;color:#f0f6fc}.kpi-label{color:#8b949e;font-size:0.85em;margin-top:4px}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:0.9em}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #21262d}
th{background:#161b22;color:#58a6ff;font-weight:600}tr:hover{background:#161b22}
.badge{background:#238636;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em}
.risk-critical{color:#ff7b72;font-weight:bold}.risk-high{color:#ffa657}.risk-med{color:#d29922}
.flags{display:flex;flex-wrap:wrap;gap:8px}
.flag{padding:4px 10px;border-radius:4px;font-size:0.85em}
.flag-ok{background:#0d4429;color:#3fb950;border:1px solid #238636}
.flag-fail{background:#3d1e20;color:#ff7b72;border:1px solid #da3633}
.h5w-box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;margin:8px 0}
.h5w-box h3{color:#ffa657;margin-bottom:6px}
pre{color:#c9d1d9;white-space:pre-wrap;font-size:0.85em;max-height:200px;overflow-y:auto}
.url-cell{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.new-badge{background:#1f6feb;color:#fff;padding:1px 6px;border-radius:3px;font-size:0.7em;margin-left:6px}
footer{text-align:center;color:#484f58;padding:30px 0;border-top:1px solid #21262d;margin-top:30px}
</style></head><body><div class="container">`;

    // Header
    html += `<header><h1>🛡️ ${this.version} Unified Forensic Engine</h1>`;
    html += `<p class="subtitle">Target: <strong>${context.target}</strong> | Mode: <strong>${context.mode}</strong> | ${context.scanDate}</p>`;
    html += `<p class="subtitle">⚡ rebrowser-patches: <strong>${process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE || 'addBinding'}</strong> | Runtime.Enable: <strong>PATCHED</strong></p>`;
    html += `</header>`;

    // KPIs
    const eventCount = events.length;
    const riskClass = riskScore >= 50 ? 'bad' : riskScore >= 20 ? 'warn' : 'good';
    html += `<div class="kpi-grid">`;
    html += `<div class="kpi good"><div class="kpi-value">${eventCount}</div><div class="kpi-label">Total Events</div></div>`;
    html += `<div class="kpi ${riskClass}"><div class="kpi-value">${riskScore}/100</div><div class="kpi-label">Risk Score</div></div>`;
    html += `<div class="kpi"><div class="kpi-value">${categories.length}/42</div><div class="kpi-label">Categories</div></div>`;
    html += `<div class="kpi"><div class="kpi-value">${duration}s</div><div class="kpi-label">Duration</div></div>`;
    html += `<div class="kpi good"><div class="kpi-value">${context.coverageProof?.frameCoverage || 'N/A'}</div><div class="kpi-label">Frame Coverage</div></div>`;
    html += `<div class="kpi ${threats.length > 10 ? 'bad' : 'warn'}"><div class="kpi-value">${threats.length}</div><div class="kpi-label">Threats</div></div>`;
    html += `</div>`;

    // Injection Status
    html += `<section><h2>Injection & Patch Status</h2><div class="flags">`;
    if (injectionStatus) {
      for (const [key, val] of Object.entries(injectionStatus)) {
        const cls = val === true || (typeof val === 'number' && val > 0) ? 'flag-ok' : 'flag-fail';
        html += `<span class="flag ${cls}">${key}: ${val}</span>`;
      }
    }
    html += `</div></section>`;

    // Categories
    html += `<section><h2>Categories Detected (${categories.length}/42)</h2>`;
    html += `<table><thead><tr><th>Category</th><th>Events</th><th>Risk</th></tr></thead><tbody>`;
    for (const cat of categories.sort((a, b) => b.events - a.events)) {
      const riskCls = cat.risk === 'critical' ? 'risk-critical' : cat.risk === 'high' ? 'risk-high' : 'risk-med';
      html += `<tr><td>${cat.name}</td><td>${cat.events}</td><td class="${riskCls}">${cat.risk}</td></tr>`;
    }
    html += `</tbody></table></section>`;

    // Threats
    html += `<section><h2>Threats (${threats.length})</h2>`;
    html += `<table><thead><tr><th>Risk</th><th>Category</th><th>API</th><th>Detail</th></tr></thead><tbody>`;
    for (const t of threats.slice(0, 50)) {
      const riskCls = t.risk === 'critical' ? 'risk-critical' : 'risk-high';
      html += `<tr><td class="${riskCls}">${t.risk}</td><td>${t.category}</td><td>${t.api}</td><td>${this._esc(t.detail)}</td></tr>`;
    }
    html += `</tbody></table></section>`;

    // Library Attribution
    html += `<section><h2>Library Attribution</h2>`;
    html += `<table><thead><tr><th>Library</th><th>Matched</th><th>Confidence</th></tr></thead><tbody>`;
    for (const lib of libraryAttribution) {
      html += `<tr><td>${lib.name}</td><td>${lib.matched}</td><td>${lib.confidence}</td></tr>`;
    }
    html += `</tbody></table></section>`;

    // 5W1H
    html += `<section><h2>🔍 5W1H Forensic Summary</h2>`;
    for (const [key, val] of Object.entries(h5w)) {
      html += `<div class="h5w-box"><h3>${key.toUpperCase()}</h3><pre>${JSON.stringify(val, null, 2)}</pre></div>`;
    }
    html += `</section>`;

    // Entropy
    html += `<section><h2>Entropy Analysis</h2>`;
    html += `<p>Category entropy: <strong>${entropy.categoryEntropy}</strong> | API entropy: <strong>${entropy.apiEntropy}</strong></p>`;
    html += `</section>`;

    // Value Captures
    html += `<section><h2>Value Captures (top 50)</h2>`;
    html += `<table><thead><tr><th>Category</th><th>API</th><th>Value</th><th>Direction</th></tr></thead><tbody>`;
    for (const vc of valueCaptures.slice(0, 50)) {
      html += `<tr><td>${vc.category}</td><td>${vc.api}</td><td>${this._esc(String(vc.value).slice(0, 100))}</td><td>${vc.direction}</td></tr>`;
    }
    html += `</tbody></table></section>`;

    // Footer
    html += `<footer><p>${this.version} Unified Forensic Engine | Generated ${new Date().toISOString()}</p>`;
    html += `<p>⚡ Powered by: Official Playwright + rebrowser-patches + Stealth Plugin</p></footer>`;
    html += `</div></body></html>`;

    return html;
  }

  _esc(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}

module.exports = { ReportGenerator };
