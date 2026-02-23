/**
 * Sentinel v3 — Report Generator
 * Produces JSON, HTML, and context-map outputs
 */

const fs = require('fs');
const path = require('path');

function generateReport(sentinelData, contextMap, targetUrl, options = {}) {
  const outputDir = options.outputDir || path.join(__dirname, '..', 'output');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const prefix = options.prefix || `sentinel_${timestamp}`;

  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const events = sentinelData.events || [];

  // ── Analyze events ──
  const byCategory = {};
  const byRisk = { low: 0, medium: 0, high: 0, critical: 0 };
  const apiCounts = {};
  const originSet = new Set();
  const timelineSlots = {};

  for (const e of events) {
    byCategory[e.cat] = (byCategory[e.cat] || 0) + 1;
    byRisk[e.risk] = (byRisk[e.risk] || 0) + 1;
    apiCounts[e.api] = (apiCounts[e.api] || 0) + 1;
    originSet.add(e.origin);

    const slot = Math.floor(e.ts / 1000);
    timelineSlots[slot] = (timelineSlots[slot] || 0) + 1;
  }

  const topApis = Object.entries(apiCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([api, count]) => ({ api, count }));

  // ── Risk Score calculation ──
  const riskScore = Math.min(100, Math.round(
    (byRisk.critical * 15) +
    (byRisk.high * 5) +
    (byRisk.medium * 1) +
    (byRisk.low * 0.1) +
    (Object.keys(byCategory).length * 3) +
    (originSet.size > 2 ? (originSet.size - 1) * 5 : 0)
  ));

  // ── Threat Assessment ──
  const threats = [];
  if (byCategory['audio'] > 0) threats.push({ type: 'Audio Fingerprinting', severity: 'HIGH', detail: `${byCategory['audio']} audio API calls detected` });
  if (byCategory['canvas'] > 0) threats.push({ type: 'Canvas Fingerprinting', severity: 'HIGH', detail: `${byCategory['canvas']} canvas operations` });
  if (byCategory['webgl'] > 0) threats.push({ type: 'WebGL Fingerprinting', severity: 'HIGH', detail: `${byCategory['webgl']} WebGL parameter reads` });
  if (byCategory['font-detection'] > 50) threats.push({ type: 'Font Enumeration', severity: 'CRITICAL', detail: `${byCategory['font-detection']} font probing calls — likely full font scan` });
  if (byCategory['webrtc'] > 0) threats.push({ type: 'WebRTC IP Leak Attempt', severity: 'CRITICAL', detail: `${byCategory['webrtc']} WebRTC connection attempts` });
  if (byCategory['geolocation'] > 0) threats.push({ type: 'Geolocation Request', severity: 'CRITICAL', detail: `Attempted to read device location` });
  if (byCategory['clipboard'] > 0) threats.push({ type: 'Clipboard Access', severity: 'CRITICAL', detail: `Attempted clipboard read/write` });
  if (byCategory['media-devices'] > 0) threats.push({ type: 'Media Device Enumeration', severity: 'HIGH', detail: `Attempted to list cameras/microphones` });
  if (byCategory['service-worker'] > 0) threats.push({ type: 'Service Worker Registration', severity: 'HIGH', detail: `Attempted persistent background code` });
  if (byCategory['math-fingerprint'] > 10) threats.push({ type: 'Math Fingerprinting', severity: 'MEDIUM', detail: `${byCategory['math-fingerprint']} Math function probes` });
  if (byCategory['storage'] > 50) threats.push({ type: 'Aggressive Storage Usage', severity: 'MEDIUM', detail: `${byCategory['storage']} storage operations` });
  if (originSet.size > 3) threats.push({ type: 'Multi-Origin Tracking', severity: 'HIGH', detail: `${originSet.size} unique origins detected — possible cross-domain tracking` });

  // ── FingerprintJS v5 detection ──
  const fpjsSignature = events.some(e => e.api === 'isPointInPath' && e.cat === 'canvas') &&
    events.some(e => e.cat === 'audio') &&
    events.some(e => e.cat === 'font-detection') &&
    events.some(e => e.cat === 'math-fingerprint');
  if (fpjsSignature) {
    threats.push({ type: '⚠️ FingerprintJS-like Library Detected', severity: 'CRITICAL',
      detail: 'Combination of canvas(isPointInPath), audio, font-detection, and math fingerprinting matches FingerprintJS v5 pattern' });
  }

  const reportJson = {
    version: 'sentinel-v3.0.0',
    target: targetUrl,
    scanDate: new Date().toISOString(),
    mode: options.stealthEnabled ? 'stealth' : 'observe',
    totalEvents: events.length,
    riskScore,
    riskLevel: riskScore >= 70 ? 'DANGER 🔴' : riskScore >= 40 ? 'WARNING 🟡' : 'LOW 🟢',
    timeSpanMs: events.length > 0 ? events[events.length - 1].ts : 0,
    byCategory,
    byRisk,
    topApis,
    uniqueOrigins: [...originSet],
    threats,
    categoriesMonitored: 18,
    categoriesDetected: Object.keys(byCategory).length,
    timeline: timelineSlots
  };

  // ── Save JSON ──
  const jsonPath = path.join(outputDir, `${prefix}_report.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(reportJson, null, 2));

  // ── Save Context Map ──
  const ctxPath = path.join(outputDir, `${prefix}_context-map.json`);
  fs.writeFileSync(ctxPath, JSON.stringify(contextMap || [], null, 2));

  // ── Generate HTML ──
  const htmlPath = path.join(outputDir, `${prefix}_report.html`);
  const html = generateHTML(reportJson, events);
  fs.writeFileSync(htmlPath, html);

  return { jsonPath, ctxPath, htmlPath, reportJson };
}

function generateHTML(report, events) {
  const catRows = Object.entries(report.byCategory)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, count]) => `<tr><td>${cat}</td><td>${count}</td><td>${getCatBadge(cat)}</td></tr>`)
    .join('');

  const apiRows = report.topApis
    .map(a => `<tr><td><code>${a.api}</code></td><td>${a.count}</td></tr>`)
    .join('');

  const threatRows = report.threats
    .map(t => `<tr class="threat-${t.severity.toLowerCase()}"><td>${t.type}</td><td><span class="badge badge-${t.severity.toLowerCase()}">${t.severity}</span></td><td>${t.detail}</td></tr>`)
    .join('');

  const riskClass = report.riskScore >= 70 ? 'danger' : report.riskScore >= 40 ? 'warning' : 'safe';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel v3 — Maling Catcher Report</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --danger: #f85149; --warning: #d29922; --safe: #3fb950; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; padding: 20px; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { color: var(--accent); margin-bottom: 8px; font-size: 1.8rem; }
  .subtitle { color: #8b949e; margin-bottom: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card h3 { color: #8b949e; font-size: 0.75rem; text-transform: uppercase; margin-bottom: 8px; }
  .card .value { font-size: 2rem; font-weight: bold; }
  .card .value.danger { color: var(--danger); }
  .card .value.warning { color: var(--warning); }
  .card .value.safe { color: var(--safe); }
  table { width: 100%; border-collapse: collapse; margin-bottom: 24px; background: var(--card); border-radius: 8px; overflow: hidden; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: #21262d; color: var(--accent); font-size: 0.8rem; text-transform: uppercase; }
  .badge { padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; font-weight: bold; }
  .badge-critical { background: #f8514933; color: var(--danger); }
  .badge-high { background: #d2992233; color: var(--warning); }
  .badge-medium { background: #58a6ff22; color: var(--accent); }
  .badge-low { background: #3fb95022; color: var(--safe); }
  .threat-critical { border-left: 3px solid var(--danger); }
  .threat-high { border-left: 3px solid var(--warning); }
  .threat-medium { border-left: 3px solid var(--accent); }
  .section { margin-bottom: 32px; }
  .section h2 { color: var(--accent); margin-bottom: 12px; font-size: 1.2rem; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
  .mode-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; margin-left: 12px; }
  .mode-stealth { background: #3fb95033; color: var(--safe); }
  .mode-observe { background: #d2992233; color: var(--warning); }
  .origin-list { display: flex; gap: 8px; flex-wrap: wrap; }
  .origin-tag { background: #21262d; border: 1px solid var(--border); padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; }
  footer { text-align: center; color: #484f58; margin-top: 40px; font-size: 0.8rem; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ Sentinel v3 — Maling Catcher Report</h1>
  <p class="subtitle">${report.target} <span class="mode-badge mode-${report.mode}">${report.mode.toUpperCase()} MODE</span></p>

  <div class="grid">
    <div class="card"><h3>Risk Score</h3><div class="value ${riskClass}">${report.riskScore}/100</div><div>${report.riskLevel}</div></div>
    <div class="card"><h3>Total Events</h3><div class="value">${report.totalEvents.toLocaleString()}</div></div>
    <div class="card"><h3>Categories Detected</h3><div class="value">${report.categoriesDetected}/${report.categoriesMonitored}</div></div>
    <div class="card"><h3>Unique Origins</h3><div class="value">${report.uniqueOrigins.length}</div></div>
    <div class="card"><h3>Threats Found</h3><div class="value ${report.threats.length > 3 ? 'danger' : report.threats.length > 0 ? 'warning' : 'safe'}">${report.threats.length}</div></div>
    <div class="card"><h3>Scan Duration</h3><div class="value">${(report.timeSpanMs / 1000).toFixed(1)}s</div></div>
  </div>

  ${report.threats.length > 0 ? `
  <div class="section">
    <h2>🚨 Threat Assessment</h2>
    <table><thead><tr><th>Threat</th><th>Severity</th><th>Detail</th></tr></thead><tbody>${threatRows}</tbody></table>
  </div>` : ''}

  <div class="section">
    <h2>📊 Activity by Category</h2>
    <table><thead><tr><th>Category</th><th>Events</th><th>Risk Level</th></tr></thead><tbody>${catRows}</tbody></table>
  </div>

  <div class="section">
    <h2>🔍 Top APIs Called</h2>
    <table><thead><tr><th>API</th><th>Count</th></tr></thead><tbody>${apiRows}</tbody></table>
  </div>

  <div class="section">
    <h2>🌐 Origins Detected</h2>
    <div class="origin-list">${report.uniqueOrigins.map(o => `<span class="origin-tag">${o}</span>`).join('')}</div>
  </div>

  <div class="section">
    <h2>📈 Risk Breakdown</h2>
    <div class="grid">
      <div class="card"><h3>Critical</h3><div class="value danger">${report.byRisk.critical || 0}</div></div>
      <div class="card"><h3>High</h3><div class="value warning">${report.byRisk.high || 0}</div></div>
      <div class="card"><h3>Medium</h3><div class="value" style="color:var(--accent)">${report.byRisk.medium || 0}</div></div>
      <div class="card"><h3>Low</h3><div class="value safe">${report.byRisk.low || 0}</div></div>
    </div>
  </div>

  <footer>Sentinel v3.0.0 — Maling Catcher | Scan: ${report.scanDate}</footer>
</div>
</body></html>`;
}

function getCatBadge(cat) {
  const map = {
    'audio': '<span class="badge badge-critical">CRITICAL</span>',
    'webrtc': '<span class="badge badge-critical">CRITICAL</span>',
    'geolocation': '<span class="badge badge-critical">CRITICAL</span>',
    'clipboard': '<span class="badge badge-critical">CRITICAL</span>',
    'media-devices': '<span class="badge badge-critical">CRITICAL</span>',
    'canvas': '<span class="badge badge-high">HIGH</span>',
    'webgl': '<span class="badge badge-high">HIGH</span>',
    'font-detection': '<span class="badge badge-high">HIGH</span>',
    'fingerprint': '<span class="badge badge-high">HIGH</span>',
    'math-fingerprint': '<span class="badge badge-high">HIGH</span>',
    'permissions': '<span class="badge badge-high">HIGH</span>',
    'service-worker': '<span class="badge badge-high">HIGH</span>',
    'storage': '<span class="badge badge-medium">MEDIUM</span>',
    'network': '<span class="badge badge-medium">MEDIUM</span>',
    'screen': '<span class="badge badge-medium">MEDIUM</span>',
    'perf-timing': '<span class="badge badge-medium">MEDIUM</span>',
    'dom-probe': '<span class="badge badge-medium">MEDIUM</span>',
    'hardware': '<span class="badge badge-medium">MEDIUM</span>',
  };
  return map[cat] || '<span class="badge badge-low">LOW</span>';
}

module.exports = { generateReport };
