/**
 * Sentinel v4 — Forensic Report Generator (Layer 7)
 * 
 * Produces comprehensive 1H5W reports:
 * - JSON: Full forensic data with correlation engine results
 * - HTML: Interactive dashboard with timeline, burst analysis, attribution
 * - Context Map: Frame-by-frame coverage proof with BOOT_OK status
 * 
 * UPGRADES from v3:
 * - Correlation engine integration (bursts, attribution, entropy)
 * - Value capture display (actual return values)
 * - Stack trace viewer
 * - 1H5W forensic columns
 * - Coverage proof with BOOT_OK protocol
 * - Exfiltration monitor alerts
 * - Honeypot trigger display
 */

const fs = require('fs');
const path = require('path');
const { CorrelationEngine } = require('../lib/correlation-engine');

function generateReport(sentinelData, contextMap, targetUrl, options = {}) {
  const outputDir = options.outputDir || path.join(__dirname, '..', 'output');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const prefix = options.prefix || `sentinel_${timestamp}`;

  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const events = sentinelData.events || [];

  // ── Correlation Engine Analysis ──
  const correlator = new CorrelationEngine();
  correlator.ingestEvents(events);
  const correlation = correlator.getReport();

  // ── Analyze events ──
  const byCategory = {};
  const byRisk = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const apiCounts = {};
  const originSet = new Set();
  const frameSet = new Set();
  const timelineSlots = {};
  const valueCaptures = [];

  for (const e of events) {
    byCategory[e.cat] = (byCategory[e.cat] || 0) + 1;
    byRisk[e.risk] = (byRisk[e.risk] || 0) + 1;
    apiCounts[e.api] = (apiCounts[e.api] || 0) + 1;
    originSet.add(e.origin);
    if (e.frameId) frameSet.add(e.frameId);

    const slot = Math.floor(e.ts / 1000);
    timelineSlots[slot] = (timelineSlots[slot] || 0) + 1;

    // Collect value captures for forensic display
    if (e.value && e.value !== 'undefined' && e.value !== 'null') {
      valueCaptures.push({
        ts: e.ts,
        api: e.api,
        value: e.value,
        category: e.cat
      });
    }
  }

  const topApis = Object.entries(apiCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 30)
    .map(([api, count]) => ({ api, count }));

  // ── Risk Score calculation (v4 enhanced) ──
  const riskScore = Math.min(100, Math.round(
    (byRisk.critical * 15) +
    (byRisk.high * 5) +
    (byRisk.medium * 1) +
    (byRisk.low * 0.1) +
    (Object.keys(byCategory).length * 2) +
    (originSet.size > 2 ? (originSet.size - 1) * 5 : 0) +
    (correlation.summary.fingerprintBursts * 10) +
    (correlation.summary.exfilAttempts * 5) +
    (correlation.summary.honeypotTriggered ? 20 : 0)
  ));

  // ── Threat Assessment (v4 enhanced) ──
  const threats = [];

  if (byCategory['audio'] > 0) threats.push({ type: 'Audio Fingerprinting', severity: 'HIGH', detail: `${byCategory['audio']} audio API calls detected`, who: 'Audio processing pipeline', how: 'OfflineAudioContext + Oscillator + Compressor' });
  if (byCategory['canvas'] > 0) threats.push({ type: 'Canvas Fingerprinting', severity: 'HIGH', detail: `${byCategory['canvas']} canvas operations`, who: 'Canvas 2D/WebGL renderer', how: 'toDataURL/getImageData pixel hash' });
  if (byCategory['webgl'] > 0) threats.push({ type: 'WebGL Fingerprinting', severity: 'HIGH', detail: `${byCategory['webgl']} WebGL parameter reads`, who: 'WebGL context', how: 'getParameter(VENDOR/RENDERER) + precision format' });
  if (byCategory['font-detection'] > 50) threats.push({ type: 'Font Enumeration', severity: 'CRITICAL', detail: `${byCategory['font-detection']} font probing calls — likely full font scan`, who: 'Font detection engine', how: 'measureText/getBoundingClientRect width comparison' });
  if (byCategory['webrtc'] > 0) threats.push({ type: 'WebRTC IP Leak', severity: 'CRITICAL', detail: `${byCategory['webrtc']} WebRTC connection attempts`, who: 'WebRTC STUN/TURN', how: 'RTCPeerConnection ICE candidate harvesting' });
  if (byCategory['geolocation'] > 0) threats.push({ type: 'Geolocation Request', severity: 'CRITICAL', detail: 'Attempted to read device location', who: 'Geolocation API', how: 'getCurrentPosition/watchPosition' });
  if (byCategory['clipboard'] > 0) threats.push({ type: 'Clipboard Access', severity: 'CRITICAL', detail: 'Attempted clipboard read/write', who: 'Clipboard API', how: 'navigator.clipboard.readText/writeText' });
  if (byCategory['media-devices'] > 0) threats.push({ type: 'Media Device Enumeration', severity: 'HIGH', detail: 'Attempted to list cameras/microphones', who: 'MediaDevices API', how: 'enumerateDevices()' });
  if (byCategory['service-worker'] > 0) threats.push({ type: 'Service Worker', severity: 'HIGH', detail: 'Attempted persistent background code', who: 'ServiceWorker API', how: 'navigator.serviceWorker.register()' });
  if (byCategory['math-fingerprint'] > 10) threats.push({ type: 'Math Fingerprinting', severity: 'MEDIUM', detail: `${byCategory['math-fingerprint']} Math function probes`, who: 'Math precision engine', how: 'Math.acos/sinh/expm1 precision differences' });
  if (byCategory['storage'] > 50) threats.push({ type: 'Aggressive Storage', severity: 'MEDIUM', detail: `${byCategory['storage']} storage operations`, who: 'Storage APIs', how: 'cookie/localStorage/IndexedDB read/write' });
  if (byCategory['speech'] > 0) threats.push({ type: 'Speech Voice Fingerprint', severity: 'HIGH', detail: `${byCategory['speech']} speech synthesis probes`, who: 'Web Speech API', how: 'speechSynthesis.getVoices() OS/language detection' });
  if (byCategory['client-hints'] > 0) threats.push({ type: 'Client Hints Probing', severity: 'HIGH', detail: `${byCategory['client-hints']} Client Hints requests`, who: 'UA-CH API', how: 'getHighEntropyValues(OS, CPU arch, device model)' });
  if (byCategory['intl-fingerprint'] > 0) threats.push({ type: 'Intl API Fingerprint', severity: 'MEDIUM', detail: `${byCategory['intl-fingerprint']} Intl probes`, who: 'Intl API', how: 'ListFormat/NumberFormat/Collator resolvedOptions' });
  if (byCategory['css-fingerprint'] > 0) threats.push({ type: 'CSS Feature Detection', severity: 'MEDIUM', detail: `${byCategory['css-fingerprint']} CSS.supports probes`, who: 'CSS Object Model', how: 'CSS.supports() feature query fingerprinting' });
  if (byCategory['offscreen-canvas'] > 0) threats.push({ type: 'OffscreenCanvas Fingerprint', severity: 'HIGH', detail: `${byCategory['offscreen-canvas']} OffscreenCanvas operations`, who: 'OffscreenCanvas API', how: 'Worker-based canvas fingerprinting' });
  if (byCategory['exfiltration'] > 0) threats.push({ type: 'Data Exfiltration', severity: 'CRITICAL', detail: `${byCategory['exfiltration']} exfiltration events (Beacon/WebSocket/pixel)`, who: 'Network layer', how: 'sendBeacon/WebSocket/img.src data transmission' });
  if (byCategory['honeypot'] > 0) threats.push({ type: '🍯 Honeypot Triggered', severity: 'CRITICAL', detail: `${byCategory['honeypot']} honeypot property accesses — CONFIRMED fingerprinting`, who: 'Fingerprinting script', how: 'Accessed planted trap properties' });
  if (byCategory['property-enum'] > 0) threats.push({ type: 'Prototype Inspection', severity: 'HIGH', detail: `${byCategory['property-enum']} property enumeration events`, who: 'Lie detection engine', how: 'Object.keys/getOwnPropertyNames on navigator/screen' });
  if (byCategory['credential'] > 0) threats.push({ type: 'Credential Probing', severity: 'CRITICAL', detail: `${byCategory['credential']} credential API calls`, who: 'Credential Management API', how: 'credentials.get/create for WebAuthn fingerprint' });
  if (originSet.size > 3) threats.push({ type: 'Multi-Origin Tracking', severity: 'HIGH', detail: `${originSet.size} unique origins detected — possible cross-domain tracking`, who: 'Third-party scripts', how: 'Cross-origin iframe/script fingerprinting' });

  // Library attribution threats
  for (const attr of correlation.attributions) {
    threats.push({
      type: `📚 Library Detected: ${attr.library}`,
      severity: 'CRITICAL',
      detail: `${attr.confidence}% confidence — ${attr.description}`,
      who: attr.library,
      how: `Matched patterns: ${attr.matchedPatterns.join(', ')}${attr.burstCorrelation ? ' + burst correlation' : ''}`
    });
  }

  // ── Coverage Proof ──
  const bootOkEvents = events.filter(e => e.api === 'BOOT_OK');
  const monitoredFrames = bootOkEvents.map(e => ({
    frameId: e.frameId,
    origin: e.origin,
    url: e.detail
  }));

  const coverageProof = {
    totalFramesDetected: contextMap ? contextMap.length : 0,
    monitoredFrames: monitoredFrames.length,
    bootOkReceived: bootOkEvents.length,
    coverage: contextMap && contextMap.length > 0 
      ? Math.round((monitoredFrames.length / contextMap.length) * 100) 
      : 0,
    unmonitoredFrames: contextMap 
      ? contextMap.filter(cm => !monitoredFrames.some(mf => mf.origin === cm.origin)).map(cm => cm.url || cm.origin)
      : [],
    verdict: bootOkEvents.length > 0 ? 'MONITORED' : 'BLIND_SPOT_DETECTED'
  };

  // ── Build Report JSON ──
  const reportJson = {
    version: 'sentinel-v4.0.0',
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
    uniqueFrames: [...frameSet],
    threats,
    categoriesMonitored: 31,
    categoriesDetected: Object.keys(byCategory).length,
    timeline: timelineSlots,
    correlation,
    coverageProof,
    valueCaptures: valueCaptures.slice(0, 100),
    forensic1H5W: {
      WHO: correlation.attributions.length > 0 
        ? correlation.attributions.map(a => a.library).join(', ') 
        : 'Unknown fingerprinting script(s)',
      WHAT: `${events.length} API calls across ${Object.keys(byCategory).length} categories`,
      WHEN: events.length > 0 
        ? `Scan duration: ${(events[events.length-1].ts / 1000).toFixed(1)}s, ` +
          `${correlation.summary.fingerprintBursts} fingerprint bursts detected`
        : 'No events captured',
      WHERE: `${originSet.size} origin(s), ${frameSet.size} frame(s) — ` +
        `Coverage: ${coverageProof.coverage}%`,
      WHY: threats.length > 0
        ? `${threats.filter(t=>t.severity==='CRITICAL').length} critical, ` +
          `${threats.filter(t=>t.severity==='HIGH').length} high severity threats`
        : 'No threats detected',
      HOW: correlation.attributions.length > 0
        ? correlation.attributions.map(a => `${a.library}: ${a.matchedPatterns.join(', ')}`).join('; ')
        : 'Multiple API probing across fingerprint vectors'
    }
  };

  // ── Save JSON ──
  const jsonPath = path.join(outputDir, `${prefix}_report.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(reportJson, null, 2));

  // ── Save Context Map ──
  const ctxPath = path.join(outputDir, `${prefix}_context-map.json`);
  fs.writeFileSync(ctxPath, JSON.stringify({
    frames: contextMap || [],
    coverageProof,
    monitoredFrames
  }, null, 2));

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
    .map(t => `<tr class="threat-${t.severity.toLowerCase()}">
      <td>${t.type}</td>
      <td><span class="badge badge-${t.severity.toLowerCase()}">${t.severity}</span></td>
      <td>${t.detail}</td>
      <td class="who-col">${t.who || '-'}</td>
      <td class="how-col">${t.how || '-'}</td>
    </tr>`)
    .join('');

  const riskClass = report.riskScore >= 70 ? 'danger' : report.riskScore >= 40 ? 'warning' : 'safe';

  // Burst analysis rows
  const burstRows = (report.correlation?.bursts || [])
    .map(b => `<tr>
      <td>${(b.startTs/1000).toFixed(1)}s — ${(b.endTs/1000).toFixed(1)}s</td>
      <td>${b.count}</td>
      <td>${b.durationMs}ms</td>
      <td>${b.topCategory}</td>
      <td>${b.isFingerprintBurst ? '🔴 YES' : '🟢 NO'}</td>
    </tr>`)
    .join('');

  // Attribution rows
  const attrRows = (report.correlation?.attributions || [])
    .map(a => `<tr>
      <td><strong>${a.library}</strong></td>
      <td><div class="confidence-bar"><div class="confidence-fill" style="width:${a.confidence}%">${a.confidence}%</div></div></td>
      <td>${a.matchedPatterns.join(', ')}</td>
      <td>${a.burstCorrelation ? '✅' : '❌'}</td>
      <td>${a.description}</td>
    </tr>`)
    .join('');

  // Exfiltration rows
  const exfilRows = (report.correlation?.exfilAlerts || [])
    .map(e => `<tr>
      <td>${e.tracker}</td>
      <td><code>${e.method}</code></td>
      <td class="url-cell">${e.url}</td>
      <td>${(e.timestamp/1000).toFixed(1)}s</td>
    </tr>`)
    .join('');

  // Value captures (top 50)
  const valueRows = (report.valueCaptures || []).slice(0, 50)
    .map(v => `<tr>
      <td>${(v.ts/1000).toFixed(2)}s</td>
      <td><code>${v.api}</code></td>
      <td>${v.category}</td>
      <td class="value-cell">${escapeHtml(String(v.value).slice(0, 150))}</td>
    </tr>`)
    .join('');

  // Coverage proof
  const coverageClass = report.coverageProof?.coverage >= 80 ? 'safe' : report.coverageProof?.coverage >= 50 ? 'warning' : 'danger';

  // Timeline data for chart
  const timelineData = JSON.stringify(report.timeline || {});

  // 1H5W Summary
  const forensic = report.forensic1H5W || {};

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel v4 — Forensic Maling Catcher Report</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --danger: #f85149; --warning: #d29922; --safe: #3fb950; --purple: #bc8cff; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; padding: 20px; line-height: 1.5; }
  .container { max-width: 1400px; margin: 0 auto; }
  h1 { color: var(--accent); margin-bottom: 8px; font-size: 1.8rem; }
  h2 { color: var(--accent); margin-bottom: 12px; font-size: 1.2rem; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
  .subtitle { color: #8b949e; margin-bottom: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
  .card h3 { color: #8b949e; font-size: 0.7rem; text-transform: uppercase; margin-bottom: 6px; }
  .card .value { font-size: 1.8rem; font-weight: bold; }
  .card .value.danger { color: var(--danger); }
  .card .value.warning { color: var(--warning); }
  .card .value.safe { color: var(--safe); }
  table { width: 100%; border-collapse: collapse; margin-bottom: 24px; background: var(--card); border-radius: 8px; overflow: hidden; font-size: 0.85rem; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: #21262d; color: var(--accent); font-size: 0.75rem; text-transform: uppercase; }
  .badge { padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; font-weight: bold; display: inline-block; }
  .badge-critical { background: #f8514933; color: var(--danger); }
  .badge-high { background: #d2992233; color: var(--warning); }
  .badge-medium { background: #58a6ff22; color: var(--accent); }
  .badge-low { background: #3fb95022; color: var(--safe); }
  .badge-info { background: #bc8cff22; color: var(--purple); }
  .threat-critical { border-left: 3px solid var(--danger); }
  .threat-high { border-left: 3px solid var(--warning); }
  .threat-medium { border-left: 3px solid var(--accent); }
  .section { margin-bottom: 32px; }
  .mode-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; margin-left: 12px; }
  .mode-stealth { background: #3fb95033; color: var(--safe); }
  .mode-observe { background: #d2992233; color: var(--warning); }
  .forensic-box { background: var(--card); border: 2px solid var(--accent); border-radius: 8px; padding: 16px; margin-bottom: 24px; }
  .forensic-box h2 { border-bottom: none; margin-bottom: 16px; }
  .forensic-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 12px; }
  .forensic-item { background: #21262d; border-radius: 6px; padding: 12px; }
  .forensic-item .label { color: var(--accent); font-weight: bold; font-size: 0.9rem; margin-bottom: 4px; }
  .forensic-item .content { color: var(--text); font-size: 0.85rem; }
  .confidence-bar { background: #21262d; border-radius: 4px; height: 22px; overflow: hidden; }
  .confidence-fill { background: linear-gradient(90deg, var(--safe), var(--warning), var(--danger)); height: 100%; display: flex; align-items: center; justify-content: center; font-size: 0.7rem; font-weight: bold; color: white; text-shadow: 0 1px 2px rgba(0,0,0,0.5); }
  .url-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .value-cell { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 0.8rem; color: var(--safe); }
  .who-col, .how-col { font-size: 0.8rem; color: #8b949e; max-width: 200px; }
  .coverage-indicator { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
  .coverage-indicator.safe { background: #3fb95033; color: var(--safe); }
  .coverage-indicator.warning { background: #d2992233; color: var(--warning); }
  .coverage-indicator.danger { background: #f8514933; color: var(--danger); }
  .tab-container { margin-bottom: 24px; }
  .tab-buttons { display: flex; gap: 4px; margin-bottom: 12px; }
  .tab-btn { background: #21262d; border: 1px solid var(--border); color: var(--text); padding: 8px 16px; border-radius: 6px 6px 0 0; cursor: pointer; font-size: 0.85rem; }
  .tab-btn.active { background: var(--card); border-bottom-color: var(--card); color: var(--accent); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  canvas { max-width: 100%; }
  footer { text-align: center; color: #484f58; margin-top: 40px; font-size: 0.8rem; }
  @media (max-width: 768px) {
    .grid { grid-template-columns: repeat(2, 1fr); }
    .forensic-grid { grid-template-columns: 1fr; }
    .who-col, .how-col { display: none; }
  }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ Sentinel v4 — Forensic Maling Catcher Report</h1>
  <p class="subtitle">${report.target} <span class="mode-badge mode-${report.mode}">${report.mode.toUpperCase()} MODE</span> · ${report.scanDate}</p>

  <!-- 1H5W FORENSIC SUMMARY -->
  <div class="forensic-box">
    <h2>🔍 Forensic Summary (1H5W)</h2>
    <div class="forensic-grid">
      <div class="forensic-item"><div class="label">👤 WHO (Siapa)</div><div class="content">${escapeHtml(forensic.WHO || '-')}</div></div>
      <div class="forensic-item"><div class="label">📋 WHAT (Apa)</div><div class="content">${escapeHtml(forensic.WHAT || '-')}</div></div>
      <div class="forensic-item"><div class="label">⏱️ WHEN (Kapan)</div><div class="content">${escapeHtml(forensic.WHEN || '-')}</div></div>
      <div class="forensic-item"><div class="label">📍 WHERE (Dimana)</div><div class="content">${escapeHtml(forensic.WHERE || '-')}</div></div>
      <div class="forensic-item"><div class="label">❓ WHY (Mengapa)</div><div class="content">${escapeHtml(forensic.WHY || '-')}</div></div>
      <div class="forensic-item"><div class="label">🔧 HOW (Bagaimana)</div><div class="content">${escapeHtml(forensic.HOW || '-')}</div></div>
    </div>
  </div>

  <!-- KPI CARDS -->
  <div class="grid">
    <div class="card"><h3>Risk Score</h3><div class="value ${riskClass}">${report.riskScore}/100</div><div>${report.riskLevel}</div></div>
    <div class="card"><h3>Total Events</h3><div class="value">${report.totalEvents.toLocaleString()}</div></div>
    <div class="card"><h3>Categories</h3><div class="value">${report.categoriesDetected}/${report.categoriesMonitored}</div></div>
    <div class="card"><h3>Origins</h3><div class="value">${report.uniqueOrigins.length}</div></div>
    <div class="card"><h3>Frames</h3><div class="value">${report.uniqueFrames?.length || 0}</div></div>
    <div class="card"><h3>Threats</h3><div class="value ${report.threats.length > 5 ? 'danger' : report.threats.length > 0 ? 'warning' : 'safe'}">${report.threats.length}</div></div>
    <div class="card"><h3>Bursts</h3><div class="value ${(report.correlation?.summary?.fingerprintBursts||0) > 0 ? 'danger' : 'safe'}">${report.correlation?.summary?.fingerprintBursts || 0}</div></div>
    <div class="card"><h3>Duration</h3><div class="value">${(report.timeSpanMs / 1000).toFixed(1)}s</div></div>
  </div>

  <!-- COVERAGE PROOF -->
  <div class="section">
    <h2>📡 Coverage Proof (BOOT_OK Protocol)</h2>
    <div class="card">
      <p>Coverage: <span class="coverage-indicator ${coverageClass}">${report.coverageProof?.coverage || 0}%</span>
         — ${report.coverageProof?.monitoredFrames || 0} of ${report.coverageProof?.totalFramesDetected || 0} frames monitored
         — Verdict: <strong>${report.coverageProof?.verdict || 'UNKNOWN'}</strong></p>
      ${report.coverageProof?.unmonitoredFrames?.length > 0 ? 
        '<p style="color:var(--danger);margin-top:8px;">⚠️ Unmonitored frames: ' + 
        report.coverageProof.unmonitoredFrames.map(u => '<code>' + escapeHtml(String(u).slice(0, 80)) + '</code>').join(', ') + '</p>' : 
        '<p style="color:var(--safe);margin-top:8px;">✅ All detected frames are being monitored</p>'}
    </div>
  </div>

  ${report.threats.length > 0 ? `
  <!-- THREATS -->
  <div class="section">
    <h2>🚨 Threat Assessment</h2>
    <table>
      <thead><tr><th>Threat</th><th>Severity</th><th>Detail</th><th>WHO</th><th>HOW</th></tr></thead>
      <tbody>${threatRows}</tbody>
    </table>
  </div>` : ''}

  <!-- TABBED SECTIONS -->
  <div class="tab-container">
    <div class="tab-buttons">
      <button class="tab-btn active" onclick="showTab('timeline')">📈 Timeline</button>
      <button class="tab-btn" onclick="showTab('attribution')">📚 Attribution</button>
      <button class="tab-btn" onclick="showTab('bursts')">💥 Bursts</button>
      <button class="tab-btn" onclick="showTab('exfil')">📡 Exfiltration</button>
      <button class="tab-btn" onclick="showTab('values')">🔬 Values</button>
      <button class="tab-btn" onclick="showTab('categories')">📊 Categories</button>
      <button class="tab-btn" onclick="showTab('apis')">🔗 Top APIs</button>
      <button class="tab-btn" onclick="showTab('entropy')">🎲 Entropy</button>
    </div>

    <div id="tab-timeline" class="tab-content active">
      <h2>📈 Event Timeline</h2>
      <canvas id="timelineChart" height="200"></canvas>
    </div>

    <div id="tab-attribution" class="tab-content">
      <h2>📚 Library Attribution</h2>
      ${attrRows ? `<table>
        <thead><tr><th>Library</th><th>Confidence</th><th>Matched Patterns</th><th>Burst Match</th><th>Description</th></tr></thead>
        <tbody>${attrRows}</tbody>
      </table>` : '<p style="color:#8b949e;">No known fingerprinting libraries identified.</p>'}
    </div>

    <div id="tab-bursts" class="tab-content">
      <h2>💥 Burst Analysis</h2>
      ${burstRows ? `<table>
        <thead><tr><th>Time Window</th><th>Events</th><th>Duration</th><th>Top Category</th><th>Fingerprint Burst?</th></tr></thead>
        <tbody>${burstRows}</tbody>
      </table>` : '<p style="color:#8b949e;">No significant event bursts detected.</p>'}
    </div>

    <div id="tab-exfil" class="tab-content">
      <h2>📡 Exfiltration Monitor</h2>
      ${exfilRows ? `<table>
        <thead><tr><th>Tracker</th><th>Method</th><th>URL</th><th>Time</th></tr></thead>
        <tbody>${exfilRows}</tbody>
      </table>` : '<p style="color:#8b949e;">No exfiltration events detected.</p>'}
    </div>

    <div id="tab-values" class="tab-content">
      <h2>🔬 Captured Values (Forensic Evidence)</h2>
      ${valueRows ? `<table>
        <thead><tr><th>Time</th><th>API</th><th>Category</th><th>Captured Value</th></tr></thead>
        <tbody>${valueRows}</tbody>
      </table>` : '<p style="color:#8b949e;">No values captured.</p>'}
    </div>

    <div id="tab-categories" class="tab-content">
      <h2>📊 Category Breakdown</h2>
      <table>
        <thead><tr><th>Category</th><th>Events</th><th>Risk Level</th></tr></thead>
        <tbody>${catRows}</tbody>
      </table>
    </div>

    <div id="tab-apis" class="tab-content">
      <h2>🔗 Top 30 APIs</h2>
      <table>
        <thead><tr><th>API</th><th>Calls</th></tr></thead>
        <tbody>${apiRows}</tbody>
      </table>
    </div>

    <div id="tab-entropy" class="tab-content">
      <h2>🎲 Entropy Analysis</h2>
      <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
        <div class="card"><h3>Category Entropy</h3><div class="value">${report.correlation?.entropy?.categoryEntropy?.toFixed(2) || '0'}</div><div>Shannon bits</div></div>
        <div class="card"><h3>API Entropy</h3><div class="value">${report.correlation?.entropy?.apiEntropy?.toFixed(2) || '0'}</div><div>Shannon bits</div></div>
        <div class="card"><h3>Origin Entropy</h3><div class="value">${report.correlation?.entropy?.originEntropy?.toFixed(2) || '0'}</div><div>Shannon bits</div></div>
        <div class="card"><h3>Diversity Score</h3><div class="value">${report.correlation?.entropy?.diversityScore || 0}/100</div></div>
        <div class="card"><h3>Unique APIs</h3><div class="value">${report.correlation?.entropy?.uniqueApis || 0}</div></div>
        <div class="card"><h3>Unique Categories</h3><div class="value">${report.correlation?.entropy?.uniqueCategories || 0}</div></div>
      </div>
    </div>
  </div>

  <footer>
    <p>Sentinel v4.0.0 — Forensic Maling Catcher | Generated ${new Date().toISOString()}</p>
    <p>31 Categories Monitored | 7-Layer Architecture | 1H5W Forensic Framework</p>
  </footer>
</div>

<script>
  function showTab(name) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    event.target.classList.add('active');
  }

  // Simple timeline chart using canvas
  const timelineData = ${timelineData};
  const canvas = document.getElementById('timelineChart');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    const keys = Object.keys(timelineData).map(Number).sort((a,b) => a-b);
    const values = keys.map(k => timelineData[k]);
    const maxVal = Math.max(...values, 1);
    const w = canvas.width = canvas.parentElement.clientWidth;
    const h = canvas.height = 250;
    const padding = { top: 20, right: 20, bottom: 40, left: 50 };
    const chartW = w - padding.left - padding.right;
    const chartH = h - padding.top - padding.bottom;

    ctx.fillStyle = '#161b22';
    ctx.fillRect(0, 0, w, h);

    if (keys.length > 0) {
      const barW = Math.max(2, (chartW / keys.length) - 1);

      keys.forEach((sec, i) => {
        const val = timelineData[sec];
        const barH = (val / maxVal) * chartH;
        const x = padding.left + (i * (chartW / keys.length));
        const y = padding.top + chartH - barH;

        const intensity = val / maxVal;
        if (intensity > 0.6) ctx.fillStyle = '#f85149';
        else if (intensity > 0.3) ctx.fillStyle = '#d29922';
        else ctx.fillStyle = '#58a6ff';

        ctx.fillRect(x, y, barW, barH);
      });

      ctx.fillStyle = '#8b949e';
      ctx.font = '11px monospace';
      ctx.textAlign = 'center';
      const step = Math.max(1, Math.floor(keys.length / 10));
      keys.forEach((sec, i) => {
        if (i % step === 0) {
          ctx.fillText(sec + 's', padding.left + (i * (chartW / keys.length)) + barW/2, h - 10);
        }
      });

      ctx.textAlign = 'right';
      for (let i = 0; i <= 4; i++) {
        const val = Math.round(maxVal * i / 4);
        const y = padding.top + chartH - (chartH * i / 4);
        ctx.fillText(val, padding.left - 8, y + 4);
        ctx.strokeStyle = '#30363d';
        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(w - padding.right, y);
        ctx.stroke();
      }
    } else {
      ctx.fillStyle = '#8b949e';
      ctx.font = '14px monospace';
      ctx.textAlign = 'center';
      ctx.fillText('No timeline data', w/2, h/2);
    }
  }
</script>
</body>
</html>`;
}

function getCatBadge(cat) {
  const riskMap = {
    'canvas': 'high', 'webgl': 'high', 'audio': 'critical',
    'font-detection': 'high', 'fingerprint': 'high',
    'webrtc': 'critical', 'geolocation': 'critical',
    'clipboard': 'critical', 'media-devices': 'critical',
    'service-worker': 'high', 'math-fingerprint': 'medium',
    'storage': 'medium', 'network': 'medium',
    'perf-timing': 'medium', 'screen': 'medium',
    'permissions': 'high', 'dom-probe': 'low',
    'hardware': 'high', 'architecture': 'medium',
    'speech': 'high', 'client-hints': 'critical',
    'intl-fingerprint': 'medium', 'css-fingerprint': 'medium',
    'property-enum': 'high', 'offscreen-canvas': 'high',
    'exfiltration': 'critical', 'honeypot': 'critical',
    'credential': 'critical', 'system': 'info'
  };
  const level = riskMap[cat] || 'low';
  return `<span class="badge badge-${level}">${level.toUpperCase()}</span>`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = { generateReport };
