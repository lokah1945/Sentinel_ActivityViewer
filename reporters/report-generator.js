/**
 * Sentinel v4.1 — Forensic Report Generator (Layer 7)
 * JSON + HTML + Context Map with 1H5W forensic framework
 */

const fs = require('fs');
const path = require('path');
const { CorrelationEngine } = require('../lib/correlation-engine');

function generateReport(sentinelData, contextMap, targetUrl, options = {}) {
  const outputDir = options.outputDir || path.join(__dirname, '..', 'output');
  const prefix = options.prefix || `sentinel_${Date.now()}`;

  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const events = sentinelData.events || [];

  // Correlation Engine Analysis
  const correlator = new CorrelationEngine();
  correlator.ingestEvents(events);
  const correlation = correlator.getReport();

  // Analyze events
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

  // Risk Score
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

  // Threat Assessment
  const threats = [];

  if (byCategory['audio'] > 0) threats.push({ type: 'Audio Fingerprinting', severity: 'HIGH', detail: `${byCategory['audio']} audio API calls`, who: 'Audio processing pipeline', how: 'OfflineAudioContext + Oscillator + Compressor' });
  if (byCategory['canvas'] > 0) threats.push({ type: 'Canvas Fingerprinting', severity: 'HIGH', detail: `${byCategory['canvas']} canvas operations`, who: 'Canvas renderer', how: 'toDataURL/getImageData pixel hash' });
  if (byCategory['webgl'] > 0) threats.push({ type: 'WebGL Fingerprinting', severity: 'HIGH', detail: `${byCategory['webgl']} WebGL parameter reads`, who: 'WebGL context', how: 'getParameter(VENDOR/RENDERER)' });
  if (byCategory['font-detection'] > 50) threats.push({ type: 'Font Enumeration', severity: 'CRITICAL', detail: `${byCategory['font-detection']} font probing calls`, who: 'Font detection engine', how: 'measureText/getBoundingClientRect' });
  if (byCategory['webrtc'] > 0) threats.push({ type: 'WebRTC IP Leak', severity: 'CRITICAL', detail: `${byCategory['webrtc']} WebRTC connections`, who: 'WebRTC STUN/TURN', how: 'RTCPeerConnection ICE harvesting' });
  if (byCategory['geolocation'] > 0) threats.push({ type: 'Geolocation Request', severity: 'CRITICAL', detail: 'Location access attempt', who: 'Geolocation API', how: 'getCurrentPosition' });
  if (byCategory['clipboard'] > 0) threats.push({ type: 'Clipboard Access', severity: 'CRITICAL', detail: 'Clipboard read/write', who: 'Clipboard API' });
  if (byCategory['media-devices'] > 0) threats.push({ type: 'Media Device Enum', severity: 'HIGH', detail: 'Camera/mic listing', who: 'MediaDevices API' });
  if (byCategory['service-worker'] > 0) threats.push({ type: 'Service Worker', severity: 'HIGH', detail: 'Persistent background code', who: 'ServiceWorker API' });
  if (byCategory['math-fingerprint'] > 10) threats.push({ type: 'Math Fingerprinting', severity: 'MEDIUM', detail: `${byCategory['math-fingerprint']} Math probes`, who: 'Math precision engine' });
  if (byCategory['storage'] > 50) threats.push({ type: 'Aggressive Storage', severity: 'MEDIUM', detail: `${byCategory['storage']} storage operations` });
  if (byCategory['speech'] > 0) threats.push({ type: 'Speech Voice Fingerprint', severity: 'HIGH', detail: `${byCategory['speech']} speech probes`, who: 'Web Speech API' });
  if (byCategory['client-hints'] > 0) threats.push({ type: 'Client Hints Probing', severity: 'HIGH', detail: `${byCategory['client-hints']} UA-CH requests`, who: 'UA-CH API' });
  if (byCategory['intl-fingerprint'] > 0) threats.push({ type: 'Intl API Fingerprint', severity: 'MEDIUM', detail: `${byCategory['intl-fingerprint']} Intl probes` });
  if (byCategory['css-fingerprint'] > 0) threats.push({ type: 'CSS Feature Detection', severity: 'MEDIUM', detail: `${byCategory['css-fingerprint']} CSS.supports probes` });
  if (byCategory['offscreen-canvas'] > 0) threats.push({ type: 'OffscreenCanvas', severity: 'HIGH', detail: `${byCategory['offscreen-canvas']} OffscreenCanvas ops` });
  if (byCategory['exfiltration'] > 0) threats.push({ type: 'Data Exfiltration', severity: 'CRITICAL', detail: `${byCategory['exfiltration']} exfiltration events` });
  if (byCategory['honeypot'] > 0) threats.push({ type: '🍯 Honeypot Triggered', severity: 'CRITICAL', detail: `CONFIRMED fingerprinting — ${byCategory['honeypot']} trap accesses` });
  if (byCategory['property-enum'] > 0) threats.push({ type: 'Prototype Inspection', severity: 'HIGH', detail: `${byCategory['property-enum']} property enumeration events` });
  if (byCategory['credential'] > 0) threats.push({ type: 'Credential Probing', severity: 'CRITICAL', detail: `${byCategory['credential']} credential API calls` });
  if (originSet.size > 3) threats.push({ type: 'Multi-Origin Tracking', severity: 'HIGH', detail: `${originSet.size} unique origins` });

  for (const attr of correlation.attributions) {
    threats.push({
      type: `📚 Library: ${attr.library}`,
      severity: 'CRITICAL',
      detail: `${attr.confidence}% confidence — ${attr.description}`,
      who: attr.library,
      how: `Patterns: ${attr.matchedPatterns.join(', ')}`
    });
  }

  // Coverage Proof
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
      ? Math.round((Math.max(monitoredFrames.length, 1) / contextMap.length) * 100)
      : 0,
    unmonitoredFrames: contextMap
      ? contextMap.filter(cm => !monitoredFrames.some(mf => mf.origin === cm.origin)).map(cm => cm.url || cm.origin || 'unknown')
      : [],
    verdict: bootOkEvents.length > 0 ? 'MONITORED' : 'BLIND_SPOT_DETECTED'
  };

  // 1H5W Forensic Summary
  const topCats = Object.entries(byCategory).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const firstEvent = events.length > 0 ? events.reduce((a, b) => a.ts < b.ts ? a : b) : null;
  const lastEvent = events.length > 0 ? events.reduce((a, b) => a.ts > b.ts ? a : b) : null;
  const duration = lastEvent && firstEvent ? ((lastEvent.ts - firstEvent.ts) / 1000).toFixed(1) : '0';
  const libs = correlation.attributions.map(a => a.library).join(', ') || 'Unknown';

  const forensic1H5W = {
    WHO: libs !== 'Unknown'
      ? `${libs} fingerprinting script(s)`
      : events.length > 0 ? 'Unknown fingerprinting script(s)' : 'No scripts detected',
    WHAT: events.length > 0
      ? `${events.length} API calls across ${Object.keys(byCategory).length} categories (top: ${topCats.map(c => c[0]).join(', ')})`
      : 'No API calls captured',
    WHEN: events.length > 0
      ? `${duration}s activity window (${firstEvent.ts}ms — ${lastEvent.ts}ms from page load)`
      : 'No events captured',
    WHERE: `${originSet.size} origin(s), ${frameSet.size} frame(s) — Coverage: ${coverageProof.coverage}%`,
    WHY: threats.length > 0
      ? threats.slice(0, 3).map(t => `${t.type} (${t.severity})`).join('; ')
      : 'No threats detected',
    HOW: events.length > 0
      ? 'Multiple API probing across fingerprint vectors'
      : 'No fingerprinting methods observed'
  };

  const categoriesMonitored = 31;

  // Build Report JSON
  const reportJson = {
    version: 'sentinel-v4.1.0',
    target: targetUrl,
    scanDate: new Date().toISOString(),
    mode: options.stealthEnabled ? 'stealth' : 'observe',
    totalEvents: events.length,
    riskScore,
    riskLevel: riskScore >= 70 ? 'DANGER 🔴' : riskScore >= 40 ? 'WARNING 🟡' : 'LOW 🟢',
    categoriesDetected: Object.keys(byCategory).length,
    categoriesMonitored,
    byCategory,
    byRisk,
    topApis,
    uniqueOrigins: [...originSet],
    uniqueFrames: [...frameSet],
    threats,
    correlation,
    coverageProof,
    forensic1H5W,
    timeline: timelineSlots,
    valueCaptures: valueCaptures.slice(0, 100),
    events: events.slice(0, 5000)
  };

  // Save JSON
  const jsonPath = path.join(outputDir, `${prefix}_report.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(reportJson, null, 2));

  // Save Context Map
  const ctxPath = path.join(outputDir, `${prefix}_context-map.json`);
  fs.writeFileSync(ctxPath, JSON.stringify(contextMap || [], null, 2));

  // Generate HTML Report
  const htmlPath = path.join(outputDir, `${prefix}_report.html`);
  const html = generateHTML(reportJson, targetUrl);
  fs.writeFileSync(htmlPath, html);

  return { reportJson, jsonPath, htmlPath, ctxPath };
}

function generateHTML(r, targetUrl) {
  const threatRows = r.threats.map(t => {
    const color = t.severity === 'CRITICAL' ? '#ff4444' : t.severity === 'HIGH' ? '#ffaa00' : '#4488ff';
    return `<tr><td style="color:${color};font-weight:bold">${t.severity}</td><td>${t.type}</td><td>${t.detail}</td><td>${t.who || '-'}</td><td>${t.how || '-'}</td></tr>`;
  }).join('');

  const catRows = Object.entries(r.byCategory).sort((a, b) => b[1] - a[1]).map(([cat, count]) =>
    `<tr><td>${cat}</td><td>${count}</td></tr>`
  ).join('');

  const apiRows = r.topApis.map(a => `<tr><td>${a.api}</td><td>${a.count}</td></tr>`).join('');

  const valueRows = (r.valueCaptures || []).slice(0, 50).map(v =>
    `<tr><td>${v.ts}ms</td><td>${v.api}</td><td>${v.category}</td><td style="max-width:400px;overflow:hidden;text-overflow:ellipsis">${String(v.value).replace(/</g,'&lt;').slice(0, 200)}</td></tr>`
  ).join('');

  const burstRows = (r.correlation?.bursts || []).map(b =>
    `<tr><td>${b.startTs}-${b.endTs}ms</td><td>${b.count}</td><td>${b.durationMs}ms</td><td>${b.topCategory}</td><td>${b.isFingerprintBurst ? '✅ YES' : '❌ No'}</td></tr>`
  ).join('');

  const libRows = (r.correlation?.attributions || []).map(a =>
    `<tr><td>${a.library}</td><td>${a.confidence}%</td><td>${a.matchedPatterns.join(', ')}</td><td>${a.burstCorrelation ? '✅' : '❌'}</td></tr>`
  ).join('');

  const timelineData = Object.entries(r.timeline || {}).sort((a, b) => parseInt(a[0]) - parseInt(b[0]));
  const timelineBars = timelineData.map(([sec, count]) => {
    const height = Math.min(count, 200);
    return `<div style="display:inline-block;width:8px;height:${height}px;background:#00ff88;margin:0 1px;vertical-align:bottom" title="${sec}s: ${count} events"></div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel v4.1 Forensic Report — ${targetUrl}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a0a;color:#e0e0e0;padding:20px;line-height:1.6}
h1{color:#00ff88;font-size:1.8em;margin-bottom:5px}
h2{color:#00ccff;margin:25px 0 10px;border-bottom:1px solid #333;padding-bottom:5px}
h3{color:#ffaa00;margin:15px 0 8px}
.container{max-width:1400px;margin:0 auto}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin:20px 0}
.card{background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:15px;text-align:center}
.card .value{font-size:2em;font-weight:bold;color:#00ff88}
.card .label{font-size:0.85em;color:#888;margin-top:5px}
.risk-high .value{color:#ff4444}
.risk-med .value{color:#ffaa00}
table{width:100%;border-collapse:collapse;margin:10px 0;background:#111}
th{background:#1a1a2e;color:#00ccff;text-align:left;padding:8px;border:1px solid #333}
td{padding:6px 8px;border:1px solid #222;font-size:0.9em}
tr:hover{background:#1a1a2e}
.timeline{background:#111;border:1px solid #333;border-radius:8px;padding:15px;margin:15px 0;min-height:60px;display:flex;align-items:flex-end}
.h5w{background:#1a1a2e;border:1px solid #333;border-radius:8px;padding:15px;margin:15px 0}
.h5w div{margin:5px 0}
.h5w span.label{color:#00ccff;font-weight:bold;display:inline-block;width:80px}
.coverage{padding:10px;border-radius:5px;margin:10px 0}
.coverage-ok{background:#0a2a0a;border:1px solid #00ff88}
.coverage-warn{background:#2a1a0a;border:1px solid #ffaa00}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold}
.badge-critical{background:#ff4444;color:#fff}
.badge-high{background:#ffaa00;color:#000}
.badge-medium{background:#4488ff;color:#fff}
.badge-low{background:#444;color:#ccc}
</style>
</head>
<body>
<div class="container">
<h1>🛡️ SENTINEL v4.1 — FORENSIC REPORT</h1>
<p style="color:#888">Target: <strong>${targetUrl}</strong> | Mode: <strong>${r.mode}</strong> | Scanned: ${r.scanDate}</p>

<div class="summary">
  <div class="card ${r.riskScore >= 70 ? 'risk-high' : r.riskScore >= 40 ? 'risk-med' : ''}">
    <div class="value">${r.riskScore}/100</div><div class="label">Risk Score</div>
  </div>
  <div class="card"><div class="value">${r.totalEvents}</div><div class="label">Total Events</div></div>
  <div class="card"><div class="value">${r.categoriesDetected}/${r.categoriesMonitored}</div><div class="label">Categories</div></div>
  <div class="card"><div class="value">${r.threats.length}</div><div class="label">Threats</div></div>
  <div class="card"><div class="value">${r.uniqueOrigins.length}</div><div class="label">Origins</div></div>
  <div class="card"><div class="value">${r.coverageProof?.coverage || 0}%</div><div class="label">Coverage</div></div>
</div>

<h2>🔍 Forensic 1H5W Analysis</h2>
<div class="h5w">
  <div><span class="label">👤 WHO:</span> ${r.forensic1H5W.WHO}</div>
  <div><span class="label">📋 WHAT:</span> ${r.forensic1H5W.WHAT}</div>
  <div><span class="label">⏱️ WHEN:</span> ${r.forensic1H5W.WHEN}</div>
  <div><span class="label">📍 WHERE:</span> ${r.forensic1H5W.WHERE}</div>
  <div><span class="label">❓ WHY:</span> ${r.forensic1H5W.WHY}</div>
  <div><span class="label">🔧 HOW:</span> ${r.forensic1H5W.HOW}</div>
</div>

<div class="coverage ${r.coverageProof?.verdict === 'MONITORED' ? 'coverage-ok' : 'coverage-warn'}">
  📡 Coverage: ${r.coverageProof?.verdict || 'UNKNOWN'} — ${r.coverageProof?.bootOkReceived || 0} BOOT_OK from ${r.coverageProof?.totalFramesDetected || 0} frames
  ${r.coverageProof?.unmonitoredFrames?.length > 0 ? '<br>⚠️ Unmonitored: ' + r.coverageProof.unmonitoredFrames.slice(0, 5).join(', ') : ''}
</div>

<h2>📊 Event Timeline</h2>
<div class="timeline">${timelineBars || '<span style="color:#666">No events to display</span>'}</div>

${r.threats.length > 0 ? `
<h2>🚨 Threats (${r.threats.length})</h2>
<table><tr><th>Severity</th><th>Type</th><th>Detail</th><th>WHO</th><th>HOW</th></tr>${threatRows}</table>
` : ''}

${libRows ? `
<h2>📚 Library Attribution</h2>
<table><tr><th>Library</th><th>Confidence</th><th>Matched Patterns</th><th>Burst Match</th></tr>${libRows}</table>
` : ''}

${burstRows ? `
<h2>💥 Burst Analysis</h2>
<table><tr><th>Time Range</th><th>Events</th><th>Duration</th><th>Top Category</th><th>FP Burst?</th></tr>${burstRows}</table>
` : ''}

<h2>📂 Categories (${Object.keys(r.byCategory).length})</h2>
<table><tr><th>Category</th><th>Events</th></tr>${catRows}</table>

<h2>🔝 Top APIs</h2>
<table><tr><th>API</th><th>Calls</th></tr>${apiRows}</table>

${valueRows ? `
<h2>🔬 Value Captures (top 50)</h2>
<table><tr><th>Time</th><th>API</th><th>Category</th><th>Captured Value</th></tr>${valueRows}</table>
` : ''}

<h2>📈 Risk Distribution</h2>
<table><tr><th>Level</th><th>Count</th></tr>
<tr><td><span class="badge badge-critical">CRITICAL</span></td><td>${r.byRisk.critical}</td></tr>
<tr><td><span class="badge badge-high">HIGH</span></td><td>${r.byRisk.high}</td></tr>
<tr><td><span class="badge badge-medium">MEDIUM</span></td><td>${r.byRisk.medium}</td></tr>
<tr><td><span class="badge badge-low">LOW</span></td><td>${r.byRisk.low}</td></tr>
<tr><td>INFO</td><td>${r.byRisk.info}</td></tr>
</table>

<p style="margin-top:30px;color:#555;font-size:0.8em">Generated by Sentinel v4.1 — Forensic Maling Catcher | ${r.scanDate}</p>
</div>
</body>
</html>`;
}

module.exports = { generateReport };
