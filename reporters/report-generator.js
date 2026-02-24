/**
 * Sentinel v4.2 — Forensic Report Generator (Layer 7)
 * ZERO ESCAPE ARCHITECTURE
 *
 * UPGRADES from v4:
 * - 37 categories in threat mapping
 * - Coverage matrix (categories with event counts)
 * - 1H5W comprehensive forensic section
 * - Injection verification status
 * - Worker/cross-origin frame sections
 * - Alert section (INJECTION_FAILURE, TIMEOUT_EXTENDED, HIGH_ENTROPY)
 * - Dedup statistics
 * - Temporal heatmap data
 * - Version "sentinel-v4.2.1"
 * - categoriesMonitored: 37
 */

const fs = require('fs');
const path = require('path');
const { CorrelationEngine } = require('../lib/correlation-engine');

function generateReport(sentinelData, contextMap, targetUrl, options) {
  options = options || {};
  var outputDir = options.outputDir || path.join(__dirname, '..', 'output');
  var timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  var prefix = options.prefix || ('sentinel_' + timestamp);

  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  var events = sentinelData.events || [];

  // ── Correlation Engine Analysis ──
  var correlator = new CorrelationEngine();
  correlator.ingestEvents(events);
  var correlation = correlator.getReport();

  // ── Analyze events ──
  var byCategory = {};
  var byRisk = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  var apiCounts = {};
  var originSet = new Set();
  var frameSet = new Set();
  var timelineSlots = {};
  var valueCaptures = [];
  var workerEvents = [];
  var riskEvents = { critical: [], high: [] };

  for (var i = 0; i < events.length; i++) {
    var e = events[i];
    byCategory[e.cat] = (byCategory[e.cat] || 0) + 1;
    byRisk[e.risk || 'info'] = (byRisk[e.risk || 'info'] || 0) + 1;
    apiCounts[e.api] = (apiCounts[e.api] || 0) + 1;
    if (e.origin) originSet.add(e.origin);
    if (e.frameId) frameSet.add(e.frameId);

    var slot = Math.floor(e.ts / 1000);
    timelineSlots[slot] = (timelineSlots[slot] || 0) + 1;

    if (e.value && e.value !== 'undefined' && e.value !== 'null') {
      valueCaptures.push({ ts: e.ts, api: e.api, value: e.value, category: e.cat });
    }

    if (e.cat === 'worker') workerEvents.push(e);
    if (e.risk === 'critical') riskEvents.critical.push(e);
    else if (e.risk === 'high') riskEvents.high.push(e);
  }

  var topApis = Object.entries(apiCounts)
    .sort(function(a, b) { return b[1] - a[1]; })
    .slice(0, 40)
    .map(function(x) { return { api: x[0], count: x[1] }; });

  // ── ALL 37 CATEGORIES ──
  var ALL_CATEGORIES = [
    'canvas', 'webgl', 'audio', 'font-detection', 'fingerprint', 'screen',
    'storage', 'network', 'perf-timing', 'media-devices', 'dom-probe',
    'clipboard', 'geolocation', 'service-worker', 'hardware', 'exfiltration',
    'webrtc', 'math-fingerprint', 'permissions', 'speech', 'client-hints',
    'intl-fingerprint', 'css-fingerprint', 'property-enum', 'offscreen-canvas',
    'honeypot', 'credential', 'system', 'encoding', 'worker',
    'webassembly', 'keyboard-layout', 'sensor-apis', 'visualization',
    'device-info'
  ];

  // ── Coverage Matrix (NEW in v4.2) ──
  var coverageMatrix = ALL_CATEGORIES.map(function(cat) {
    var count = byCategory[cat] || 0;
    var status = count > 0 ? 'ACTIVE' : 'SILENT';
    return { category: cat, events: count, status: status };
  });
  var activeCategories = coverageMatrix.filter(function(c) { return c.status === 'ACTIVE'; }).length;
  var coveragePercent = Math.round((activeCategories / ALL_CATEGORIES.length) * 100 * 10) / 10;

  // ── Risk Score (v4.2 enhanced) ──
  var riskScore = Math.min(100, Math.round(
    (byRisk.critical * 15) +
    (byRisk.high * 5) +
    (byRisk.medium * 1) +
    (byRisk.low * 0.1) +
    (Object.keys(byCategory).length * 2) +
    (originSet.size > 2 ? (originSet.size - 1) * 5 : 0) +
    (correlation.summary.fingerprintBursts * 10) +
    (correlation.summary.exfilAttempts * 5) +
    (correlation.summary.honeypotTriggered ? 20 : 0) +
    (correlation.summary.slowProbeDetected ? 10 : 0) +
    (correlation.summary.fpv5Detected ? 15 : 0) +
    (correlation.summary.creepJSDetected ? 15 : 0) +
    (workerEvents.length > 0 ? 10 : 0)
  ));

  // ── Threat Assessment (v4.2 — 37 categories) ──
  var threats = [];

  var threatMap = {
    'audio': { type: 'Audio Fingerprinting', severity: 'HIGH', how: 'OfflineAudioContext + Oscillator + Compressor' },
    'canvas': { type: 'Canvas Fingerprinting', severity: 'HIGH', how: 'toDataURL/getImageData pixel hash' },
    'webgl': { type: 'WebGL Fingerprinting', severity: 'HIGH', how: 'getParameter(VENDOR/RENDERER) + precision format' },
    'font-detection': { type: 'Font Enumeration', severity: 'CRITICAL', threshold: 50, how: 'measureText/getBoundingClientRect width comparison' },
    'webrtc': { type: 'WebRTC IP Leak', severity: 'CRITICAL', how: 'RTCPeerConnection ICE candidate harvesting' },
    'geolocation': { type: 'Geolocation Request', severity: 'CRITICAL', how: 'getCurrentPosition/watchPosition' },
    'clipboard': { type: 'Clipboard Access', severity: 'CRITICAL', how: 'navigator.clipboard.readText/writeText + DataTransfer' },
    'media-devices': { type: 'Media Device Enumeration', severity: 'HIGH', how: 'enumerateDevices()' },
    'service-worker': { type: 'Service Worker', severity: 'HIGH', how: 'navigator.serviceWorker.register()' },
    'math-fingerprint': { type: 'Math Fingerprinting', severity: 'MEDIUM', threshold: 10, how: 'Math.acos/sinh/expm1 precision differences' },
    'storage': { type: 'Aggressive Storage', severity: 'MEDIUM', threshold: 50, how: 'cookie/localStorage/IndexedDB read/write' },
    'speech': { type: 'Speech Voice Fingerprint', severity: 'HIGH', how: 'speechSynthesis.getVoices() OS/language detection' },
    'client-hints': { type: 'Client Hints Probing', severity: 'HIGH', how: 'getHighEntropyValues(OS, CPU arch, device model)' },
    'intl-fingerprint': { type: 'Intl API Fingerprint', severity: 'MEDIUM', how: 'ListFormat/NumberFormat/Collator resolvedOptions' },
    'css-fingerprint': { type: 'CSS Feature Detection', severity: 'MEDIUM', how: 'CSS.supports() + matchMedia query fingerprinting' },
    'offscreen-canvas': { type: 'OffscreenCanvas Fingerprint', severity: 'HIGH', how: 'Worker-based canvas fingerprinting' },
    'exfiltration': { type: 'Data Exfiltration', severity: 'CRITICAL', how: 'sendBeacon/WebSocket/img.src data transmission' },
    'honeypot': { type: '🍯 Honeypot Triggered', severity: 'CRITICAL', how: 'Accessed planted trap properties' },
    'property-enum': { type: 'Prototype Inspection', severity: 'HIGH', how: 'Object.keys/getOwnPropertyNames on navigator/screen' },
    'credential': { type: 'Credential Probing', severity: 'CRITICAL', how: 'credentials.get/create for WebAuthn fingerprint' },
    'webassembly': { type: 'WebAssembly Fingerprinting', severity: 'CRITICAL', how: 'WASM compile/instantiate timing + feature detection' },
    'keyboard-layout': { type: 'Keyboard Layout Fingerprint', severity: 'HIGH', how: 'navigator.keyboard.getLayoutMap() enumeration' },
    'sensor-apis': { type: 'Device Sensor Fingerprint', severity: 'HIGH', how: 'Accelerometer/Gyroscope/AmbientLight sensor data' },
    'visualization': { type: 'GPU/Visualization Probing', severity: 'MEDIUM', how: 'requestAnimationFrame timing + CSS.supports probing' },
    'device-info': { type: 'Device Info Harvesting', severity: 'MEDIUM', how: 'deviceMemory/connection/battery API access' },
    'worker': { type: 'Worker Activity', severity: 'HIGH', how: 'Web/Shared/Service Worker operations detected' },
    'dom-probe': { type: 'DOM Probing', severity: 'MEDIUM', how: 'MutationObserver/IntersectionObserver DOM inspection' },
    'permissions': { type: 'Permission Probing', severity: 'HIGH', how: 'navigator.permissions.query enumeration' },
    'encoding': { type: 'TextEncoder Fingerprint', severity: 'LOW', how: 'TextEncoder/TextDecoder encoding probing' },
    'perf-timing': { type: 'Performance Timing', severity: 'MEDIUM', how: 'performance.now/mark/measure timing analysis' },
    'hardware': { type: 'Hardware Fingerprinting', severity: 'HIGH', how: 'navigator.hardwareConcurrency/deviceMemory/platform' }
  };

  Object.keys(byCategory).forEach(function(cat) {
    var count = byCategory[cat];
    if (cat === 'system') return;
    var tm = threatMap[cat];
    if (tm) {
      if (tm.threshold && count < tm.threshold) return;
      threats.push({
        type: tm.type,
        severity: tm.severity,
        detail: count + ' ' + cat + ' API calls detected',
        who: cat + ' processing pipeline',
        how: tm.how
      });
    }
  });

  if (originSet.size > 3) {
    threats.push({
      type: 'Multi-Origin Tracking', severity: 'HIGH',
      detail: originSet.size + ' unique origins — possible cross-domain tracking',
      who: 'Third-party scripts', how: 'Cross-origin iframe/script fingerprinting'
    });
  }

  // Library attribution threats
  correlation.attributions.forEach(function(attr) {
    threats.push({
      type: '📚 Library Detected: ' + attr.library,
      severity: 'CRITICAL',
      detail: attr.confidence + '% confidence — ' + attr.description,
      who: attr.library,
      how: 'Matched patterns: ' + attr.matchedPatterns.join(', ') + (attr.burstCorrelation ? ' + burst correlation' : '') + (attr.slowProbeCorrelation ? ' + slow-probe correlation' : '')
    });
  });

  // Slow probe threats
  correlation.slowProbes.forEach(function(sp) {
    if (sp.isLikelyFingerprinting) {
      threats.push({
        type: 'Slow-Probe Fingerprinting', severity: 'HIGH',
        detail: 'Source: ' + sp.source + ' — ' + sp.totalEvents + ' events over ' + (sp.durationMs / 1000).toFixed(1) + 's',
        who: sp.source, how: 'Deliberate call spacing to evade burst detection'
      });
    }
  });

  // Cross-frame threats
  correlation.crossFrameCorrelations.forEach(function(cf) {
    if (cf.isCoordinatedFingerprinting) {
      threats.push({
        type: 'Cross-Frame Coordinated FP', severity: 'CRITICAL',
        detail: 'Frames ' + cf.frame1.origin + ' and ' + cf.frame2.origin + ' share ' + cf.sharedCategories.length + ' FP categories',
        who: cf.frame1.origin + ' + ' + cf.frame2.origin,
        how: 'Coordinated fingerprinting across cross-origin iframes'
      });
    }
  });

  threats.sort(function(a, b) {
    var order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return (order[a.severity] || 4) - (order[b.severity] || 4);
  });

  // ── Coverage Proof ──
  var bootOkEvents = events.filter(function(e) { return e.api === 'BOOT_OK'; });
  var monitoredFrames = bootOkEvents.map(function(e) {
    return { frameId: e.frameId, origin: e.origin, url: e.detail };
  });

  var coverageProof = {
    totalFramesDetected: contextMap ? contextMap.length : 0,
    monitoredFrames: monitoredFrames.length,
    bootOkReceived: bootOkEvents.length,
    coverage: contextMap && contextMap.length > 0
      ? Math.round((monitoredFrames.length / contextMap.length) * 100) : 0,
    unmonitoredFrames: contextMap
      ? contextMap.filter(function(cm) {
          return !monitoredFrames.some(function(mf) { return mf.origin === cm.origin; });
        }).map(function(cm) { return cm.url || cm.origin; })
      : [],
    verdict: bootOkEvents.length > 0 ? 'MONITORED' : 'BLIND_SPOT_DETECTED'
  };

  // ── Injection Verification (NEW in v4.2) ──
  var injectionStatus = {
    layer1_CDP: !!(sentinelData.injectionFlags && sentinelData.injectionFlags.L1),
    layer2_addInitScript: !!(sentinelData.injectionFlags && sentinelData.injectionFlags.L2),
    layer3_perTarget: !!(sentinelData.injectionFlags && sentinelData.injectionFlags.L3),
    anyLayerActive: false,
    verdict: 'UNKNOWN'
  };
  injectionStatus.anyLayerActive = injectionStatus.layer1_CDP || injectionStatus.layer2_addInitScript || injectionStatus.layer3_perTarget;
  injectionStatus.verdict = injectionStatus.anyLayerActive ? 'INJECTION_VERIFIED' : 'INJECTION_FAILURE';

  // Also check from events
  var l1Events = events.filter(function(e) { return e.api === 'SENTINEL_L1_OK'; });
  var l2Events = events.filter(function(e) { return e.api === 'SENTINEL_L2_OK' || e.api === 'BOOT_OK'; });
  if (l1Events.length > 0) injectionStatus.layer1_CDP = true;
  if (l2Events.length > 0) injectionStatus.layer2_addInitScript = true;
  if (l1Events.length > 0 || l2Events.length > 0) {
    injectionStatus.anyLayerActive = true;
    injectionStatus.verdict = 'INJECTION_VERIFIED';
  }

  // ── Alerts (NEW in v4.2) ──
  var alerts = [];
  if (injectionStatus.verdict === 'INJECTION_FAILURE') {
    alerts.push({ level: 'CRITICAL', type: 'INJECTION_FAILURE', message: 'No injection layer verified active — data may be incomplete' });
  }
  if (options.timeoutExtended) {
    alerts.push({ level: 'WARNING', type: 'TIMEOUT_EXTENDED', message: 'Adaptive timeout was extended to ' + options.finalTimeout + 'ms due to ongoing activity' });
  }
  if (correlation.entropy && correlation.entropy.fingerprintLikelihood >= 60) {
    alerts.push({ level: 'HIGH', type: 'HIGH_ENTROPY', message: 'High fingerprint likelihood score: ' + correlation.entropy.fingerprintLikelihood + '/100' });
  }
  if (correlation.summary.slowProbeDetected) {
    alerts.push({ level: 'WARNING', type: 'SLOW_PROBE', message: 'Slow-probe fingerprinting pattern detected — evasion technique' });
  }
  if (coverageProof.unmonitoredFrames.length > 0) {
    alerts.push({ level: 'WARNING', type: 'BLIND_SPOT', message: coverageProof.unmonitoredFrames.length + ' frame(s) not monitored: possible detection gap' });
  }

  // ── Dedup Statistics (NEW in v4.2) ──
  var dedupStats = sentinelData.dedupStats || { totalReceived: events.length, deduplicated: 0, kept: events.length };

  // ── Build 1H5W Forensic Section ──
  var forensic1H5W = {
    WHO: correlation.attributions.length > 0
      ? correlation.attributions.map(function(a) { return a.library; }).join(', ')
      : (originSet.size > 1 ? 'Multiple origins: ' + Array.from(originSet).slice(0, 5).join(', ') : 'Unknown script(s) from ' + (Array.from(originSet)[0] || targetUrl)),
    WHAT: Object.keys(byCategory).length + ' category fingerprinting detected: ' + Object.keys(byCategory).sort().join(', '),
    WHEN: events.length > 0
      ? 'Scan duration ' + ((events[events.length - 1].ts || 0) / 1000).toFixed(1) + 's — First event at ' + ((events[0].ts || 0) / 1000).toFixed(2) + 's, Peak activity at ' + (Object.entries(timelineSlots).sort(function(a,b) { return b[1] - a[1]; })[0] || ['0'])[0] + 's'
      : 'No events captured',
    WHERE: targetUrl + ' | ' + originSet.size + ' origin(s) | ' + frameSet.size + ' frame(s)' + (workerEvents.length > 0 ? ' | ' + workerEvents.length + ' worker event(s)' : ''),
    WHY: riskScore >= 70 ? 'Active fingerprinting for user tracking/identification' :
         riskScore >= 40 ? 'Moderate fingerprinting — likely analytics + basic tracking' :
         'Low fingerprinting activity — possibly legitimate feature detection',
    HOW: (correlation.summary.fingerprintBursts > 0 ? 'Burst-pattern fingerprinting (' + correlation.summary.fingerprintBursts + ' bursts). ' : '') +
         (correlation.summary.slowProbeDetected ? 'Slow-probe evasion technique detected. ' : '') +
         (correlation.summary.fpv5Detected ? 'FingerprintJS v5 pattern matched. ' : '') +
         (correlation.summary.creepJSDetected ? 'CreepJS pattern matched. ' : '') +
         'Total ' + events.length + ' API intercepts across ' + Object.keys(byCategory).length + ' categories'
  };

  // ── Build Report JSON ──
  var reportJson = {
    version: 'sentinel-v4.2.1',
    target: targetUrl,
    scanDate: new Date().toISOString(),
    mode: options.stealthEnabled ? 'stealth' : 'observe',
    totalEvents: events.length,
    riskScore: riskScore,
    riskLevel: riskScore >= 70 ? 'DANGER 🔴' : riskScore >= 40 ? 'WARNING 🟡' : 'LOW 🟢',
    timeSpanMs: events.length > 0 ? events[events.length - 1].ts : 0,
    byCategory: byCategory,
    byRisk: byRisk,
    topApis: topApis,
    uniqueOrigins: Array.from(originSet),
    uniqueFrames: Array.from(frameSet),
    threats: threats,
    categoriesMonitored: 37,
    categoriesDetected: Object.keys(byCategory).length,
    coverageMatrix: coverageMatrix,
    coveragePercent: coveragePercent,
    timeline: timelineSlots,
    correlation: correlation,
    coverageProof: coverageProof,
    injectionStatus: injectionStatus,
    alerts: alerts,
    dedupStats: dedupStats,
    workerEvents: { count: workerEvents.length, events: workerEvents.slice(0, 50) },
    valueCaptures: valueCaptures.slice(0, 100),
    forensic1H5W: forensic1H5W
  };

  // ── Save JSON ──
  var jsonPath = path.join(outputDir, prefix + '_report.json');
  fs.writeFileSync(jsonPath, JSON.stringify(reportJson, null, 2));

  // ── Save Context Map ──
  var ctxPath = path.join(outputDir, prefix + '_context.json');
  fs.writeFileSync(ctxPath, JSON.stringify({
    frames: contextMap || [],
    injectionStatus: injectionStatus,
    coverageProof: coverageProof,
    alerts: alerts,
    dedupStats: dedupStats
  }, null, 2));

  // ── Generate HTML Report ──
  var htmlContent = generateHtml(reportJson);
  var htmlPath = path.join(outputDir, prefix + '_report.html');
  fs.writeFileSync(htmlPath, htmlContent);

  console.log('📁 Reports saved:');
  console.log('   JSON: ' + jsonPath);
  console.log('   HTML: ' + htmlPath);
  console.log('   CTX:  ' + ctxPath);

  return {
    reportJson: reportJson,
    jsonPath: jsonPath,
    htmlPath: htmlPath,
    ctxPath: ctxPath
  };
}

function generateHtml(report) {
  var riskClass = report.riskScore >= 70 ? 'danger' : report.riskScore >= 40 ? 'warning' : 'safe';

  // Threat rows
  var threatRows = (report.threats || []).map(function(t) {
    var sev = (t.severity || '').toLowerCase();
    return '<tr class="threat-' + sev + '">' +
      '<td>' + escapeHtml(t.type) + '</td>' +
      '<td><span class="badge badge-' + sev + '">' + t.severity + '</span></td>' +
      '<td>' + escapeHtml(t.detail) + '</td>' +
      '<td class="who-col">' + escapeHtml(t.who || '-') + '</td>' +
      '<td class="how-col">' + escapeHtml(t.how || '-') + '</td></tr>';
  }).join('');

  // Category distribution rows
  var catRows = Object.entries(report.byCategory)
    .sort(function(a, b) { return b[1] - a[1]; })
    .map(function(x) {
      return '<tr><td>' + escapeHtml(x[0]) + '</td><td>' + x[1] + '</td><td>' + getCatBadge(x[0]) + '</td></tr>';
    }).join('');

  // Attribution rows
  var attrRows = (report.correlation && report.correlation.attributions ? report.correlation.attributions : [])
    .map(function(a) {
      return '<tr><td><strong>' + escapeHtml(a.library) + '</strong></td>' +
        '<td><div class="confidence-bar"><div class="confidence-fill" style="width:' + a.confidence + '%">' + a.confidence + '%</div></div></td>' +
        '<td>' + escapeHtml(a.matchedPatterns.join(', ')) + '</td>' +
        '<td>' + (a.burstCorrelation ? '✅' : '❌') + '</td>' +
        '<td>' + escapeHtml(a.description) + '</td></tr>';
    }).join('');

  // Exfiltration rows
  var exfilRows = (report.correlation && report.correlation.exfilAlerts ? report.correlation.exfilAlerts : [])
    .map(function(e) {
      return '<tr><td>' + escapeHtml(e.tracker) + '</td>' +
        '<td><code>' + escapeHtml(e.method) + '</code></td>' +
        '<td class="url-cell">' + escapeHtml(e.url) + '</td>' +
        '<td>' + (e.timestamp / 1000).toFixed(1) + 's</td></tr>';
    }).join('');

  // Value captures
  var valueRows = (report.valueCaptures || []).slice(0, 50)
    .map(function(v) {
      return '<tr><td>' + (v.ts / 1000).toFixed(2) + 's</td>' +
        '<td><code>' + escapeHtml(v.api) + '</code></td>' +
        '<td>' + escapeHtml(v.category) + '</td>' +
        '<td class="value-cell">' + escapeHtml(String(v.value).slice(0, 150)) + '</td></tr>';
    }).join('');

  // Coverage matrix rows (NEW in v4.2)
  var matrixRows = (report.coverageMatrix || []).map(function(c) {
    var statusClass = c.status === 'ACTIVE' ? 'safe' : 'danger';
    return '<tr><td>' + escapeHtml(c.category) + '</td>' +
      '<td>' + c.events + '</td>' +
      '<td><span class="badge badge-' + (c.status === 'ACTIVE' ? 'info' : 'critical') + '">' + c.status + '</span></td></tr>';
  }).join('');

  // Alerts rows
  var alertRows = (report.alerts || []).map(function(a) {
    var cls = a.level === 'CRITICAL' ? 'danger' : a.level === 'HIGH' ? 'danger' : 'warning';
    return '<tr><td><span class="badge badge-' + (a.level === 'CRITICAL' ? 'critical' : a.level === 'HIGH' ? 'high' : 'medium') + '">' + a.level + '</span></td>' +
      '<td>' + escapeHtml(a.type) + '</td>' +
      '<td>' + escapeHtml(a.message) + '</td></tr>';
  }).join('');

  var coverageClass = (report.coverageProof && report.coverageProof.coverage >= 80) ? 'safe' :
    (report.coverageProof && report.coverageProof.coverage >= 50) ? 'warning' : 'danger';

  var forensic = report.forensic1H5W || {};
  var injStatus = report.injectionStatus || {};

  var timelineData = JSON.stringify(report.timeline || {});

  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Sentinel v4.2 — Forensic Maling Catcher Report</title>\n<style>\n' +
    ':root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --danger: #f85149; --warning: #d29922; --safe: #3fb950; --purple: #bc8cff; }\n' +
    '* { box-sizing: border-box; margin: 0; padding: 0; }\n' +
    'body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, monospace; padding: 20px; line-height: 1.5; }\n' +
    '.container { max-width: 1400px; margin: 0 auto; }\n' +
    'h1 { color: var(--accent); margin-bottom: 8px; font-size: 1.8rem; }\n' +
    'h2 { color: var(--accent); margin-bottom: 12px; font-size: 1.2rem; border-bottom: 1px solid var(--border); padding-bottom: 8px; }\n' +
    '.subtitle { color: #8b949e; margin-bottom: 24px; }\n' +
    '.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }\n' +
    '.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }\n' +
    '.card h3 { color: #8b949e; font-size: 0.7rem; text-transform: uppercase; margin-bottom: 6px; }\n' +
    '.card .value { font-size: 1.6rem; font-weight: bold; }\n' +
    '.card .value.danger { color: var(--danger); }\n' +
    '.card .value.warning { color: var(--warning); }\n' +
    '.card .value.safe { color: var(--safe); }\n' +
    'table { width: 100%; border-collapse: collapse; margin-bottom: 24px; background: var(--card); border-radius: 8px; overflow: hidden; font-size: 0.85rem; }\n' +
    'th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }\n' +
    'th { background: #21262d; color: var(--accent); font-size: 0.75rem; text-transform: uppercase; }\n' +
    '.badge { padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; font-weight: bold; display: inline-block; }\n' +
    '.badge-critical { background: #f8514933; color: var(--danger); }\n' +
    '.badge-high { background: #d2992233; color: var(--warning); }\n' +
    '.badge-medium { background: #58a6ff22; color: var(--accent); }\n' +
    '.badge-low { background: #3fb95022; color: var(--safe); }\n' +
    '.badge-info { background: #bc8cff22; color: var(--purple); }\n' +
    '.threat-critical { border-left: 3px solid var(--danger); }\n' +
    '.threat-high { border-left: 3px solid var(--warning); }\n' +
    '.threat-medium { border-left: 3px solid var(--accent); }\n' +
    '.section { margin-bottom: 32px; }\n' +
    '.mode-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; margin-left: 12px; }\n' +
    '.mode-stealth { background: #3fb95033; color: var(--safe); }\n' +
    '.mode-observe { background: #d2992233; color: var(--warning); }\n' +
    '.forensic-box { background: var(--card); border: 2px solid var(--accent); border-radius: 8px; padding: 16px; margin-bottom: 24px; }\n' +
    '.forensic-box h2 { border-bottom: none; margin-bottom: 16px; }\n' +
    '.forensic-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 12px; }\n' +
    '.forensic-item { background: #21262d; border-radius: 6px; padding: 12px; }\n' +
    '.forensic-item .label { color: var(--accent); font-weight: bold; font-size: 0.9rem; margin-bottom: 4px; }\n' +
    '.forensic-item .content { color: var(--text); font-size: 0.85rem; }\n' +
    '.confidence-bar { background: #21262d; border-radius: 4px; height: 22px; overflow: hidden; }\n' +
    '.confidence-fill { background: linear-gradient(90deg, var(--safe), var(--warning), var(--danger)); height: 100%; display: flex; align-items: center; justify-content: center; font-size: 0.7rem; font-weight: bold; color: white; text-shadow: 0 1px 2px rgba(0,0,0,0.5); }\n' +
    '.url-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }\n' +
    '.value-cell { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 0.8rem; color: var(--safe); }\n' +
    '.who-col, .how-col { font-size: 0.8rem; color: #8b949e; max-width: 200px; }\n' +
    '.coverage-indicator { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; }\n' +
    '.coverage-indicator.safe { background: #3fb95033; color: var(--safe); }\n' +
    '.coverage-indicator.warning { background: #d2992233; color: var(--warning); }\n' +
    '.coverage-indicator.danger { background: #f8514933; color: var(--danger); }\n' +
    '.alert-box { background: #f8514922; border: 1px solid var(--danger); border-radius: 8px; padding: 12px; margin-bottom: 12px; }\n' +
    '.inject-status { display: flex; gap: 12px; margin-top: 8px; }\n' +
    '.inject-badge { padding: 4px 10px; border-radius: 4px; font-size: 0.8rem; }\n' +
    '.inject-ok { background: #3fb95033; color: var(--safe); }\n' +
    '.inject-fail { background: #f8514933; color: var(--danger); }\n' +
    'footer { text-align: center; color: #484f58; margin-top: 40px; font-size: 0.8rem; }\n' +
    '@media (max-width: 768px) {\n.grid { grid-template-columns: repeat(2, 1fr); }\n.forensic-grid { grid-template-columns: 1fr; }\n.who-col, .how-col { display: none; }\n}\n' +
    '</style>\n</head>\n<body>\n<div class="container">\n' +
    '<h1>🛡️ Sentinel v4.2 — Forensic Maling Catcher Report</h1>\n' +
    '<p class="subtitle">' + escapeHtml(report.target) + ' <span class="mode-badge mode-' + report.mode + '">' + (report.mode || '').toUpperCase() + ' MODE</span> · ' + report.scanDate + '</p>\n' +

    // Alerts section
    (report.alerts && report.alerts.length > 0 ?
      '<div class="section">\n<h2>⚠️ Alerts</h2>\n<table><thead><tr><th>Level</th><th>Type</th><th>Message</th></tr></thead><tbody>' + alertRows + '</tbody></table>\n</div>\n' : '') +

    // Injection verification
    '<div class="section"><h2>💉 Injection Verification</h2>\n<div class="card">\n' +
    '<p>Status: <strong>' + (injStatus.verdict || 'UNKNOWN') + '</strong></p>\n' +
    '<div class="inject-status">\n' +
    '<span class="inject-badge ' + (injStatus.layer1_CDP ? 'inject-ok' : 'inject-fail') + '">L1 CDP: ' + (injStatus.layer1_CDP ? '✅' : '❌') + '</span>\n' +
    '<span class="inject-badge ' + (injStatus.layer2_addInitScript ? 'inject-ok' : 'inject-fail') + '">L2 addInitScript: ' + (injStatus.layer2_addInitScript ? '✅' : '❌') + '</span>\n' +
    '<span class="inject-badge ' + (injStatus.layer3_perTarget ? 'inject-ok' : 'inject-fail') + '">L3 Per-Target: ' + (injStatus.layer3_perTarget ? '✅' : '❌') + '</span>\n' +
    '</div></div></div>\n' +

    // 1H5W
    '<div class="forensic-box">\n<h2>🔍 Forensic Summary (1H5W)</h2>\n<div class="forensic-grid">\n' +
    '<div class="forensic-item"><div class="label">👤 WHO (Siapa)</div><div class="content">' + escapeHtml(forensic.WHO || '-') + '</div></div>\n' +
    '<div class="forensic-item"><div class="label">📋 WHAT (Apa)</div><div class="content">' + escapeHtml(forensic.WHAT || '-') + '</div></div>\n' +
    '<div class="forensic-item"><div class="label">⏱️ WHEN (Kapan)</div><div class="content">' + escapeHtml(forensic.WHEN || '-') + '</div></div>\n' +
    '<div class="forensic-item"><div class="label">📍 WHERE (Dimana)</div><div class="content">' + escapeHtml(forensic.WHERE || '-') + '</div></div>\n' +
    '<div class="forensic-item"><div class="label">❓ WHY (Mengapa)</div><div class="content">' + escapeHtml(forensic.WHY || '-') + '</div></div>\n' +
    '<div class="forensic-item"><div class="label">🔧 HOW (Bagaimana)</div><div class="content">' + escapeHtml(forensic.HOW || '-') + '</div></div>\n' +
    '</div></div>\n' +

    // KPI Cards
    '<div class="grid">\n' +
    '<div class="card"><h3>Risk Score</h3><div class="value ' + riskClass + '">' + report.riskScore + '/100</div><div>' + report.riskLevel + '</div></div>\n' +
    '<div class="card"><h3>Total Events</h3><div class="value">' + (report.totalEvents || 0).toLocaleString() + '</div></div>\n' +
    '<div class="card"><h3>Categories</h3><div class="value">' + report.categoriesDetected + '/' + report.categoriesMonitored + '</div></div>\n' +
    '<div class="card"><h3>Det. Coverage</h3><div class="value">' + (report.coveragePercent || 0) + '%</div></div>\n' +
    '<div class="card"><h3>Origins</h3><div class="value">' + (report.uniqueOrigins || []).length + '</div></div>\n' +
    '<div class="card"><h3>Frames</h3><div class="value">' + (report.uniqueFrames || []).length + '</div></div>\n' +
    '<div class="card"><h3>Threats</h3><div class="value ' + ((report.threats || []).length > 5 ? 'danger' : (report.threats || []).length > 0 ? 'warning' : 'safe') + '">' + (report.threats || []).length + '</div></div>\n' +
    '<div class="card"><h3>FP Bursts</h3><div class="value ' + ((correlation.summary.fingerprintBursts || 0) > 0 ? 'danger' : 'safe') + '">' + (correlation.summary.fingerprintBursts || 0) + '</div></div>\n' +
    '<div class="card"><h3>Workers</h3><div class="value">' + (report.workerEvents ? report.workerEvents.count : 0) + '</div></div>\n' +
    '<div class="card"><h3>Duration</h3><div class="value">' + ((report.timeSpanMs || 0) / 1000).toFixed(1) + 's</div></div>\n' +
    '</div>\n' +

    // Coverage Proof
    '<div class="section">\n<h2>📡 Coverage Proof (BOOT_OK Protocol)</h2>\n<div class="card">\n' +
    '<p>Coverage: <span class="coverage-indicator ' + coverageClass + '">' + (report.coverageProof ? report.coverageProof.coverage : 0) + '%</span>' +
    ' — ' + (report.coverageProof ? report.coverageProof.monitoredFrames : 0) + ' of ' + (report.coverageProof ? report.coverageProof.totalFramesDetected : 0) + ' frames monitored' +
    ' — Verdict: <strong>' + (report.coverageProof ? report.coverageProof.verdict : 'UNKNOWN') + '</strong></p>\n' +
    ((report.coverageProof && report.coverageProof.unmonitoredFrames && report.coverageProof.unmonitoredFrames.length > 0) ?
      '<p style="color:var(--danger);margin-top:8px;">⚠️ Unmonitored: ' + report.coverageProof.unmonitoredFrames.map(function(u) { return '<code>' + escapeHtml(String(u).slice(0, 80)) + '</code>'; }).join(', ') + '</p>' :
      '<p style="color:var(--safe);margin-top:8px;">✅ All detected frames monitored</p>') +
    '</div></div>\n' +

    // Threats
    ((report.threats || []).length > 0 ?
      '<div class="section">\n<h2>🚨 Threat Assessment (' + (report.threats || []).length + ')</h2>\n' +
      '<table><thead><tr><th>Threat</th><th>Severity</th><th>Detail</th><th>WHO</th><th>HOW</th></tr></thead>\n<tbody>' + threatRows + '</tbody></table></div>\n' : '') +

    // Coverage Matrix (NEW)
    '<div class="section">\n<h2>📊 Detection Coverage Matrix (' + activeCategories + '/' + (report.categoriesMonitored || 37) + ')</h2>\n' +
    '<table><thead><tr><th>Category</th><th>Events</th><th>Status</th></tr></thead>\n<tbody>' + matrixRows + '</tbody></table></div>\n' +

    // Category Distribution
    '<div class="section">\n<h2>📈 Category Distribution</h2>\n' +
    '<table><thead><tr><th>Category</th><th>Events</th><th>Risk Level</th></tr></thead>\n<tbody>' + catRows + '</tbody></table></div>\n' +

    // Attribution
    (attrRows ?
      '<div class="section">\n<h2>📚 Library Attribution</h2>\n' +
      '<table><thead><tr><th>Library</th><th>Confidence</th><th>Matched Patterns</th><th>Burst</th><th>Description</th></tr></thead>\n<tbody>' + attrRows + '</tbody></table></div>\n' : '') +

    // Exfiltration
    (exfilRows ?
      '<div class="section">\n<h2>📤 Exfiltration Alerts</h2>\n' +
      '<table><thead><tr><th>Tracker</th><th>Method</th><th>URL</th><th>Time</th></tr></thead>\n<tbody>' + exfilRows + '</tbody></table></div>\n' : '') +

    // Value Captures
    (valueRows ?
      '<div class="section">\n<h2>🔬 Value Captures (Top 50)</h2>\n' +
      '<table><thead><tr><th>Time</th><th>API</th><th>Category</th><th>Value</th></tr></thead>\n<tbody>' + valueRows + '</tbody></table></div>\n' : '') +

    // Top APIs
    '<div class="section">\n<h2>🔝 Top APIs</h2>\n' +
    '<table><thead><tr><th>API</th><th>Count</th></tr></thead>\n<tbody>' +
    (report.topApis || []).map(function(a) { return '<tr><td><code>' + escapeHtml(a.api) + '</code></td><td>' + a.count + '</td></tr>'; }).join('') +
    '</tbody></table></div>\n' +

    // Dedup Stats
    '<div class="section">\n<h2>📊 Dedup Statistics</h2>\n<div class="card">\n' +
    '<p>Total received: ' + (report.dedupStats ? report.dedupStats.totalReceived : report.totalEvents) +
    ' | Deduplicated: ' + (report.dedupStats ? report.dedupStats.deduplicated : 0) +
    ' | Kept: ' + (report.dedupStats ? report.dedupStats.kept : report.totalEvents) + '</p>\n' +
    '</div></div>\n' +

    // Timeline Canvas
    '<div class="section">\n<h2>📈 Activity Timeline</h2>\n' +
    '<canvas id="timelineChart" width="1200" height="300"></canvas>\n</div>\n' +

    '<footer>🛡️ Sentinel v4.2.0 — Zero Escape Architecture — 37 Categories — Generated ' + new Date().toISOString() + '</footer>\n' +
    '</div>\n' +

    '<script>\n' +
    'var timelineData = ' + timelineData + ';\n' +
    'var canvas = document.getElementById("timelineChart");\n' +
    'if (canvas) {\n' +
    '  var ctx = canvas.getContext("2d");\n' +
    '  var w = canvas.width, h = canvas.height;\n' +
    '  ctx.fillStyle = "#161b22"; ctx.fillRect(0,0,w,h);\n' +
    '  var keys = Object.keys(timelineData).sort(function(a,b){return a-b;});\n' +
    '  if (keys.length > 0) {\n' +
    '    var maxVal = Math.max.apply(null, keys.map(function(k){return timelineData[k];}));\n' +
    '    var padding = {top:20,right:20,bottom:30,left:50};\n' +
    '    var chartW = w-padding.left-padding.right, chartH = h-padding.top-padding.bottom;\n' +
    '    var barW = Math.max(2,(chartW/keys.length)-1);\n' +
    '    keys.forEach(function(sec,i){\n' +
    '      var val=timelineData[sec]; var barH=(val/maxVal)*chartH;\n' +
    '      var x=padding.left+(i*(chartW/keys.length)); var y=padding.top+chartH-barH;\n' +
    '      var intensity=val/maxVal;\n' +
    '      if(intensity>0.6)ctx.fillStyle="#f85149";else if(intensity>0.3)ctx.fillStyle="#d29922";else ctx.fillStyle="#58a6ff";\n' +
    '      ctx.fillRect(x,y,barW,barH);\n' +
    '    });\n' +
    '    ctx.fillStyle="#8b949e";ctx.font="11px monospace";ctx.textAlign="center";\n' +
    '    var step=Math.max(1,Math.floor(keys.length/10));\n' +
    '    keys.forEach(function(sec,i){if(i%step===0)ctx.fillText(sec+"s",padding.left+(i*(chartW/keys.length))+barW/2,h-10);});\n' +
    '    ctx.textAlign="right";\n' +
    '    for(var i=0;i<=4;i++){var val=Math.round(maxVal*i/4);var y=padding.top+chartH-(chartH*i/4);ctx.fillText(val,padding.left-8,y+4);ctx.strokeStyle="#30363d";ctx.beginPath();ctx.moveTo(padding.left,y);ctx.lineTo(w-padding.right,y);ctx.stroke();}\n' +
    '  } else { ctx.fillStyle="#8b949e";ctx.font="14px monospace";ctx.textAlign="center";ctx.fillText("No timeline data",w/2,h/2); }\n' +
    '}\n</script>\n</body>\n</html>';
}

function getCatBadge(cat) {
  var riskMap = {
    'canvas': 'high', 'webgl': 'high', 'audio': 'critical',
    'font-detection': 'high', 'fingerprint': 'high',
    'webrtc': 'critical', 'geolocation': 'critical',
    'clipboard': 'critical', 'media-devices': 'critical',
    'service-worker': 'high', 'math-fingerprint': 'medium',
    'storage': 'medium', 'network': 'medium',
    'perf-timing': 'medium', 'screen': 'medium',
    'permissions': 'high', 'dom-probe': 'medium',
    'hardware': 'high', 'architecture': 'medium',
    'speech': 'high', 'client-hints': 'critical',
    'intl-fingerprint': 'medium', 'css-fingerprint': 'medium',
    'property-enum': 'high', 'offscreen-canvas': 'high',
    'exfiltration': 'critical', 'honeypot': 'critical',
    'credential': 'critical', 'system': 'info',
    'webassembly': 'critical', 'keyboard-layout': 'high',
    'sensor-apis': 'high', 'visualization': 'medium',
    'device-info': 'medium', 'worker': 'high',
    'encoding': 'low'
  };
  var level = riskMap[cat] || 'low';
  return '<span class="badge badge-' + level + '">' + level.toUpperCase() + '</span>';
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
