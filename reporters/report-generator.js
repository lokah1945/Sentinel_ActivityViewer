// Sentinel v4.4.2 — Report Generator (Layer 7)
// JSON + HTML + Context Map with 1H5W forensic reporting
// FIXES: timeSpanMs uses max(ts), proper frame coverage, injection flags passthrough

var fs = require('fs');
var path = require('path');
var correlationEngine = require('../lib/correlation-engine');

function generateReports(data, outputDir) {
  var events = data.events || [];
  var target = data.target || '';
  var mode = data.mode || 'observe';
  var injectionFlags = data.injectionFlags || {};
  var frameInfo = data.frameInfo || [];
  var pushEvents = data.pushEvents || [];
  var workerEvents = data.workerEvents || [];
  var scanStartTime = data.scanStartTime || Date.now();

  // Merge push events with main events (dedup by seqId)
  var seenSeqIds = {};
  var allEvents = [];
  for (var i = 0; i < events.length; i++) {
    var key = events[i].seqId !== undefined ? ('seq:' + events[i].seqId) : (events[i].ts + ':' + events[i].api + ':' + events[i].frameId);
    if (!seenSeqIds[key]) {
      seenSeqIds[key] = true;
      allEvents.push(events[i]);
    }
  }
  for (var p = 0; p < pushEvents.length; p++) {
    var pKey = pushEvents[p].seqId !== undefined ? ('seq:' + pushEvents[p].seqId) : (pushEvents[p].ts + ':' + pushEvents[p].api + ':' + pushEvents[p].frameId);
    if (!seenSeqIds[pKey]) {
      seenSeqIds[pKey] = true;
      allEvents.push(pushEvents[p]);
    }
  }

  // Sort by timestamp
  allEvents.sort(function(a, b) { return (a.ts || 0) - (b.ts || 0); });

  // FIX: timeSpanMs = max(ts), not last event ts
  var maxTs = 0;
  for (var t = 0; t < allEvents.length; t++) {
    if ((allEvents[t].ts || 0) > maxTs) maxTs = allEvents[t].ts;
  }

  // Category breakdown
  var byCategory = {};
  var byRisk = {};
  var apiCounts = {};
  var uniqueOrigins = {};
  var uniqueFrames = {};
  var CATEGORIES_MONITORED = 37;

  for (var e = 0; e < allEvents.length; e++) {
    var evt = allEvents[e];
    byCategory[evt.cat] = (byCategory[evt.cat] || 0) + 1;
    byRisk[evt.risk] = (byRisk[evt.risk] || 0) + 1;
    apiCounts[evt.api] = (apiCounts[evt.api] || 0) + 1;
    if (evt.origin) uniqueOrigins[evt.origin] = true;
    if (evt.frameId) uniqueFrames[evt.frameId] = true;
  }

  // Top APIs
  var topApis = Object.keys(apiCounts).map(function(api) {
    return { api: api, count: apiCounts[api] };
  }).sort(function(a, b) { return b.count - a.count; }).slice(0, 50);

  // Risk score
  var riskScore = 0;
  var criticalWeight = { 'critical': 20, 'high': 10, 'medium': 3, 'low': 1, 'info': 0 };
  for (var r in byRisk) {
    riskScore += (criticalWeight[r] || 0) * Math.min(byRisk[r], 10);
  }
  riskScore = Math.min(100, riskScore);
  var riskLevel = riskScore >= 80 ? 'DANGER' : riskScore >= 50 ? 'HIGH' : riskScore >= 20 ? 'MEDIUM' : 'LOW';

  // Threats
  var threats = [];
  var threatCategories = {
    'canvas': { type: 'Canvas Fingerprinting', severity: 'HIGH', how: 'toDataURL/getImageData pixel hash' },
    'webgl': { type: 'WebGL Fingerprinting', severity: 'HIGH', how: 'getParameter(VENDOR/RENDERER) precision format' },
    'audio': { type: 'Audio Fingerprinting', severity: 'HIGH', how: 'OfflineAudioContext Oscillator Compressor' },
    'font-detection': { type: 'Font Enumeration', severity: 'CRITICAL', how: 'measureText/getBoundingClientRect width comparison' },
    'hardware': { type: 'Hardware Fingerprinting', severity: 'HIGH', how: 'navigator.hardwareConcurrency/deviceMemory/platform' },
    'speech': { type: 'Speech Voice Fingerprint', severity: 'HIGH', how: 'speechSynthesis.getVoices OS/language detection' },
    'math-fingerprint': { type: 'Math Fingerprinting', severity: 'MEDIUM', how: 'Math.acos/sinh/expm1 precision differences' },
    'visualization': { type: 'GPU/Visualization Probing', severity: 'MEDIUM', how: 'requestAnimationFrame timing CSS.supports probing' },
    'dom-probe': { type: 'DOM Probing', severity: 'MEDIUM', how: 'MutationObserver/IntersectionObserver DOM inspection' },
    'storage': { type: 'Aggressive Storage', severity: 'MEDIUM', how: 'cookie/localStorage/IndexedDB read+write' },
    'perf-timing': { type: 'Performance Timing', severity: 'MEDIUM', how: 'performance.now/mark/measure timing analysis' },
    'css-fingerprint': { type: 'CSS Feature Detection', severity: 'MEDIUM', how: 'CSS.supports matchMedia query fingerprinting' },
    'intl-fingerprint': { type: 'Intl API Fingerprint', severity: 'MEDIUM', how: 'ListFormat/NumberFormat/Collator resolvedOptions' },
    'encoding': { type: 'TextEncoder Fingerprint', severity: 'LOW', how: 'TextEncoder/TextDecoder encoding probing' },
    'exfiltration': { type: 'Data Exfiltration', severity: 'CRITICAL', how: 'sendBeacon/WebSocket/img.src data transmission' },
    'webrtc': { type: 'WebRTC IP Leak', severity: 'CRITICAL', how: 'RTCPeerConnection ICE candidate harvesting' },
    'honeypot': { type: 'Honeypot Triggered', severity: 'CRITICAL', how: 'Trap property accessed — active probing confirmed' }
  };
  for (var tc in byCategory) {
    if (threatCategories[tc]) {
      var td = threatCategories[tc];
      threats.push({
        type: td.type, severity: td.severity,
        detail: byCategory[tc] + ' ' + tc + ' API calls detected',
        who: tc + ' processing pipeline', how: td.how
      });
    }
  }

  // Coverage matrix
  var allCats = ['canvas','webgl','audio','font-detection','fingerprint','screen','storage',
    'network','perf-timing','media-devices','dom-probe','clipboard','geolocation',
    'service-worker','hardware','exfiltration','webrtc','math-fingerprint','permissions',
    'speech','client-hints','intl-fingerprint','css-fingerprint','property-enum',
    'offscreen-canvas','honeypot','credential','system','encoding','worker',
    'webassembly','keyboard-layout','sensor-apis','visualization','device-info',
    'battery','bluetooth'];
  var coverageMatrix = allCats.map(function(cat) {
    return { category: cat, events: byCategory[cat] || 0, status: byCategory[cat] ? 'ACTIVE' : 'SILENT' };
  });
  var categoriesDetected = Object.keys(byCategory).length;
  var coveragePercent = Math.round((categoriesDetected / CATEGORIES_MONITORED) * 1000) / 10;

  // Timeline (events per second)
  var timeline = {};
  for (var tl = 0; tl < allEvents.length; tl++) {
    var sec = Math.floor((allEvents[tl].ts || 0) / 1000);
    timeline[sec] = (timeline[sec] || 0) + 1;
  }

  // Correlation analysis
  var correlation = correlationEngine.analyzeCorrelation(allEvents);

  // Coverage proof
  var bootOkEvents = allEvents.filter(function(e) { return e.api === 'BOOT_OK'; });
  var bootOkReceived = bootOkEvents.length;

  // FIX: frame coverage — use frameInfo properly
  var totalFramesDetected = frameInfo.length;
  var monitoredOrigins = {};
  for (var bo = 0; bo < bootOkEvents.length; bo++) {
    try {
      var bootData = typeof bootOkEvents[bo].value === 'string' ? JSON.parse(bootOkEvents[bo].value) : bootOkEvents[bo].value;
      if (bootData && bootData.origin) monitoredOrigins[bootData.origin] = true;
      if (bootData && bootData.url) monitoredOrigins[bootData.url] = true;
    } catch(e) {
      if (bootOkEvents[bo].origin) monitoredOrigins[bootOkEvents[bo].origin] = true;
    }
  }
  var unmonitoredFrames = [];
  for (var fi = 0; fi < frameInfo.length; fi++) {
    var fUrl = frameInfo[fi].url || '';
    var fOrigin = frameInfo[fi].origin || '';
    if (fUrl && fUrl !== 'about:blank' && fUrl.indexOf('http') === 0) {
      if (!monitoredOrigins[fUrl] && !monitoredOrigins[fOrigin]) {
        unmonitoredFrames.push(fUrl);
      }
    }
  }
  var monitoredFrames = Math.max(bootOkReceived, totalFramesDetected - unmonitoredFrames.length);
  var frameCoverage = totalFramesDetected > 0 ? Math.round((monitoredFrames / totalFramesDetected) * 100) : 100;

  var coverageVerdict = frameCoverage >= 90 ? 'FULLY_MONITORED' : frameCoverage >= 50 ? 'MONITORED' : 'BLINDSPOT_DETECTED';

  // Injection status
  var injectionStatus = {
    layer1_CDP: !!injectionFlags.layer1CDP,
    layer2_addInitScript: !!injectionFlags.layer2addInitScript,
    layer3_perTarget: !!injectionFlags.layer3perTarget,
    anyLayerActive: !!(injectionFlags.layer1CDP || injectionFlags.layer2addInitScript),
    verdict: (injectionFlags.layer1CDP || injectionFlags.layer2addInitScript) ? 'INJECTION_VERIFIED' : 'INJECTION_FAILED'
  };

  // Alerts
  var alerts = [];
  if (correlation.entropy.fingerprintLikelihood > 60) {
    alerts.push({ level: 'HIGH', type: 'HIGH_ENTROPY', message: 'High fingerprint likelihood score: ' + correlation.entropy.fingerprintLikelihood + '/100' });
  }
  if (unmonitoredFrames.length > 0) {
    alerts.push({ level: 'WARNING', type: 'BLINDSPOT', message: unmonitoredFrames.length + ' frame(s) not monitored — possible detection gap' });
  }
  if (workerEvents.length > 0) {
    alerts.push({ level: 'INFO', type: 'WORKER_ACTIVITY', message: workerEvents.length + ' events from worker contexts' });
  }

  // Dedup stats
  var dedupStats = {
    totalReceived: events.length + pushEvents.length,
    deduplicated: (events.length + pushEvents.length) - allEvents.length,
    kept: allEvents.length
  };

  // Value captures (top 100)
  var valueCaptures = allEvents.filter(function(e) { return e.value !== undefined && e.value !== ''; }).slice(0, 100).map(function(e) {
    return { ts: e.ts, api: e.api, value: e.value, category: e.cat };
  });

  // 1H5W Forensic Summary
  var originsArr = Object.keys(uniqueOrigins);
  var framesArr = Object.keys(uniqueFrames);
  var forensic1H5W = {
    WHO: 'Multiple origins: ' + originsArr.join(', '),
    WHAT: categoriesDetected + ' category fingerprinting detected: ' + Object.keys(byCategory).join(', '),
    WHEN: 'Scan duration: ' + (maxTs / 1000).toFixed(1) + 's. First event at ' + ((allEvents[0] || {}).ts || 0) / 1000 + 's. Peak activity at ' + (Object.keys(timeline).sort(function(a,b) { return timeline[b]-timeline[a]; })[0] || 0) + 's.',
    WHERE: target + ' — ' + originsArr.length + ' origins, ' + framesArr.length + ' frames',
    WHY: 'Active fingerprinting for user tracking/identification',
    HOW: 'Burst-pattern fingerprinting (' + correlation.burstWindows.length + ' bursts). Total ' + allEvents.length + ' API intercepts across ' + categoriesDetected + ' categories'
  };

  // === BUILD JSON REPORT ===
  var reportJson = {
    version: 'sentinel-v4.4.2',
    target: target,
    scanDate: new Date(scanStartTime).toISOString(),
    mode: mode,
    totalEvents: allEvents.length,
    riskScore: riskScore,
    riskLevel: riskLevel,
    timeSpanMs: maxTs, // FIX: use max(ts) not last event
    byCategory: byCategory,
    byRisk: byRisk,
    topApis: topApis,
    uniqueOrigins: originsArr,
    uniqueFrames: framesArr,
    threats: threats,
    categoriesMonitored: CATEGORIES_MONITORED,
    categoriesDetected: categoriesDetected,
    coverageMatrix: coverageMatrix,
    coveragePercent: coveragePercent,
    timeline: timeline,
    correlation: correlation,
    coverageProof: {
      totalFramesDetected: totalFramesDetected,
      monitoredFrames: monitoredFrames,
      bootOkReceived: bootOkReceived,
      coverage: frameCoverage,
      unmonitoredFrames: unmonitoredFrames,
      verdict: coverageVerdict
    },
    injectionStatus: injectionStatus,
    alerts: alerts,
    dedupStats: dedupStats,
    workerEvents: { count: workerEvents.length, events: workerEvents.slice(0, 50) },
    valueCaptures: valueCaptures,
    forensic1H5W: forensic1H5W
  };

  // === SAVE FILES ===
  var timestamp = scanStartTime;
  var baseName = 'sentinel_' + mode + '_' + timestamp;

  // Ensure output dir exists
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // JSON report
  var jsonPath = path.join(outputDir, baseName + '_report.json');
  fs.writeFileSync(jsonPath, JSON.stringify(reportJson, null, 2));

  // Context JSON
  var contextJson = {
    frames: frameInfo,
    injectionStatus: injectionStatus,
    coverageProof: reportJson.coverageProof,
    alerts: alerts,
    dedupStats: dedupStats
  };
  var ctxPath = path.join(outputDir, baseName + '_context.json');
  fs.writeFileSync(ctxPath, JSON.stringify(contextJson, null, 2));

  // HTML report
  var htmlPath = path.join(outputDir, baseName + '_report.html');
  var html = generateHTML(reportJson);
  fs.writeFileSync(htmlPath, html);

  return { jsonPath: jsonPath, htmlPath: htmlPath, ctxPath: ctxPath, report: reportJson };
}

function generateHTML(report) {
  var h = '<!DOCTYPE html><html><head><meta charset="utf-8">';
  h += '<title>Sentinel v4.4.2 Forensic Report</title>';
  h += '<style>';
  h += 'body{font-family:Consolas,monospace;background:#0d1117;color:#c9d1d9;margin:20px;line-height:1.6}';
  h += '.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}';
  h += '.danger{border-color:#f85149}.high{border-color:#d29922}.medium{border-color:#58a6ff}';
  h += 'h1{color:#58a6ff;border-bottom:2px solid #58a6ff;padding-bottom:8px}';
  h += 'h2{color:#79c0ff;margin-top:24px}';
  h += 'table{width:100%;border-collapse:collapse;margin:12px 0}';
  h += 'th,td{border:1px solid #30363d;padding:8px;text-align:left}';
  h += 'th{background:#21262d;color:#58a6ff}';
  h += '.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;margin:2px}';
  h += '.badge-danger{background:#f8514933;color:#f85149}';
  h += '.badge-high{background:#d2992233;color:#d29922}';
  h += '.badge-medium{background:#58a6ff33;color:#58a6ff}';
  h += '.badge-low{background:#3fb95033;color:#3fb950}';
  h += '.kpi{display:inline-block;text-align:center;padding:16px;margin:8px;min-width:120px;background:#21262d;border-radius:8px}';
  h += '.kpi-value{font-size:28px;font-weight:bold;color:#58a6ff}';
  h += '.kpi-label{font-size:12px;color:#8b949e;margin-top:4px}';
  h += '.active{color:#3fb950}.silent{color:#8b949e}';
  h += '</style></head><body>';

  h += '<h1>🛡️ SENTINEL v4.4.2 — FORENSIC REPORT</h1>';

  // 1H5W Box
  h += '<div class="card ' + (report.riskScore >= 80 ? 'danger' : 'medium') + '">';
  h += '<h2>🔍 1H5W Forensic Summary</h2>';
  h += '<table>';
  var dims = ['WHO','WHAT','WHEN','WHERE','WHY','HOW'];
  for (var d = 0; d < dims.length; d++) {
    h += '<tr><th>' + dims[d] + '</th><td>' + (report.forensic1H5W[dims[d]] || 'N/A') + '</td></tr>';
  }
  h += '</table></div>';

  // KPI Cards
  h += '<div style="text-align:center">';
  var kpis = [
    { label: 'Risk Score', value: report.riskScore + '/100', color: report.riskScore >= 80 ? '#f85149' : '#d29922' },
    { label: 'Events', value: report.totalEvents },
    { label: 'Categories', value: report.categoriesDetected + '/' + report.categoriesMonitored },
    { label: 'Threats', value: report.threats.length },
    { label: 'Bursts', value: report.correlation.burstWindows.length },
    { label: 'Duration', value: (report.timeSpanMs / 1000).toFixed(1) + 's' },
    { label: 'Coverage', value: report.coverageProof.coverage + '%' },
    { label: 'Exfil Alerts', value: report.correlation.exfilAlerts.length }
  ];
  for (var k = 0; k < kpis.length; k++) {
    h += '<div class="kpi"><div class="kpi-value" style="color:' + (kpis[k].color || '#58a6ff') + '">' + kpis[k].value + '</div><div class="kpi-label">' + kpis[k].label + '</div></div>';
  }
  h += '</div>';

  // Injection Status
  h += '<div class="card"><h2>💉 Injection Status</h2>';
  h += '<p>Layer 1 (CDP): ' + (report.injectionStatus.layer1_CDP ? '✅' : '❌') + '</p>';
  h += '<p>Layer 2 (addInitScript): ' + (report.injectionStatus.layer2_addInitScript ? '✅' : '❌') + '</p>';
  h += '<p>Layer 3 (per-target): ' + (report.injectionStatus.layer3_perTarget ? '✅' : '❌') + '</p>';
  h += '<p>Verdict: <strong>' + report.injectionStatus.verdict + '</strong></p></div>';

  // Threats table
  h += '<div class="card"><h2>⚠️ Threats Detected (' + report.threats.length + ')</h2>';
  h += '<table><tr><th>Type</th><th>Severity</th><th>Detail</th><th>WHO</th><th>HOW</th></tr>';
  for (var th = 0; th < report.threats.length; th++) {
    var thr = report.threats[th];
    var badgeClass = thr.severity === 'CRITICAL' ? 'badge-danger' : thr.severity === 'HIGH' ? 'badge-high' : 'badge-medium';
    h += '<tr><td>' + thr.type + '</td><td><span class="badge ' + badgeClass + '">' + thr.severity + '</span></td><td>' + thr.detail + '</td><td>' + thr.who + '</td><td>' + thr.how + '</td></tr>';
  }
  h += '</table></div>';

  // Coverage Matrix
  h += '<div class="card"><h2>📊 Coverage Matrix (' + report.categoriesDetected + '/' + report.categoriesMonitored + ')</h2>';
  h += '<table><tr><th>Category</th><th>Events</th><th>Status</th></tr>';
  for (var cm = 0; cm < report.coverageMatrix.length; cm++) {
    var cat = report.coverageMatrix[cm];
    h += '<tr><td>' + cat.category + '</td><td>' + cat.events + '</td>';
    h += '<td class="' + (cat.status === 'ACTIVE' ? 'active' : 'silent') + '">' + cat.status + '</td></tr>';
  }
  h += '</table></div>';

  // Alerts
  if (report.alerts.length > 0) {
    h += '<div class="card danger"><h2>🚨 Alerts</h2>';
    for (var al = 0; al < report.alerts.length; al++) {
      h += '<p><strong>[' + report.alerts[al].level + ']</strong> ' + report.alerts[al].type + ': ' + report.alerts[al].message + '</p>';
    }
    h += '</div>';
  }

  // Top APIs
  h += '<div class="card"><h2>📈 Top APIs (Top 20)</h2>';
  h += '<table><tr><th>API</th><th>Count</th></tr>';
  for (var ta = 0; ta < Math.min(20, report.topApis.length); ta++) {
    h += '<tr><td>' + report.topApis[ta].api + '</td><td>' + report.topApis[ta].count + '</td></tr>';
  }
  h += '</table></div>';

  h += '<div class="card"><p style="text-align:center;color:#8b949e">Generated by Sentinel v4.4.2 | ' + report.scanDate + '</p></div>';
  h += '</body></html>';
  return h;
}

module.exports = { generateReports };
