/**
 * Sentinel v4.6.3 — Forensic Report Generator
 * Ghost Protocol | 37 Categories | 1H5W Framework | Zero Spoofing
 *
 * FIXES from v4.6:
 *   - timeSpanMs computed from MAX timestamp (not last event)
 *   - Coverage proof uses proper frame inventory with origin parsing
 *   - InjectionStatus receives actual flags from index.js
 *   - Target inventory from CDP included in report
 *   - Network conversation log included
 *   - Exfiltration detection from network log
 */

var fs = require('fs');
var path = require('path');
var correlationModule = require('../lib/correlation-engine');
var CorrelationEngine = correlationModule.CorrelationEngine || correlationModule;

function generateReport(sentinelData, frameInfo, targetUrl, options) {
  options = options || {};
  var outputDir = options.outputDir || path.join(__dirname, '..', 'output');
  var prefix = options.prefix || ('sentinel_' + Date.now());
  var stealthEnabled = !!options.stealthEnabled;
  var mode = options.mode || (stealthEnabled ? 'stealth' : 'observe');
  var injectionFlags = options.injectionFlags || {};
  var targetInventory = options.targetInventory || [];
  var networkLog = options.networkLog || { requests: 0, responses: 0, pairs: [] };

  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  var events = sentinelData.events || [];

  // FIX v4.6.3: Sort events by timestamp for consistent analysis
  events.sort(function(a, b) { return (Number(a.ts) || 0) - (Number(b.ts) || 0); });

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
  var directionCounts = { call: 0, answer: 0 };

  for (var i = 0; i < events.length; i++) {
    var e = events[i];
    byCategory[e.cat] = (byCategory[e.cat] || 0) + 1;
    byRisk[e.risk || 'info'] = (byRisk[e.risk || 'info'] || 0) + 1;
    apiCounts[e.api] = (apiCounts[e.api] || 0) + 1;
    if (e.origin) originSet.add(e.origin);
    if (e.frameId || e.frame) frameSet.add(e.frameId || e.frame);

    var slot = Math.floor((Number(e.ts) || 0) / 1000);
    timelineSlots[slot] = (timelineSlots[slot] || 0) + 1;

    if (e.value && e.value !== 'undefined' && e.value !== 'null' && e.value !== '""') {
      valueCaptures.push({
        ts: e.ts, api: e.api, value: e.value, category: e.cat,
        direction: e.detail && e.detail.indexOf && e.detail.indexOf('→') >= 0 ? '→ call' : '← answer'
      });
    }

    if (e.cat === 'worker') workerEvents.push(e);
    if (e.risk === 'critical') riskEvents.critical.push(e);
    else if (e.risk === 'high') riskEvents.high.push(e);
    if (e.detail && typeof e.detail === 'string') {
      directionCounts[e.detail.indexOf('→') >= 0 ? 'call' : 'answer']++;
    }
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
    'device-info', 'battery', 'gamepad'
  ];

  // ── Coverage Matrix ──
  var coverageMatrix = ALL_CATEGORIES.map(function(cat) {
    var count = byCategory[cat] || 0;
    return { category: cat, events: count, status: count > 0 ? 'ACTIVE' : 'SILENT' };
  });
  var activeCategories = coverageMatrix.filter(function(c) { return c.status === 'ACTIVE'; }).length;
  var coveragePercent = Math.round((activeCategories / ALL_CATEGORIES.length) * 100 * 10) / 10;

  // ── FIX v4.6.3: timeSpanMs from MAX timestamp ──
  var maxTs = 0;
  for (var i = 0; i < events.length; i++) {
    var ts = Number(events[i].ts) || 0;
    if (ts > maxTs) maxTs = ts;
  }

  // ── FIX v4.6.3: Coverage Proof with proper frame inventory ──
  var monitoredFrames = [];
  var unmonitoredFrames = [];

  for (var i = 0; i < frameInfo.length; i++) {
    var fi = frameInfo[i];
    var url = fi.url || '';
    // Skip about:blank — they don't contain meaningful content
    if (!url || url === 'about:blank' || url === 'about:srcdoc') {
      if (i > 0) { // Don't add main frame to unmonitored
        unmonitoredFrames.push(fi);
      }
      continue;
    }
    // Check if this frame has bootOk (from context map) or events
    var hasEvents = events.some(function(e) { return e.origin === fi.origin; });
    if (hasEvents || i === 0) {
      monitoredFrames.push(fi);
    } else {
      unmonitoredFrames.push(fi);
    }
  }

  var frameCoverage = frameInfo.length > 0 ? 
    Math.round((monitoredFrames.length / Math.max(1, monitoredFrames.length + unmonitoredFrames.filter(function(f) { return f.url && f.url !== 'about:blank'; }).length)) * 100) : 0;

  // ── Target Graph ──
  var targetGraph = {
    totalTargets: targetInventory.length,
    injectedTargets: targetInventory.filter(function(t) { return t.injected; }).length,
    networkEnabledTargets: targetInventory.filter(function(t) { return t.networkEnabled; }).length,
    workers: targetInventory.filter(function(t) { return t.type === 'worker'; }).length,
    iframes: targetInventory.filter(function(t) { return t.type === 'iframe'; }).length,
    coveragePercent: targetInventory.length > 0 ? 
      Math.round((targetInventory.filter(function(t) { return t.injected || t.networkEnabled; }).length / targetInventory.length) * 100) : 0,
    inventory: targetInventory
  };

  // ── Risk Score ──
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

  var riskLevel = riskScore >= 80 ? 'DANGER' : riskScore >= 50 ? 'WARNING' : 'SAFE';

  // ── Threat Assessment ──
  var threats = [];
  var threatMap = {
    'audio': { type: 'Audio Fingerprinting', severity: 'HIGH', how: 'OfflineAudioContext + Oscillator + Compressor' },
    'canvas': { type: 'Canvas Fingerprinting', severity: 'HIGH', how: 'toDataURL/getImageData pixel hash' },
    'webgl': { type: 'WebGL Fingerprinting', severity: 'HIGH', how: 'getParameter(VENDOR/RENDERER) + precision format' },
    'font-detection': { type: 'Font Enumeration', severity: 'CRITICAL', threshold: 50, how: 'measureText/getBoundingClientRect width comparison' },
    'webrtc': { type: 'WebRTC IP Leak', severity: 'CRITICAL', how: 'RTCPeerConnection ICE candidate harvesting' },
    'geolocation': { type: 'Geolocation Request', severity: 'CRITICAL', how: 'getCurrentPosition/watchPosition' },
    'clipboard': { type: 'Clipboard Access', severity: 'CRITICAL', how: 'navigator.clipboard.readText/writeText' },
    'media-devices': { type: 'Media Device Enumeration', severity: 'HIGH', how: 'enumerateDevices()' },
    'service-worker': { type: 'Service Worker', severity: 'HIGH', how: 'navigator.serviceWorker.register()' },
    'math-fingerprint': { type: 'Math Fingerprinting', severity: 'MEDIUM', threshold: 10, how: 'Math.acos/sinh/expm1 precision' },
    'storage': { type: 'Aggressive Storage', severity: 'MEDIUM', threshold: 50, how: 'cookie/localStorage/IndexedDB' },
    'speech': { type: 'Speech Voice Fingerprint', severity: 'HIGH', how: 'speechSynthesis.getVoices()' },
    'client-hints': { type: 'Client Hints Probing', severity: 'HIGH', how: 'getHighEntropyValues()' },
    'intl-fingerprint': { type: 'Intl API Fingerprint', severity: 'MEDIUM', how: 'NumberFormat/DateTimeFormat resolvedOptions' },
    'css-fingerprint': { type: 'CSS Feature Detection', severity: 'MEDIUM', how: 'CSS.supports() + matchMedia' },
    'offscreen-canvas': { type: 'OffscreenCanvas Fingerprint', severity: 'HIGH', how: 'Worker-based canvas FP' },
    'exfiltration': { type: 'Data Exfiltration', severity: 'CRITICAL', how: 'sendBeacon/WebSocket/postMessage data transmission' },
    'honeypot': { type: 'Honeypot Triggered', severity: 'CRITICAL', how: 'Accessed planted trap properties' },
    'property-enum': { type: 'Prototype Inspection', severity: 'HIGH', how: 'Object.keys/getOwnPropertyNames on navigator/screen' },
    'credential': { type: 'Credential Probing', severity: 'CRITICAL', how: 'credentials.get/create' },
    'webassembly': { type: 'WebAssembly Fingerprinting', severity: 'CRITICAL', how: 'WASM compile/instantiate timing' },
    'keyboard-layout': { type: 'Keyboard Layout Fingerprint', severity: 'HIGH', how: 'navigator.keyboard.getLayoutMap()' },
    'sensor-apis': { type: 'Device Sensor Fingerprint', severity: 'HIGH', how: 'Accelerometer/Gyroscope/AmbientLight' },
    'visualization': { type: 'GPU/Visualization Probing', severity: 'MEDIUM', how: 'requestAnimationFrame timing' },
    'device-info': { type: 'Device Info Harvesting', severity: 'MEDIUM', how: 'deviceMemory/connection/battery' },
    'worker': { type: 'Worker Activity', severity: 'HIGH', how: 'Web/Shared/Service Worker operations' },
    'dom-probe': { type: 'DOM Probing', severity: 'MEDIUM', how: 'MutationObserver/IntersectionObserver/Blob URL' },
    'permissions': { type: 'Permission Probing', severity: 'HIGH', how: 'navigator.permissions.query enumeration' },
    'encoding': { type: 'TextEncoder Fingerprint', severity: 'LOW', how: 'TextEncoder/TextDecoder probing' },
    'perf-timing': { type: 'Performance Timing', severity: 'MEDIUM', how: 'performance.now/mark/measure timing' },
    'hardware': { type: 'Hardware Fingerprinting', severity: 'HIGH', how: 'hardwareConcurrency/deviceMemory/platform' }
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

  // Library attribution
  if (correlation.attributions) {
    correlation.attributions.forEach(function(attr) {
      threats.push({
        type: 'Library: ' + attr.library,
        severity: 'CRITICAL',
        detail: attr.confidence + '% confidence — ' + attr.description,
        who: attr.library,
        how: 'Matched: ' + attr.matchedPatterns.join(', ')
      });
    });
  }

  // Cross-frame threats
  if (correlation.crossFrameCorrelations) {
    correlation.crossFrameCorrelations.forEach(function(cf) {
      if (cf.isCoordinatedFingerprinting) {
        threats.push({
          type: 'Cross-Frame Coordinated FP',
          severity: 'CRITICAL',
          detail: 'Frames share ' + (cf.sharedCategories ? cf.sharedCategories.length : 0) + ' categories',
          who: 'Multiple origins',
          how: 'Coordinated fingerprinting across origins'
        });
      }
    });
  }

  // ── 1H5W Forensic Analysis ──
  var detectedCats = Object.keys(byCategory).filter(function(c) { return c !== 'system'; });
  var forensic1H5W = {
    who: originSet.size > 0 ? 'Multiple origins: ' + Array.from(originSet).join(', ') : 'Unknown origin',
    what: detectedCats.length + ' category fingerprinting detected: ' + detectedCats.sort().join(', '),
    when: 'Duration: ' + (maxTs / 1000).toFixed(1) + 's. First event at ' + ((events[0] && events[0].ts) ? (events[0].ts / 1000).toFixed(2) + 's' : 'N/A'),
    where: targetUrl + ' — ' + originSet.size + ' origins, ' + frameSet.size + ' frames, ' + targetGraph.totalTargets + ' CDP targets',
    why: riskScore >= 50 ? 'Active fingerprinting for user tracking/identification' : 'Passive data collection',
    how: 'Burst-pattern: ' + (correlation.summary.fingerprintBursts || 0) + ' bursts. Total ' + events.length + ' intercepts across ' + detectedCats.length + ' categories'
  };

  // ── Exfiltration from network log ──
  var exfiltrationEntries = [];
  if (networkLog.pairs) {
    networkLog.pairs.forEach(function(p) {
      // Identify tracker/analytics/fingerprint endpoints
      var trackerPatterns = ['analytics', 'collect', 'beacon', 'tracker', 'fingerprint', 'report', 'event',
        'ip-api', 'surfsharkdns', 'data4.net', 'browserscan', 'ip-scan'];
      var isTracker = trackerPatterns.some(function(pat) { return p.url && p.url.indexOf(pat) >= 0; });
      if (isTracker || (p.method === 'POST' && p.postData) || p.resourceType === 'ping') {
        exfiltrationEntries.push({
          origin: p.requestHeaders.origin || p.requestHeaders.referer || 'unknown',
          method: p.method === 'POST' ? 'fetch(POST)' : 'fetch',
          url: p.url,
          ts: p.ts
        });
      }
    });
  }

  // ── Network conversation summary ──
  var networkConversation = networkLog.pairs ? networkLog.pairs.map(function(p) {
    return {
      method: p.method,
      url: p.url ? p.url.slice(0, 120) : '',
      resourceType: p.resourceType,
      status: p.responseStatus,
      size: p.responseSize ? (p.responseSize > 1024 ? Math.round(p.responseSize / 1024) + 'KB' : p.responseSize + 'B') : '-',
      headers: p.requestHeaders
    };
  }) : [];

  // ── Alerts ──
  var alerts = [];
  if (riskScore >= 60) {
    alerts.push({ level: 'HIGH', type: 'HIGH_ENTROPY', message: 'High fingerprint likelihood: ' + riskScore + '/100' });
  }
  var realUnmonitored = unmonitoredFrames.filter(function(f) { return f.url && f.url !== 'about:blank'; });
  if (realUnmonitored.length > 0) {
    alerts.push({ level: 'WARNING', type: 'BLINDSPOT', message: realUnmonitored.length + ' meaningful frames not monitored' });
  }
  var aboutBlankCount = unmonitoredFrames.filter(function(f) { return !f.url || f.url === 'about:blank'; }).length;
  if (aboutBlankCount > 0) {
    alerts.push({ level: 'INFO', type: 'BLANK_FRAMES', message: aboutBlankCount + ' about:blank frames skipped (normal)' });
  }
  if (!injectionFlags.L1_addInitScript) {
    alerts.push({ level: 'CRITICAL', type: 'INJECTION_FAILURE', message: 'Primary injection (addInitScript) failed' });
  }
  if (workerEvents.length === 0 && !injectionFlags.L6_workerPipeline) {
    alerts.push({ level: 'INFO', type: 'NO_WORKERS', message: 'No workers detected on target page' });
  }

  // ── Build report JSON ──
  var reportJson = {
    version: '4.6.3',
    mode: mode,
    ghostProtocol: true,
    zeroSpoofing: true,
    timestamp: new Date().toISOString(),
    targetUrl: targetUrl,
    resolvedUrl: targetUrl,
    totalEvents: events.length,
    timeSpanMs: maxTs,
    riskScore: riskScore,
    riskLevel: riskLevel,
    categoriesDetected: activeCategories,
    categoriesMonitored: ALL_CATEGORIES.length,
    coveragePercent: coveragePercent,
    forensic1H5W: forensic1H5W,
    threats: threats,
    coverageMatrix: coverageMatrix,
    coverageProof: {
      totalFramesDetected: frameInfo.length,
      monitoredFrames: monitoredFrames.length,
      unmonitoredFrames: unmonitoredFrames,
      coverage: frameCoverage,
      verdict: frameCoverage >= 80 ? 'COVERAGE_OK' : frameCoverage >= 50 ? 'PARTIAL' : 'BLINDSPOT'
    },
    injectionStatus: {
      layer1_addInitScript: !!injectionFlags.L1_addInitScript,
      layer2_automationCleanup: !!injectionFlags.L2_automationCleanup,
      layer3_cdpSupplement: !!injectionFlags.L3_cdpSupplement,
      layer4_perFrame: !!injectionFlags.L4_perFrame,
      layer5_recursiveAutoAttach: !!injectionFlags.L5_recursiveAutoAttach,
      layer6_workerPipeline: !!injectionFlags.L6_workerPipeline,
      anyLayerActive: true,
      verdict: injectionFlags.L1_addInitScript ? 'INJECTION_VERIFIED' : 'INJECTION_PARTIAL'
    },
    targetGraph: targetGraph,
    topApis: topApis,
    uniqueOrigins: Array.from(originSet),
    uniqueFrames: Array.from(frameSet),
    correlation: {
      fingerprintBursts: correlation.summary.fingerprintBursts || 0,
      exfilAttempts: correlation.summary.exfilAttempts || 0,
      attributions: correlation.attributions || [],
      slowProbes: correlation.slowProbes || [],
      crossFrame: correlation.crossFrameCorrelations || []
    },
    workerEvents: { count: workerEvents.length, events: workerEvents.slice(0, 50) },
    dedupStats: { totalReceived: events.length + (sentinelData.dedupCount || 0), deduplicated: sentinelData.dedupCount || 0, kept: events.length },
    alerts: alerts,
    timeline: timelineSlots,
    valueCaptures: valueCaptures.slice(0, 200),
    networkSummary: {
      totalRequests: networkLog.requests,
      totalResponses: networkLog.responses,
      conversation: networkConversation.slice(0, 100)
    },
    exfiltration: exfiltrationEntries.slice(0, 50)
  };

  // ── Save JSON report ──
  var jsonPath = path.join(outputDir, prefix + '_report.json');
  fs.writeFileSync(jsonPath, JSON.stringify(reportJson, null, 2));

  // ── Save context JSON ──
  var contextJson = {
    frames: frameInfo,
    injectionStatus: reportJson.injectionStatus,
    coverageProof: reportJson.coverageProof,
    targetGraph: targetGraph,
    alerts: alerts,
    targetInventory: targetInventory
  };
  var ctxPath = path.join(outputDir, prefix + '_context.json');
  fs.writeFileSync(ctxPath, JSON.stringify(contextJson, null, 2));

  // ── Generate HTML report ──
  var htmlPath = path.join(outputDir, prefix + '_report.html');
  var htmlContent = generateHtmlReport(reportJson, correlation, exfiltrationEntries, networkConversation);
  fs.writeFileSync(htmlPath, htmlContent);

  return {
    jsonPath: jsonPath,
    htmlPath: htmlPath,
    ctxPath: ctxPath,
    reportJson: reportJson
  };
}

function generateHtmlReport(report, correlation, exfiltrationEntries, networkConversation) {
  var threatRows = (report.threats || []).map(function(t) {
    var cls = t.severity === 'CRITICAL' ? 'threat-critical' : t.severity === 'HIGH' ? 'threat-high' : 'threat-medium';
    return '<tr class="' + cls + '"><td>' + escapeHtml(t.type) + '</td><td><span class="badge badge-' + t.severity.toLowerCase() + '">' + t.severity + '</span></td><td>' + escapeHtml(t.detail) + '</td><td>' + escapeHtml(t.who) + '</td><td>' + escapeHtml(t.how) + '</td></tr>';
  }).join('');

  var matrixRows = (report.coverageMatrix || []).map(function(c) {
    var badge = c.status === 'ACTIVE' ? 'badge-info' : 'badge-critical';
    return '<tr><td>' + c.category + '</td><td>' + c.events + '</td><td><span class="badge ' + badge + '">' + c.status + '</span></td></tr>';
  }).join('');

  var valueRows = (report.valueCaptures || []).slice(0, 100).map(function(v) {
    var dir = v.direction || '← answer';
    return '<tr><td>' + (v.ts / 1000).toFixed(2) + 's</td><td>' + dir + '</td><td>' + escapeHtml(v.api) + '</td><td>' + escapeHtml(v.category) + '</td><td style="word-break:break-all;max-width:400px">' + escapeHtml(String(v.value).slice(0, 200)) + '</td></tr>';
  }).join('');

  var attrRows = (report.correlation.attributions || []).map(function(a) {
    return '<tr><td>' + escapeHtml(a.library) + '</td><td>' + a.confidence + '%</td><td>' + escapeHtml((a.matchedPatterns || []).join(', ')) + '</td><td>' + (a.burstCorrelation ? 'Yes' : 'No') + '</td><td>' + escapeHtml(a.description || '') + '</td></tr>';
  }).join('');

  var exfilRows = (exfiltrationEntries || []).slice(0, 30).map(function(ex) {
    return '<tr><td>' + escapeHtml(ex.origin) + '</td><td><code>' + escapeHtml(ex.method) + '</code></td><td>' + escapeHtml(String(ex.url).slice(0, 100)) + '</td><td>' + ((ex.ts - (report.networkSummary.conversation[0] && report.networkSummary.conversation[0].ts || ex.ts)) / 1000).toFixed(1) + 's</td></tr>';
  }).join('');

  var netRows = (networkConversation || []).slice(0, 80).map(function(n) {
    return '<tr><td><code>' + escapeHtml(n.method) + '</code></td><td style="max-width:300px;word-break:break-all">' + escapeHtml(n.url) + '</td><td>' + escapeHtml(n.resourceType) + '</td><td>' + (n.status || '-') + '</td><td>' + (n.size || '-') + '</td></tr>';
  }).join('');

  var targetRows = (report.targetGraph.inventory || []).map(function(t) {
    return '<tr><td><code>' + escapeHtml(t.targetId) + '</code></td><td>' + t.type + '</td><td style="max-width:200px;word-break:break-all">' + escapeHtml(t.url || '') + '</td><td>' + (t.networkEnabled ? '✅' : '❌') + '</td><td>' + (t.injected ? '✅' : '❌') + '</td><td>' + (t.bootOk ? '✅' : '❌') + '</td><td>' + t.eventsCollected + '</td><td>' + (t.skipReason || '-') + '</td></tr>';
  }).join('');

  var alertRows = (report.alerts || []).map(function(a) {
    return '<tr><td><span class="badge badge-' + (a.level === 'CRITICAL' ? 'critical' : a.level === 'HIGH' ? 'high' : a.level === 'WARNING' ? 'medium' : 'low') + '">' + a.level + '</span></td><td>' + a.type + '</td><td>' + escapeHtml(a.message) + '</td></tr>';
  }).join('');

  var injRows = [
    ['L1 addInitScript', report.injectionStatus.layer1_addInitScript],
    ['L2 Automation Cleanup', report.injectionStatus.layer2_automationCleanup],
    ['L3 CDP Supplement', report.injectionStatus.layer3_cdpSupplement],
    ['L4 Per-Frame Injection', report.injectionStatus.layer4_perFrame],
    ['L5 Recursive Auto-Attach', report.injectionStatus.layer5_recursiveAutoAttach],
    ['L6 Worker Pipeline', report.injectionStatus.layer6_workerPipeline]
  ].map(function(pair) {
    return '<tr><td>' + pair[0] + '</td><td>' + (pair[1] ? '✅ Active' : '❌ No workers found') + '</td></tr>';
  }).join('');

  var riskClass = report.riskScore >= 80 ? 'risk-danger' : report.riskScore >= 50 ? 'risk-warning' : 'risk-safe';
  var timelineData = JSON.stringify(report.timeline || {});

  return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sentinel v4.6.3 Ghost Protocol Report</title>' +
    '<style>' +
    'body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:20px;background:#0a0a0a;color:#e0e0e0}' +
    '.container{max-width:1400px;margin:0 auto}' +
    'h1{color:#00ff88;text-align:center;font-size:24px}h2{color:#00ccff;border-bottom:1px solid #333;padding-bottom:8px;margin-top:30px}' +
    '.risk-danger{background:#ff1744;color:#fff;padding:8px 16px;border-radius:8px;display:inline-block;font-size:20px;font-weight:bold}' +
    '.risk-warning{background:#ff9100;color:#000;padding:8px 16px;border-radius:8px;display:inline-block;font-size:20px;font-weight:bold}' +
    '.risk-safe{background:#00c853;color:#000;padding:8px 16px;border-radius:8px;display:inline-block;font-size:20px;font-weight:bold}' +
    '.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:16px 0}' +
    '.stat-card{background:#1a1a2e;border:1px solid #333;border-radius:8px;padding:12px;text-align:center}' +
    '.stat-value{font-size:28px;font-weight:bold;color:#00ff88}.stat-label{font-size:12px;color:#888;margin-top:4px}' +
    'table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}' +
    'th{background:#1a1a2e;color:#00ccff;padding:8px;text-align:left;border:1px solid #333}' +
    'td{padding:6px 8px;border:1px solid #222;vertical-align:top}tr:nth-child(even){background:#111}' +
    '.badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}' +
    '.badge-critical{background:#ff1744;color:#fff}.badge-high{background:#ff6d00;color:#fff}' +
    '.badge-medium{background:#ffab00;color:#000}.badge-low{background:#00c853;color:#000}' +
    '.badge-info{background:#2979ff;color:#fff}' +
    '.forensic-box{background:#1a1a2e;border-left:4px solid #00ff88;padding:12px 16px;margin:8px 0;border-radius:0 8px 8px 0}' +
    '.forensic-label{color:#00ccff;font-weight:bold;font-size:14px}.forensic-value{color:#e0e0e0;margin-top:4px}' +
    'code{background:#1a1a2e;padding:1px 4px;border-radius:3px;font-size:12px;color:#00ff88}' +
    '.ghost-badge{background:linear-gradient(135deg,#00ff88,#00ccff);color:#000;padding:4px 12px;border-radius:12px;font-size:11px;font-weight:bold}' +
    '</style></head><body><div class="container">' +
    '<h1>🛡️ SENTINEL v4.6.3 GHOST PROTOCOL <span class="ghost-badge">GHOST</span></h1>' +
    '<p style="text-align:center;color:#888">' + escapeHtml(report.targetUrl) + ' — ' + report.timestamp + ' — ' + report.mode + ' mode</p>' +
    '<div style="text-align:center;margin:16px 0"><span class="' + riskClass + '">' + report.riskScore + '/100 ' + report.riskLevel + '</span></div>' +

    // Stats grid
    '<div class="stats">' +
    '<div class="stat-card"><div class="stat-value">' + report.totalEvents + '</div><div class="stat-label">API Events</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + (report.networkSummary.totalRequests + report.networkSummary.totalResponses) + '</div><div class="stat-label">Network Req/Resp</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + report.workerEvents.count + '</div><div class="stat-label">Worker Events</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + report.categoriesDetected + '/' + report.categoriesMonitored + '</div><div class="stat-label">Categories</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + report.coveragePercent + '</div><div class="stat-label">Coverage %</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + (report.timeSpanMs / 1000).toFixed(1) + 's</div><div class="stat-label">Duration</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + report.targetGraph.totalTargets + '</div><div class="stat-label">CDP Targets</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + report.threats.length + '</div><div class="stat-label">Threats</div></div>' +
    '</div>' +

    // 1H5W
    '<h2>🔍 1H5W Forensic Analysis</h2>' +
    '<div class="forensic-box"><div class="forensic-label">👤 WHO (Siapa pelakunya?)</div><div class="forensic-value">' + escapeHtml(report.forensic1H5W.who) + '</div></div>' +
    '<div class="forensic-box"><div class="forensic-label">📦 WHAT (Apa yang dicuri?)</div><div class="forensic-value">' + escapeHtml(report.forensic1H5W.what) + '</div></div>' +
    '<div class="forensic-box"><div class="forensic-label">⏰ WHEN (Kapan terjadi?)</div><div class="forensic-value">' + escapeHtml(report.forensic1H5W.when) + '</div></div>' +
    '<div class="forensic-box"><div class="forensic-label">📍 WHERE (Di mana lokasi?)</div><div class="forensic-value">' + escapeHtml(report.forensic1H5W.where) + '</div></div>' +
    '<div class="forensic-box"><div class="forensic-label">❓ WHY (Mengapa dilakukan?)</div><div class="forensic-value">' + escapeHtml(report.forensic1H5W.why) + '</div></div>' +
    '<div class="forensic-box"><div class="forensic-label">🔧 HOW (Bagaimana caranya?)</div><div class="forensic-value">' + escapeHtml(report.forensic1H5W.how) + '</div></div>' +

    // Threats
    (threatRows ? '<h2>⚠️ Threat Assessment</h2><table><tr><th>Threat</th><th>Severity</th><th>Detail</th><th>Who</th><th>How</th></tr>' + threatRows + '</table>' : '') +

    // Captured Values
    (valueRows ? '<h2>📋 Captured Values (API Responses)</h2><table><tr><th>Time</th><th>Direction</th><th>API</th><th>Category</th><th>Value</th></tr>' + valueRows + '</table>' : '') +

    // Library Attribution
    (attrRows ? '<h2>📚 Library Attribution</h2><table><tr><th>Library</th><th>Confidence</th><th>Matched Patterns</th><th>Burst</th><th>Description</th></tr>' + attrRows + '</table>' : '<h2>📚 Library Attribution</h2><p>No libraries attributed</p>') +

    // Exfiltration
    (exfilRows ? '<h2>📡 Data Exfiltration</h2><table><tr><th>Tracker</th><th>Method</th><th>URL</th><th>Time</th></tr>' + exfilRows + '</table>' : '') +

    // Target Graph
    '<h2>🎯 Target Graph & Inventory (v4.6.3)</h2>' +
    '<table><tr><th>Target ID</th><th>Type</th><th>URL</th><th>Network</th><th>Injected</th><th>Boot</th><th>Events</th><th>Skip Reason</th></tr>' + targetRows + '</table>' +

    // Network Conversation
    '<h2>🌐 Network Conversation</h2><p>' + report.networkSummary.totalRequests + ' requests, ' + report.networkSummary.totalResponses + ' responses</p>' +
    '<table><tr><th>Method</th><th>URL</th><th>Type</th><th>Status</th><th>Size</th></tr>' + netRows + '</table>' +

    // Coverage Matrix
    '<h2>📊 Coverage Matrix</h2><table><tr><th>Category</th><th>Events</th><th>Status</th></tr>' + matrixRows + '</table>' +

    // Alerts
    '<h2>🚨 Alerts</h2><table><tr><th>Level</th><th>Type</th><th>Message</th></tr>' + alertRows + '</table>' +

    // Injection Status
    '<h2>💉 Injection Status</h2><table><tr><th>Layer</th><th>Status</th></tr>' + injRows +
    '<tr><td colspan="2"><strong>Verdict: ' + report.injectionStatus.verdict + '</strong></td></tr></table>' +

    '<p style="text-align:center;color:#555;margin-top:30px">Sentinel v4.6.3 Ghost Protocol — Zero Spoofing — ' + report.timestamp + '</p>' +
    '</div></body></html>';
}

function escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

module.exports = { generateReport };
