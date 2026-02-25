/**
 * Sentinel v4.6 — Forensic Report Generator (Ghost Protocol)
 * 
 * FIXES from v4.5:
 *   - "vc is not defined" HTML bug fixed
 *   - Target inventory section (per-target attach/inject/boot proof)
 *   - Worker events section
 *   - 42 categories (5 new in v4.6)
 *   - timeSpanMs uses max(ts) not last(ts)
 *   - Coverage proof based on actual target graph data
 */

var fs = require('fs');
var path = require('path');
var correlationModule = require('../lib/correlation-engine');
var CorrelationEngine = correlationModule.CorrelationEngine || correlationModule;

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

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
    if (e.frame) frameSet.add(e.frame);

    var slot = Math.floor((Number(e.ts) || 0) / 1000);
    timelineSlots[slot] = (timelineSlots[slot] || 0) + 1;

    if (e.value && e.value !== 'undefined' && e.value !== 'null') {
      valueCaptures.push({ ts: e.ts, api: e.api, value: e.value, dir: e.dir || 'call', category: e.cat });
    }

    if (e.cat === 'worker') workerEvents.push(e);
    if (e.risk === 'critical') riskEvents.critical.push(e);
    else if (e.risk === 'high') riskEvents.high.push(e);
  }

  // Merge external worker events
  var extWorkerEvents = options.workerEvents || [];
  workerEvents = workerEvents.concat(extWorkerEvents.map(function(w) {
    return { ts: w.ts, cat: 'worker', api: w.api, detail: w.url, risk: 'high', origin: w.workerUrl || 'worker' };
  }));

  var topApis = Object.entries(apiCounts)
    .sort(function(a, b) { return b[1] - a[1]; })
    .slice(0, 40)
    .map(function(x) { return { api: x[0], count: x[1] }; });

  // ── ALL 42 CATEGORIES (v4.6) ──
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
    'math-fingerprint': { type: 'Math Fingerprinting', severity: 'MEDIUM', threshold: 10, how: 'Math.acos/sinh/expm1 precision differences' },
    'storage': { type: 'Aggressive Storage', severity: 'MEDIUM', threshold: 50, how: 'cookie/localStorage/IndexedDB' },
    'speech': { type: 'Speech Voice Fingerprint', severity: 'HIGH', how: 'speechSynthesis.getVoices()' },
    'client-hints': { type: 'Client Hints Probing', severity: 'HIGH', how: 'getHighEntropyValues(OS, CPU arch)' },
    'intl-fingerprint': { type: 'Intl API Fingerprint', severity: 'MEDIUM', how: 'NumberFormat/DateTimeFormat resolvedOptions' },
    'css-fingerprint': { type: 'CSS Feature Detection', severity: 'MEDIUM', how: 'CSS.supports() + matchMedia' },
    'offscreen-canvas': { type: 'OffscreenCanvas Fingerprint', severity: 'HIGH', how: 'Worker-based canvas fingerprinting' },
    'exfiltration': { type: 'Data Exfiltration', severity: 'CRITICAL', how: 'sendBeacon/WebSocket/postMessage data transmission' },
    'honeypot': { type: 'Honeypot Triggered', severity: 'CRITICAL', how: 'Accessed planted trap properties' },
    'property-enum': { type: 'Prototype Inspection', severity: 'HIGH', how: 'Object.keys/getOwnPropertyNames on navigator/screen' },
    'credential': { type: 'Credential Probing', severity: 'CRITICAL', how: 'credentials.get/create for WebAuthn' },
    'webassembly': { type: 'WebAssembly Fingerprinting', severity: 'CRITICAL', how: 'WASM compile/instantiate' },
    'keyboard-layout': { type: 'Keyboard Layout Fingerprint', severity: 'HIGH', how: 'navigator.keyboard.getLayoutMap()' },
    'sensor-apis': { type: 'Device Sensor Fingerprint', severity: 'HIGH', how: 'Accelerometer/Gyroscope sensor data' },
    'visualization': { type: 'GPU/Visualization Probing', severity: 'MEDIUM', how: 'requestAnimationFrame timing' },
    'device-info': { type: 'Device Info Harvesting', severity: 'MEDIUM', how: 'deviceMemory/connection API' },
    'worker': { type: 'Worker Activity', severity: 'HIGH', how: 'Web/Shared/Service Worker operations' },
    'dom-probe': { type: 'DOM Probing', severity: 'MEDIUM', how: 'MutationObserver/IntersectionObserver/Blob URL' },
    'permissions': { type: 'Permission Probing', severity: 'HIGH', how: 'navigator.permissions.query enumeration' },
    'encoding': { type: 'TextEncoder Fingerprint', severity: 'LOW', how: 'TextEncoder/TextDecoder probing' },
    'perf-timing': { type: 'Performance Timing', severity: 'MEDIUM', how: 'performance.now/mark/measure timing' },
    'hardware': { type: 'Hardware Fingerprinting', severity: 'HIGH', how: 'hardwareConcurrency/deviceMemory/SharedArrayBuffer' },
    'battery': { type: 'Battery Fingerprint', severity: 'MEDIUM', how: 'navigator.getBattery() charge level' },
    'gamepad': { type: 'Gamepad Fingerprint', severity: 'LOW', how: 'navigator.getGamepads() device detection' }
  };

  Object.keys(byCategory).forEach(function(cat) {
    var count = byCategory[cat];
    if (cat === 'system') return;
    var tm = threatMap[cat];
    if (tm) {
      if (tm.threshold && count < tm.threshold) return;
      threats.push({
        type: tm.type, severity: tm.severity,
        detail: count + ' ' + cat + ' API calls detected',
        who: cat + ' processing pipeline', how: tm.how
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
  (correlation.attributions || []).forEach(function(attr) {
    threats.push({
      type: 'Library Detected: ' + attr.library, severity: 'CRITICAL',
      detail: attr.confidence + '% confidence — ' + attr.description,
      who: attr.library,
      how: 'Matched patterns: ' + attr.matchedPatterns.join(', ')
    });
  });

  // Slow probe threats
  (correlation.slowProbes || []).forEach(function(sp) {
    if (sp.isLikelyFingerprinting) {
      threats.push({
        type: 'Slow-Probe Fingerprinting', severity: 'HIGH',
        detail: 'Source: ' + sp.source + ' — ' + sp.totalEvents + ' events over ' + (sp.durationMs / 1000).toFixed(1) + 's',
        who: sp.source, how: 'Deliberate call spacing to evade burst detection'
      });
    }
  });

  // Cross-frame threats
  (correlation.crossFrameCorrelations || []).forEach(function(cf) {
    if (cf.isCoordinatedFingerprinting) {
      threats.push({
        type: 'Cross-Frame Coordinated FP', severity: 'CRITICAL',
        detail: 'Frames sharing ' + cf.sharedCategories.length + ' categories',
        who: cf.frame1.origin + ' + ' + cf.frame2.origin,
        how: 'Distributed fingerprinting across ' + cf.sharedCategories.join(', ')
      });
    }
  });

  // ── Coverage Proof (v4.6: based on target graph, not just flags) ──
  var targetInventory = options.targetInventory || [];
  var targetSummary = options.targetSummary || {};
  var frameInfo = options.frameInfo || [];

  var coverageProof = {
    totalFramesDetected: frameInfo.length,
    monitoredFrames: frameInfo.filter(function(f) { return f.index === 0 || (f.url && f.url.startsWith('http')); }).length,
    unmonitoredFrames: frameInfo.filter(function(f) { return f.index > 0 && (!f.url || !f.url.startsWith('http')); }),
    targetGraph: {
      totalTargets: targetSummary.totalTargets || 0,
      injectedTargets: targetSummary.injectedTargets || 0,
      networkEnabledTargets: targetSummary.networkEnabledTargets || 0,
      workers: targetSummary.workers || 0,
      iframes: targetSummary.iframes || 0,
      coveragePercent: targetSummary.coveragePercent || 0,
      inventory: targetInventory
    }
  };

  // ── Injection Status ──
  var injFlags = options.injectionFlags || {};
  var injectionStatus = {
    layer1_addInitScript: !!injFlags.L1_addInitScript,
    layer2_automationCleanup: !!injFlags.L2_automationCleanup,
    layer3_cdpSupplement: !!injFlags.L3_cdpSupplement,
    layer4_perFrame: !!injFlags.L4_perFrame,
    layer5_recursiveAutoAttach: !!injFlags.L5_recursiveAutoAttach,
    layer6_workerPipeline: !!injFlags.L6_workerPipeline,
    anyLayerActive: false,
    verdict: 'INJECTION_FAILURE'
  };

  var l2Events = events.filter(function(e) { return e.api === 'BOOT_OK'; });
  if (l2Events.length > 0 || injFlags.L1_addInitScript) {
    injectionStatus.anyLayerActive = true;
    injectionStatus.verdict = 'INJECTION_VERIFIED';
  }

  // ── Alerts ──
  var alerts = [];
  if (injectionStatus.verdict === 'INJECTION_FAILURE') {
    alerts.push({ level: 'CRITICAL', type: 'INJECTION_FAILURE', message: 'No injection layer verified active' });
  }
  if (correlation.entropy && correlation.entropy.fingerprintLikelihood >= 60) {
    alerts.push({ level: 'HIGH', type: 'HIGH_ENTROPY', message: 'High fingerprint likelihood: ' + correlation.entropy.fingerprintLikelihood + '/100' });
  }
  if (correlation.summary.slowProbeDetected) {
    alerts.push({ level: 'WARNING', type: 'SLOW_PROBE', message: 'Slow-probe fingerprinting pattern detected' });
  }
  if (coverageProof.unmonitoredFrames.length > 2) {
    alerts.push({ level: 'WARNING', type: 'BLIND_SPOT', message: coverageProof.unmonitoredFrames.length + ' frame(s) not monitored' });
  }

  // ── timeSpanMs FIX: use max(ts) not last event ──
  var timeSpanMs = events.length > 0 ? events.reduce(function(m, e) { return Math.max(m, Number(e.ts) || 0); }, 0) : 0;

  // ── 1H5W Forensic Section ──
  var forensic1H5W = {
    WHO: correlation.attributions.length > 0
      ? correlation.attributions.map(function(a) { return a.library; }).join(', ')
      : (originSet.size > 1 ? 'Multiple origins: ' + Array.from(originSet).slice(0, 5).join(', ') : 'Unknown script(s) from ' + (Array.from(originSet)[0] || targetUrl)),
    WHAT: Object.keys(byCategory).length + ' category fingerprinting detected: ' + Object.keys(byCategory).sort().join(', '),
    WHEN: events.length > 0
      ? 'Duration ' + (timeSpanMs / 1000).toFixed(1) + 's — First event at ' + ((events[0].ts || 0) / 1000).toFixed(2) + 's'
      : 'No events captured',
    WHERE: targetUrl + ' | ' + originSet.size + ' origin(s) | ' + frameSet.size + ' frame(s)' +
      (workerEvents.length > 0 ? ' | ' + workerEvents.length + ' worker event(s)' : '') +
      ' | ' + (targetSummary.totalTargets || 0) + ' CDP targets',
    WHY: riskScore >= 70 ? 'Active fingerprinting for user tracking/identification' :
         riskScore >= 40 ? 'Moderate fingerprinting — analytics + tracking' :
         'Low fingerprinting activity — possibly legitimate',
    HOW: (correlation.summary.fingerprintBursts > 0 ? 'Burst-pattern (' + correlation.summary.fingerprintBursts + ' bursts). ' : '') +
         (correlation.summary.slowProbeDetected ? 'Slow-probe evasion. ' : '') +
         (correlation.summary.fpv5Detected ? 'FingerprintJS v5. ' : '') +
         (correlation.summary.creepJSDetected ? 'CreepJS. ' : '') +
         'Total ' + events.length + ' intercepts across ' + Object.keys(byCategory).length + ' categories'
  };

  // ── Build Report JSON ──
  var reportJson = {
    version: 'sentinel-v4.6',
    target: targetUrl,
    scanDate: new Date().toISOString(),
    mode: options.stealthEnabled ? 'stealth' : 'observe',
    totalEvents: events.length,
    riskScore: riskScore,
    riskLevel: riskScore >= 70 ? 'DANGER' : riskScore >= 40 ? 'WARNING' : 'LOW',
    timeSpanMs: timeSpanMs,
    byCategory: byCategory,
    byRisk: byRisk,
    topApis: topApis,
    uniqueOrigins: Array.from(originSet),
    uniqueFrames: Array.from(frameSet),
    threats: threats,
    categoriesMonitored: ALL_CATEGORIES.length,
    categoriesDetected: Object.keys(byCategory).length,
    coverageMatrix: coverageMatrix,
    coveragePercent: coveragePercent,
    timeline: timelineSlots,
    correlation: correlation,
    coverageProof: coverageProof,
    injectionStatus: injectionStatus,
    alerts: alerts,
    workerEvents: { count: workerEvents.length, events: workerEvents.slice(0, 50) },
    valueCaptures: valueCaptures.slice(0, 200),
    networkConversation: (function() {
      var nlog = options.networkLog || [];
      if (!nlog.length) return { summary: 'No network capture', requests: 0, responses: 0, log: [] };
      var requests = nlog.filter(function(n) { return n.dir === 'request'; });
      var responses = nlog.filter(function(n) { return n.dir === 'response'; });
      var pairs = [];
      for (var ri = 0; ri < requests.length; ri++) {
        var req = requests[ri];
        var resp = responses.find(function(r) { return r.url === req.url; });
        pairs.push({
          url: req.url, method: req.method, resourceType: req.resourceType,
          requestHeaders: req.headers, postData: req.postData ? req.postData.slice(0, 500) : null,
          responseStatus: resp ? resp.status : null, responseHeaders: resp ? resp.headers : null,
          responseBody: resp && resp.bodyPreview ? resp.bodyPreview.slice(0, 1000) : null,
          responseSize: resp ? resp.bodySize : null, ts: req.ts
        });
      }
      pairs.sort(function(a, b) { return (a.ts || 0) - (b.ts || 0); });
      return {
        summary: requests.length + ' requests, ' + responses.length + ' responses',
        requests: requests.length, responses: responses.length,
        totalBodyBytes: responses.reduce(function(sum, r) { return sum + (r.bodySize || 0); }, 0),
        pairs: pairs.slice(0, 200)
      };
    })(),
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
    targetInventory: targetInventory
  }, null, 2));

  // ── Generate HTML Report ──
  var htmlContent = generateHtml(reportJson, correlation);
  var htmlPath = path.join(outputDir, prefix + '_report.html');
  fs.writeFileSync(htmlPath, htmlContent);

  return { reportJson: reportJson, jsonPath: jsonPath, htmlPath: htmlPath, ctxPath: ctxPath };
}

function generateHtml(report, correlation) {
  var riskClass = report.riskScore >= 70 ? 'danger' : report.riskScore >= 40 ? 'warning' : 'safe';

  var threatRows = (report.threats || []).map(function(t) {
    var sev = (t.severity || '').toLowerCase();
    return '<tr class="threat-' + sev + '">' +
      '<td>' + escapeHtml(t.type) + '</td>' +
      '<td><span class="badge badge-' + sev + '">' + t.severity + '</span></td>' +
      '<td>' + escapeHtml(t.detail) + '</td>' +
      '<td>' + escapeHtml(t.who || '-') + '</td>' +
      '<td>' + escapeHtml(t.how || '-') + '</td></tr>';
  }).join('');

  // FIX v4.6: catRows was using 'vc' variable which belonged to valueCaptures loop
  var catRows = Object.entries(report.byCategory)
    .sort(function(a, b) { return b[1] - a[1]; })
    .map(function(entry) {
      var cat = entry[0], count = entry[1];
      var pct = report.totalEvents > 0 ? Math.round(count / report.totalEvents * 100) : 0;
      return '<tr><td>' + escapeHtml(cat) + '</td><td>' + count + '</td><td>' + pct + '%</td>' +
        '<td><div style="background:#4CAF50;height:8px;width:' + Math.min(pct, 100) + '%;border-radius:4px"></div></td></tr>';
    }).join('');

  var valueRows = (report.valueCaptures || []).slice(0, 50)
    .map(function(vc) {
      return '<tr><td>' + (vc.ts/1000).toFixed(2) + 's</td>' +
        '<td>' + (vc.dir === 'response' ? '📤 answer' : '📥 call') + '</td>' +
        '<td>' + escapeHtml(vc.api) + '</td>' +
        '<td>' + escapeHtml(vc.category) + '</td>' +
        '<td style="word-break:break-all;max-width:400px">' + escapeHtml(String(vc.value || '-').slice(0, 150)) + '</td></tr>';
    }).join('');

  var attrRows = (report.correlation && report.correlation.attributions ? report.correlation.attributions : [])
    .map(function(a) {
      return '<tr><td><strong>' + escapeHtml(a.library) + '</strong></td>' +
        '<td>' + a.confidence + '%</td>' +
        '<td>' + escapeHtml(a.matchedPatterns.join(', ')) + '</td>' +
        '<td>' + (a.burstCorrelation ? 'Yes' : 'No') + '</td>' +
        '<td>' + escapeHtml(a.description) + '</td></tr>';
    }).join('');

  var exfilRows = (report.correlation && report.correlation.exfilAlerts ? report.correlation.exfilAlerts : [])
    .map(function(e) {
      return '<tr><td>' + escapeHtml(e.tracker) + '</td>' +
        '<td><code>' + escapeHtml(e.method) + '</code></td>' +
        '<td>' + escapeHtml(String(e.url).slice(0, 80)) + '</td>' +
        '<td>' + (e.timestamp / 1000).toFixed(1) + 's</td></tr>';
    }).join('');

  var matrixRows = (report.coverageMatrix || []).map(function(c) {
    return '<tr><td>' + escapeHtml(c.category) + '</td>' +
      '<td>' + c.events + '</td>' +
      '<td><span class="badge badge-' + (c.status === 'ACTIVE' ? 'info' : 'critical') + '">' + c.status + '</span></td></tr>';
  }).join('');

  var alertRows = (report.alerts || []).map(function(a) {
    return '<tr><td><span class="badge badge-' + (a.level === 'CRITICAL' ? 'critical' : a.level === 'HIGH' ? 'high' : 'medium') + '">' + a.level + '</span></td>' +
      '<td>' + escapeHtml(a.type) + '</td>' +
      '<td>' + escapeHtml(a.message) + '</td></tr>';
  }).join('');

  // v4.6: Target Inventory rows
  var targetInvRows = '';
  if (report.coverageProof && report.coverageProof.targetGraph && report.coverageProof.targetGraph.inventory) {
    targetInvRows = report.coverageProof.targetGraph.inventory.map(function(t) {
      return '<tr>' +
        '<td><code>' + escapeHtml(t.targetId || '') + '</code></td>' +
        '<td>' + escapeHtml(t.type || '') + '</td>' +
        '<td style="max-width:200px;word-break:break-all">' + escapeHtml((t.url || '').slice(0,80)) + '</td>' +
        '<td>' + (t.networkEnabled ? '✅' : '❌') + '</td>' +
        '<td>' + (t.injected ? '✅' : '❌') + '</td>' +
        '<td>' + (t.bootOk ? '✅' : '❌') + '</td>' +
        '<td>' + (t.eventsCollected || 0) + '</td>' +
        '<td>' + escapeHtml(t.skipReason || '-') + '</td></tr>';
    }).join('');
  }

  // Network conversation preview
  var netPairRows = '';
  if (report.networkConversation && report.networkConversation.pairs) {
    netPairRows = report.networkConversation.pairs.slice(0, 50).map(function(p) {
      return '<tr>' +
        '<td><code>' + escapeHtml(p.method || 'GET') + '</code></td>' +
        '<td style="max-width:300px;word-break:break-all">' + escapeHtml((p.url || '').slice(0, 80)) + '</td>' +
        '<td>' + escapeHtml(p.resourceType || '-') + '</td>' +
        '<td>' + (p.responseStatus || '-') + '</td>' +
        '<td>' + (p.responseSize ? Math.round(p.responseSize/1024) + 'KB' : '-') + '</td></tr>';
    }).join('');
  }

  var f = report.forensic1H5W || {};

  return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sentinel v4.6 Ghost Protocol Report</title>' +
    '<style>' +
    'body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:20px;background:#0a0a0a;color:#e0e0e0}' +
    '.container{max-width:1400px;margin:0 auto}' +
    'h1{color:#00ff88;text-align:center;font-size:24px}' +
    'h2{color:#00ccff;border-bottom:1px solid #333;padding-bottom:8px;margin-top:30px}' +
    '.risk-danger{background:#ff1744;color:#fff;padding:8px 16px;border-radius:8px;display:inline-block;font-size:20px;font-weight:bold}' +
    '.risk-warning{background:#ff9100;color:#000;padding:8px 16px;border-radius:8px;display:inline-block;font-size:20px;font-weight:bold}' +
    '.risk-safe{background:#00c853;color:#000;padding:8px 16px;border-radius:8px;display:inline-block;font-size:20px;font-weight:bold}' +
    '.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:16px 0}' +
    '.stat-card{background:#1a1a2e;border:1px solid #333;border-radius:8px;padding:12px;text-align:center}' +
    '.stat-value{font-size:28px;font-weight:bold;color:#00ff88}' +
    '.stat-label{font-size:12px;color:#888;margin-top:4px}' +
    'table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}' +
    'th{background:#1a1a2e;color:#00ccff;padding:8px;text-align:left;border:1px solid #333}' +
    'td{padding:6px 8px;border:1px solid #222;vertical-align:top}' +
    'tr:nth-child(even){background:#111}' +
    '.badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}' +
    '.badge-critical{background:#ff1744;color:#fff}.badge-high{background:#ff6d00;color:#fff}' +
    '.badge-medium{background:#ffab00;color:#000}.badge-low{background:#00c853;color:#000}' +
    '.badge-info{background:#2979ff;color:#fff}' +
    '.forensic-box{background:#1a1a2e;border-left:4px solid #00ff88;padding:12px 16px;margin:8px 0;border-radius:0 8px 8px 0}' +
    '.forensic-label{color:#00ccff;font-weight:bold;font-size:14px}' +
    '.forensic-value{color:#e0e0e0;margin-top:4px}' +
    'code{background:#1a1a2e;padding:1px 4px;border-radius:3px;font-size:12px;color:#00ff88}' +
    '.ghost-badge{background:linear-gradient(135deg,#00ff88,#00ccff);color:#000;padding:4px 12px;border-radius:12px;font-size:11px;font-weight:bold}' +
    '</style></head><body><div class="container">' +
    '<h1>🛡️ SENTINEL v4.6 — GHOST PROTOCOL <span class="ghost-badge">GHOST</span></h1>' +
    '<p style="text-align:center;color:#888">' + escapeHtml(report.target) + ' | ' + report.scanDate + ' | ' + report.mode + ' mode</p>' +
    '<div style="text-align:center;margin:16px 0"><span class="risk-' + riskClass + '">' + report.riskScore + '/100 ' + report.riskLevel + '</span></div>' +
    '<div class="stats">' +
    '<div class="stat-card"><div class="stat-value">' + report.totalEvents + '</div><div class="stat-label">API Events</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + (report.networkConversation ? report.networkConversation.requests : 0) + '/' + (report.networkConversation ? report.networkConversation.responses : 0) + '</div><div class="stat-label">Network Req/Resp</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + (report.workerEvents ? report.workerEvents.count : 0) + '</div><div class="stat-label">Worker Events</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + report.categoriesDetected + '/' + report.categoriesMonitored + '</div><div class="stat-label">Categories</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + report.coveragePercent + '%</div><div class="stat-label">Coverage</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + (report.timeSpanMs / 1000).toFixed(1) + 's</div><div class="stat-label">Duration</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + (report.coverageProof && report.coverageProof.targetGraph ? report.coverageProof.targetGraph.totalTargets : 0) + '</div><div class="stat-label">CDP Targets</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + report.threats.length + '</div><div class="stat-label">Threats</div></div>' +
    '</div>' +

    '<h2>📋 1H5W Forensic Analysis</h2>' +
    '<div class="forensic-box"><div class="forensic-label">👤 WHO (Siapa pelakunya?)</div><div class="forensic-value">' + escapeHtml(f.WHO) + '</div></div>' +
    '<div class="forensic-box"><div class="forensic-label">🔍 WHAT (Apa yang dicuri?)</div><div class="forensic-value">' + escapeHtml(f.WHAT) + '</div></div>' +
    '<div class="forensic-box"><div class="forensic-label">⏰ WHEN (Kapan terjadi?)</div><div class="forensic-value">' + escapeHtml(f.WHEN) + '</div></div>' +
    '<div class="forensic-box"><div class="forensic-label">📍 WHERE (Di mana lokasi?)</div><div class="forensic-value">' + escapeHtml(f.WHERE) + '</div></div>' +
    '<div class="forensic-box"><div class="forensic-label">❓ WHY (Mengapa dilakukan?)</div><div class="forensic-value">' + escapeHtml(f.WHY) + '</div></div>' +
    '<div class="forensic-box"><div class="forensic-label">🔧 HOW (Bagaimana caranya?)</div><div class="forensic-value">' + escapeHtml(f.HOW) + '</div></div>' +

    '<h2>🚨 Threat Assessment</h2>' +
    '<table><tr><th>Threat</th><th>Severity</th><th>Detail</th><th>Who</th><th>How</th></tr>' + threatRows + '</table>' +

    '<h2>📊 Category Breakdown</h2>' +
    '<table><tr><th>Category</th><th>Events</th><th>%</th><th>Bar</th></tr>' + catRows + '</table>' +

    '<h2>🔬 Captured Values (API Responses)</h2>' +
    '<table><tr><th>Time</th><th>Direction</th><th>API</th><th>Category</th><th>Value</th></tr>' + valueRows + '</table>' +

    '<h2>🕵️ Library Attribution</h2>' +
    (attrRows ? '<table><tr><th>Library</th><th>Confidence</th><th>Patterns</th><th>Burst</th><th>Description</th></tr>' + attrRows + '</table>' : '<p>No libraries attributed</p>') +

    '<h2>📡 Data Exfiltration</h2>' +
    (exfilRows ? '<table><tr><th>Tracker</th><th>Method</th><th>URL</th><th>Time</th></tr>' + exfilRows + '</table>' : '<p>No exfiltration detected</p>') +

    '<h2>🎯 Target Graph Inventory (v4.6)</h2>' +
    (targetInvRows ? '<table><tr><th>Target ID</th><th>Type</th><th>URL</th><th>Network</th><th>Injected</th><th>Boot</th><th>Events</th><th>Skip Reason</th></tr>' + targetInvRows + '</table>' : '<p>No target inventory data</p>') +

    '<h2>🌐 Network Conversation</h2>' +
    '<p>' + (report.networkConversation ? report.networkConversation.summary : 'No data') + '</p>' +
    (netPairRows ? '<table><tr><th>Method</th><th>URL</th><th>Type</th><th>Status</th><th>Size</th></tr>' + netPairRows + '</table>' : '') +

    '<h2>🔍 Coverage Matrix</h2>' +
    '<table><tr><th>Category</th><th>Events</th><th>Status</th></tr>' + matrixRows + '</table>' +

    '<h2>⚠️ Alerts</h2>' +
    (alertRows ? '<table><tr><th>Level</th><th>Type</th><th>Message</th></tr>' + alertRows + '</table>' : '<p>No alerts</p>') +

    '<h2>💉 Injection Status</h2>' +
    '<table><tr><th>Layer</th><th>Status</th></tr>' +
    '<tr><td>L1: addInitScript</td><td>' + (report.injectionStatus.layer1_addInitScript ? '✅ Active' : '❌') + '</td></tr>' +
    '<tr><td>L2: Automation Cleanup</td><td>' + (report.injectionStatus.layer2_automationCleanup ? '✅ Active' : '❌ Skipped (observe mode)') + '</td></tr>' +
    '<tr><td>L3: CDP Supplement</td><td>' + (report.injectionStatus.layer3_cdpSupplement ? '✅ Active' : '❌') + '</td></tr>' +
    '<tr><td>L4: Per-Frame Injection</td><td>' + (report.injectionStatus.layer4_perFrame ? '✅ Active' : '⚪ No late frames') + '</td></tr>' +
    '<tr><td>L5: Recursive Auto-Attach</td><td>' + (report.injectionStatus.layer5_recursiveAutoAttach ? '✅ Active' : '❌') + '</td></tr>' +
    '<tr><td>L6: Worker Pipeline</td><td>' + (report.injectionStatus.layer6_workerPipeline ? '✅ Active' : '⚪ No workers found') + '</td></tr>' +
    '<tr><td colspan="2"><strong>Verdict: ' + report.injectionStatus.verdict + '</strong></td></tr>' +
    '</table>' +

    '<p style="text-align:center;color:#555;margin-top:30px">Sentinel v4.6 Ghost Protocol | Zero Spoofing | ' + report.scanDate + '</p>' +
    '</div></body></html>';
}

module.exports = { generateReport };
