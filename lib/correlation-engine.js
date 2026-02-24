// Sentinel v4.4.2 — Correlation Engine (Layer 6)
// Burst detection, slow-probe, cross-frame, attribution, entropy

function analyzeCorrelation(events, options) {
  options = options || {};
  var burstWindowMs = options.burstWindowMs || 2000;
  var burstMinEvents = options.burstMinEvents || 50;
  var burstMinCategories = options.burstMinCategories || 3;
  var slowProbeWindowMs = options.slowProbeWindowMs || 30000;
  var slowProbeMinApis = options.slowProbeMinApis || 10;

  // Sort events by timestamp
  events.sort(function(a, b) { return (a.ts || 0) - (b.ts || 0); });

  // === BURST DETECTION ===
  var burstWindows = [];
  if (events.length > 0) {
    var windowStart = 0;
    for (var i = 0; i < events.length; i++) {
      while (events[i].ts - events[windowStart].ts > burstWindowMs) windowStart++;
      var windowEvents = events.slice(windowStart, i + 1);
      if (windowEvents.length >= burstMinEvents) {
        var cats = {};
        for (var j = 0; j < windowEvents.length; j++) {
          cats[windowEvents[j].cat] = (cats[windowEvents[j].cat] || 0) + 1;
        }
        var catCount = Object.keys(cats).length;
        if (catCount >= burstMinCategories) {
          var burst = {
            startTs: windowEvents[0].ts,
            endTs: windowEvents[windowEvents.length - 1].ts,
            eventCount: windowEvents.length,
            categories: cats,
            fpCategoryCount: catCount,
            isFingerprinting: catCount >= burstMinCategories
          };
          // Avoid overlapping bursts
          if (burstWindows.length === 0 || burst.startTs > burstWindows[burstWindows.length - 1].endTs) {
            burstWindows.push(burst);
          } else {
            var last = burstWindows[burstWindows.length - 1];
            if (burst.eventCount > last.eventCount) {
              burstWindows[burstWindows.length - 1] = burst;
            }
          }
        }
      }
    }
  }

  // === SLOW PROBE DETECTION ===
  var slowProbes = [];
  var apiByOrigin = {};
  for (var s = 0; s < events.length; s++) {
    var origin = events[s].origin || events[s].frameUrl || 'unknown';
    if (!apiByOrigin[origin]) apiByOrigin[origin] = {};
    apiByOrigin[origin][events[s].api] = true;
  }
  for (var org in apiByOrigin) {
    var uniqueApis = Object.keys(apiByOrigin[org]).length;
    if (uniqueApis >= slowProbeMinApis) {
      var firstTs = Infinity, lastTs = 0;
      for (var sp = 0; sp < events.length; sp++) {
        var evtOrg = events[sp].origin || events[sp].frameUrl || 'unknown';
        if (evtOrg === org) {
          if (events[sp].ts < firstTs) firstTs = events[sp].ts;
          if (events[sp].ts > lastTs) lastTs = events[sp].ts;
        }
      }
      var duration = lastTs - firstTs;
      if (duration > slowProbeWindowMs * 0.5) {
        slowProbes.push({
          origin: org,
          uniqueApis: uniqueApis,
          durationMs: Math.round(duration),
          avgIntervalMs: Math.round(duration / uniqueApis)
        });
      }
    }
  }

  // === CROSS-FRAME CORRELATION ===
  var frameApis = {};
  for (var cf = 0; cf < events.length; cf++) {
    var fId = events[cf].frameId || 'unknown';
    if (!frameApis[fId]) frameApis[fId] = new Set();
    frameApis[fId].add(events[cf].api);
  }
  var crossFrameCorrelations = [];
  var frameIds = Object.keys(frameApis);
  for (var f1 = 0; f1 < frameIds.length; f1++) {
    for (var f2 = f1 + 1; f2 < frameIds.length; f2++) {
      var overlap = 0;
      frameApis[frameIds[f1]].forEach(function(api) {
        if (frameApis[frameIds[f2]].has(api)) overlap++;
      });
      if (overlap > 5) {
        crossFrameCorrelations.push({
          frame1: frameIds[f1],
          frame2: frameIds[f2],
          sharedApis: overlap
        });
      }
    }
  }

  // === LIBRARY ATTRIBUTION ===
  var signatures = require('./signature-db').getSignatures();
  var attributions = [];
  var detectedApis = {};
  for (var la = 0; la < events.length; la++) {
    detectedApis[events[la].api] = true;
  }
  var detectedCats = {};
  for (var lc = 0; lc < events.length; lc++) {
    detectedCats[events[lc].cat] = true;
  }
  for (var li = 0; li < signatures.length; li++) {
    var sig = signatures[li];
    var matched = 0;
    for (var pi = 0; pi < sig.patterns.length; pi++) {
      var pattern = sig.patterns[pi];
      if (pattern.type === 'api-set') {
        var apiMatches = 0;
        for (var ai = 0; ai < pattern.apis.length; ai++) {
          if (detectedApis[pattern.apis[ai]]) apiMatches++;
        }
        if (apiMatches >= (pattern.minMatch || pattern.apis.length * 0.5)) matched++;
      } else if (pattern.type === 'category-set') {
        var catMatches = 0;
        for (var cci = 0; cci < pattern.categories.length; cci++) {
          if (detectedCats[pattern.categories[cci]]) catMatches++;
        }
        if (catMatches >= (pattern.minMatch || pattern.categories.length * 0.5)) matched++;
      }
    }
    var confidence = Math.round((matched / sig.patterns.length) * 100);
    if (confidence > 30) {
      attributions.push({ library: sig.name, confidence: confidence, patternsMatched: matched, patternsTotal: sig.patterns.length });
    }
  }

  // === EXFILTRATION ALERTS ===
  var exfilAlerts = [];
  var exfilEvents = events.filter(function(e) { return e.cat === 'exfiltration' || e.cat === 'network'; });
  for (var ei = 0; ei < exfilEvents.length; ei++) {
    exfilAlerts.push({
      tracker: exfilEvents[ei].origin || 'unknown',
      method: exfilEvents[ei].api,
      url: exfilEvents[ei].value || exfilEvents[ei].detail || '',
      timestamp: exfilEvents[ei].ts,
      risk: exfilEvents[ei].risk
    });
  }

  // === SHANNON ENTROPY ===
  var catDist = {};
  for (var en = 0; en < events.length; en++) {
    catDist[events[en].cat] = (catDist[events[en].cat] || 0) + 1;
  }
  var total = events.length || 1;
  var entropy = 0;
  for (var c in catDist) {
    var p = catDist[c] / total;
    if (p > 0) entropy -= p * Math.log2(p);
  }

  // Fingerprint detection categories
  var fpCategories = ['canvas','webgl','audio','font-detection','screen','fingerprint',
    'math-fingerprint','speech','client-hints','intl-fingerprint','css-fingerprint',
    'hardware','webrtc','property-enum','offscreen-canvas','device-info',
    'keyboard-layout','sensor-apis','webassembly','credential'];
  var fpCatsDetected = 0;
  for (var fi = 0; fi < fpCategories.length; fi++) {
    if (catDist[fpCategories[fi]]) fpCatsDetected++;
  }

  var likelihood = Math.min(100, Math.round(
    (fpCatsDetected / fpCategories.length) * 60 +
    (burstWindows.length > 0 ? 20 : 0) +
    (entropy > 2.5 ? 10 : 0) +
    (attributions.length > 0 ? 10 : 0)
  ));

  return {
    burstWindows: burstWindows,
    attributions: attributions,
    exfilAlerts: exfilAlerts,
    slowProbes: slowProbes,
    crossFrameCorrelations: crossFrameCorrelations,
    entropy: {
      fingerprintLikelihood: likelihood,
      fpCategoriesDetected: fpCatsDetected,
      totalFpCategories: fpCategories.length,
      burstCount: burstWindows.length,
      libraryMatches: attributions.length,
      shannonEntropy: Math.round(entropy * 100) / 100
    },
    summary: {
      fingerprintBursts: burstWindows.length,
      exfilAttempts: exfilAlerts.length,
      honeypotTriggered: events.some(function(e) { return e.cat === 'honeypot'; }),
      slowProbeDetected: slowProbes.length > 0,
      fpv5Detected: attributions.some(function(a) { return a.library.indexOf('FingerprintJS') >= 0; }),
      creepJSDetected: attributions.some(function(a) { return a.library.indexOf('CreepJS') >= 0; }),
      crossFrameDetected: crossFrameCorrelations.length > 0
    }
  };
}

module.exports = { analyzeCorrelation };
