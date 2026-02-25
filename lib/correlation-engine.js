// ═══════════════════════════════════════════════════════════════
//  SENTINEL v6.0.0 — CORRELATION ENGINE
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.0.0 (2026-02-25):
//   FROM v5.0.0:
//   - KEPT: ALL C-COR-01 through C-COR-06 contracts
//   - KEPT: Burst detection, slow-probe, cross-frame, Shannon entropy
//
// LAST HISTORY LOG:
//   v5.0.0: Burst/slow-probe/cross-frame/entropy (147 lines)
//   v6.0.0: Version bump, no logic changes
//
// CONTRACT: C-COR-01 through C-COR-06
// ═══════════════════════════════════════════════════════════════

var signatureDb = require('./signature-db');

function analyzeCorrelation(events, options) {
  options = options || {};
  var result = {
    bursts: [],
    slowProbes: [],
    crossFrameCorrelations: [],
    entropy: { category: 0, api: 0, origin: 0 },
    libraryAttribution: [],
    riskScore: 0,
    riskMax: 100,
    threatCount: 0,
    threats: []
  };

  if (!events || events.length === 0) return result;

  // [C-COR-01] Burst detection: >=50 events in 1 second, >=3 categories
  var sorted = events.slice().sort(function(a, b) { return a.ts - b.ts; });
  var windowMs = 1000;
  for (var i = 0; i < sorted.length; i++) {
    var windowEnd = sorted[i].ts + windowMs;
    var windowEvents = [];
    var windowCats = {};
    for (var j = i; j < sorted.length && sorted[j].ts <= windowEnd; j++) {
      windowEvents.push(sorted[j]);
      windowCats[sorted[j].cat] = true;
    }
    var catCount = Object.keys(windowCats).length;
    if (windowEvents.length >= 50 && catCount >= 3) {
      result.bursts.push({
        startTs: sorted[i].ts,
        endTs: windowEvents[windowEvents.length - 1].ts,
        eventCount: windowEvents.length,
        categories: catCount,
        topCategories: Object.keys(windowCats).slice(0, 5)
      });
      i = j - 1; // skip past this burst
    }
  }

  // [C-COR-02] Slow-probe detection: accumulation per source script
  var sourceMap = {};
  for (var k = 0; k < events.length; k++) {
    var src = events[k].src || 'unknown';
    var srcKey = src.substring(0, 100);
    if (!sourceMap[srcKey]) sourceMap[srcKey] = { events: 0, categories: {}, firstTs: events[k].ts, lastTs: events[k].ts };
    sourceMap[srcKey].events++;
    sourceMap[srcKey].categories[events[k].cat] = true;
    sourceMap[srcKey].lastTs = Math.max(sourceMap[srcKey].lastTs, events[k].ts);
  }
  var srcEntries = Object.keys(sourceMap);
  for (var si = 0; si < srcEntries.length; si++) {
    var sm = sourceMap[srcEntries[si]];
    var duration = sm.lastTs - sm.firstTs;
    if (duration > 5000 && sm.events >= 10 && Object.keys(sm.categories).length >= 2) {
      result.slowProbes.push({
        source: srcEntries[si],
        events: sm.events,
        durationMs: duration,
        categories: Object.keys(sm.categories)
      });
    }
  }

  // [C-COR-03] Cross-frame correlation
  var frameMap = {};
  for (var fi = 0; fi < events.length; fi++) {
    var fid = events[fi].fid || 'main';
    if (!frameMap[fid]) frameMap[fid] = [];
    frameMap[fid].push(events[fi]);
  }
  var frameIds = Object.keys(frameMap);
  if (frameIds.length > 1) {
    for (var f1 = 0; f1 < frameIds.length; f1++) {
      for (var f2 = f1 + 1; f2 < frameIds.length; f2++) {
        var f1Cats = {};
        var f2Cats = {};
        frameMap[frameIds[f1]].forEach(function(e) { f1Cats[e.cat] = true; });
        frameMap[frameIds[f2]].forEach(function(e) { f2Cats[e.cat] = true; });
        var shared = Object.keys(f1Cats).filter(function(c) { return f2Cats[c]; });
        if (shared.length >= 2) {
          result.crossFrameCorrelations.push({
            frame1: frameIds[f1], frame2: frameIds[f2],
            sharedCategories: shared, count: shared.length
          });
        }
      }
    }
  }

  // [C-COR-04] Shannon entropy
  result.entropy.category = shannonEntropy(events.map(function(e) { return e.cat; }));
  result.entropy.api = shannonEntropy(events.map(function(e) { return e.api; }));

  // [C-COR-05] Library attribution
  result.libraryAttribution = signatureDb.matchSignatures(events);

  // Risk scoring
  var riskWeights = { critical: 10, high: 5, medium: 2, low: 1, info: 0 };
  var catSet = {};
  var threats = [];
  for (var ri = 0; ri < events.length; ri++) {
    catSet[events[ri].cat] = true;
    var w = riskWeights[events[ri].risk] || 1;
    if (w >= 5) {
      var tKey = events[ri].cat + ':' + events[ri].api;
      if (!threats.some(function(t) { return t.key === tKey; })) {
        threats.push({
          key: tKey, category: events[ri].cat, api: events[ri].api,
          risk: events[ri].risk, detail: events[ri].detail
        });
      }
    }
  }
  var catCount = Object.keys(catSet).length;
  var rawScore = Math.min(100, Math.round((catCount / 42) * 50 + (events.length / 30) + (result.bursts.length * 5) + (threats.length * 2)));
  result.riskScore = Math.min(100, rawScore);
  result.threatCount = threats.length;
  result.threats = threats;

  return result;
}

function shannonEntropy(values) {
  var freq = {};
  for (var i = 0; i < values.length; i++) {
    freq[values[i]] = (freq[values[i]] || 0) + 1;
  }
  var total = values.length;
  var entropy = 0;
  var keys = Object.keys(freq);
  for (var j = 0; j < keys.length; j++) {
    var p = freq[keys[j]] / total;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 1000) / 1000;
}

module.exports = { analyzeCorrelation };
