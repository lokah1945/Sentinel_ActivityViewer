// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — CORRELATION ENGINE (Forensic Analysis)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - FROM v6.4: ForensicEngine analysis logic preserved
//   - REG-013: timeSpanMs uses reduce + Math.max
//   - NEW: Category extraction from dual-source events
//   - NEW: Risk scoring from combined hook + CDP
//   - NEW: Burst detection (rapid same-category events)
//   - NEW: Library detection summary from CDP
//   - NEW: hookStats for interceptor performance metrics
// ═══════════════════════════════════════════════════════════════

'use strict';

function CorrelationEngine(version) {
  this._version = version;
}

CorrelationEngine.prototype.analyze = function(events, frames, pipelineStats) {
  var categories = this._extractCategories(events);
  var timeline = this._buildTimeline(events);
  var riskScore = this._calculateRisk(events, categories);
  var bursts = this._detectBursts(events);
  var libs = this._extractLibraries(events);
  var hookStats = this._hookAnalysis(events);

  // REG-013: timeSpanMs with reduce + Math.max
  var timestamps = events.map(function(e) { return e.ts || 0; });
  var minTs = timestamps.length > 0 ? timestamps.reduce(function(a, b) { return Math.min(a, b); }, Infinity) : 0;
  var maxTs = timestamps.length > 0 ? timestamps.reduce(function(a, b) { return Math.max(a, b); }, 0) : 0;
  var timeSpanMs = maxTs - minTs;

  return {
    version: this._version,
    totalEvents: events.length,
    categories: categories,
    categoryCount: categories.length,
    timeline: timeline,
    riskScore: riskScore,
    bursts: bursts,
    libraryDetections: libs,
    hookStats: hookStats,
    timeSpanMs: timeSpanMs,
    frames: frames,
    pipelineStats: pipelineStats || {}
  };
};

CorrelationEngine.prototype._extractCategories = function(events) {
  var catMap = {};
  for (var i = 0; i < events.length; i++) {
    var cat = events[i].cat;
    if (!cat) continue;
    if (!catMap[cat]) {
      catMap[cat] = { name: cat, count: 0, firstSeen: events[i].ts, lastSeen: events[i].ts, risks: {}, sources: {} };
    }
    catMap[cat].count++;
    catMap[cat].lastSeen = events[i].ts;
    var risk = events[i].risk || 'info';
    catMap[cat].risks[risk] = (catMap[cat].risks[risk] || 0) + 1;
    var src = events[i].src || 'unknown';
    catMap[cat].sources[src] = (catMap[cat].sources[src] || 0) + 1;
  }
  var result = [];
  for (var key in catMap) {
    if (catMap.hasOwnProperty(key)) result.push(catMap[key]);
  }
  result.sort(function(a, b) { return b.count - a.count; });
  return result;
};

CorrelationEngine.prototype._buildTimeline = function(events) {
  var buckets = {};
  for (var i = 0; i < events.length; i++) {
    var bucket = Math.floor((events[i].ts || 0) / 1000);
    if (!buckets[bucket]) buckets[bucket] = { ts: bucket * 1000, count: 0, cats: {} };
    buckets[bucket].count++;
    var cat = events[i].cat || 'unknown';
    buckets[bucket].cats[cat] = (buckets[bucket].cats[cat] || 0) + 1;
  }
  var result = [];
  for (var key in buckets) {
    if (buckets.hasOwnProperty(key)) result.push(buckets[key]);
  }
  result.sort(function(a, b) { return a.ts - b.ts; });
  return result;
};

CorrelationEngine.prototype._calculateRisk = function(events, categories) {
  var score = 0;
  var riskWeights = { critical: 10, high: 5, medium: 2, low: 1, info: 0 };
  for (var i = 0; i < events.length; i++) {
    score += riskWeights[events[i].risk] || 0;
  }
  // Normalize to 0-100
  var maxPossible = events.length * 10;
  if (maxPossible === 0) return 0;
  return Math.min(100, Math.round((score / maxPossible) * 100));
};

CorrelationEngine.prototype._detectBursts = function(events) {
  var bursts = [];
  if (events.length < 5) return bursts;

  var windowSize = 1000; // 1 second window
  var threshold = 20; // 20 events per second = burst

  for (var i = 0; i < events.length; i++) {
    var windowEnd = (events[i].ts || 0) + windowSize;
    var count = 0;
    var cats = {};
    for (var j = i; j < events.length && (events[j].ts || 0) <= windowEnd; j++) {
      count++;
      var cat = events[j].cat || 'unknown';
      cats[cat] = (cats[cat] || 0) + 1;
    }
    if (count >= threshold) {
      bursts.push({
        startTs: events[i].ts,
        count: count,
        duration: windowSize,
        dominantCategory: Object.keys(cats).sort(function(a, b) { return cats[b] - cats[a]; })[0]
      });
      i = i + count - 1; // skip to end of burst
    }
  }
  return bursts;
};

CorrelationEngine.prototype._extractLibraries = function(events) {
  var libs = [];
  var seen = {};
  for (var i = 0; i < events.length; i++) {
    if (events[i].cat === 'library-detected' && !seen[events[i].api]) {
      seen[events[i].api] = true;
      libs.push({ name: events[i].api, detail: events[i].detail });
    }
  }
  return libs;
};

CorrelationEngine.prototype._hookAnalysis = function(events) {
  var hookCount = 0;
  var cdpCount = 0;
  var pageCount = 0;
  for (var i = 0; i < events.length; i++) {
    if (events[i].src === 'hook') hookCount++;
    else if (events[i].src === 'cdp') cdpCount++;
    else if (events[i].src === 'page') pageCount++;
  }
  return {
    hookEventCount: hookCount,
    cdpEventCount: cdpCount,
    pageEventCount: pageCount,
    hookRatio: events.length > 0 ? (hookCount / events.length * 100).toFixed(1) + '%' : '0%'
  };
};

module.exports = { CorrelationEngine: CorrelationEngine };
