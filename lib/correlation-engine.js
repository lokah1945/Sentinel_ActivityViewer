/**
 * Sentinel v4.3 — Correlation Engine
 * Burst detection, library attribution, slow-probe detection,
 * cross-frame correlation, exfiltration tracking, entropy scoring
 */

var signatureDb = require('./signature-db');

function CorrelationEngine() {
  this.events = [];
  this.burstWindows = [];
  this.attributions = [];
  this.exfilAlerts = [];
  this.slowProbes = [];
  this.crossFrameCorrelations = [];
  this.entropy = { fingerprintLikelihood: 0 };
}

CorrelationEngine.prototype.ingestEvents = function(events) {
  this.events = events || [];
  this._detectBursts();
  this._attributeLibraries();
  this._detectSlowProbes();
  this._detectCrossFrame();
  this._detectExfiltration();
  this._calculateEntropy();
};

CorrelationEngine.prototype._detectBursts = function() {
  if (this.events.length < 5) return;

  var sorted = this.events.slice().sort(function(a, b) { return a.ts - b.ts; });
  var windowMs = 2000;
  var burstThreshold = 15;
  var i = 0;

  while (i < sorted.length) {
    var windowEnd = sorted[i].ts + windowMs;
    var windowEvents = [];

    for (var j = i; j < sorted.length && sorted[j].ts <= windowEnd; j++) {
      windowEvents.push(sorted[j]);
    }

    if (windowEvents.length >= burstThreshold) {
      var categories = {};
      var apis = {};
      for (var k = 0; k < windowEvents.length; k++) {
        categories[windowEvents[k].cat] = (categories[windowEvents[k].cat] || 0) + 1;
        apis[windowEvents[k].api] = (apis[windowEvents[k].api] || 0) + 1;
      }

      var fpCategories = ['canvas', 'webgl', 'audio', 'font-detection', 'fingerprint',
        'math-fingerprint', 'speech', 'client-hints', 'intl-fingerprint',
        'css-fingerprint', 'offscreen-canvas', 'webassembly', 'keyboard-layout',
        'sensor-apis', 'hardware', 'screen', 'media-devices'];

      var fpCount = 0;
      var catKeys = Object.keys(categories);
      for (var c = 0; c < catKeys.length; c++) {
        if (fpCategories.indexOf(catKeys[c]) !== -1) fpCount++;
      }

      if (fpCount >= 3) {
        this.burstWindows.push({
          startTs: windowEvents[0].ts,
          endTs: windowEvents[windowEvents.length - 1].ts,
          eventCount: windowEvents.length,
          categories: categories,
          fpCategoryCount: fpCount,
          isFingerprinting: true
        });
      }

      i = j;
    } else {
      i++;
    }
  }
};

CorrelationEngine.prototype._attributeLibraries = function() {
  this.attributions = signatureDb.matchSignature(this.events, 5000);

  for (var a = 0; a < this.attributions.length; a++) {
    var attr = this.attributions[a];
    attr.burstCorrelation = this.burstWindows.length > 0;
    attr.slowProbeCorrelation = this.slowProbes.length > 0;
  }
};

CorrelationEngine.prototype._detectSlowProbes = function() {
  var bySource = {};
  for (var i = 0; i < this.events.length; i++) {
    var e = this.events[i];
    var source = e.origin || e.frameId || 'main';
    if (!bySource[source]) bySource[source] = [];
    bySource[source].push(e);
  }

  var sourceKeys = Object.keys(bySource);
  for (var s = 0; s < sourceKeys.length; s++) {
    var source = sourceKeys[s];
    var evts = bySource[source];
    if (evts.length < 10) continue;

    evts.sort(function(a, b) { return a.ts - b.ts; });
    var duration = evts[evts.length - 1].ts - evts[0].ts;

    if (duration > 15000) {
      var avgGap = duration / (evts.length - 1);
      var categories = {};
      for (var e = 0; e < evts.length; e++) {
        categories[evts[e].cat] = true;
      }

      if (avgGap > 500 && Object.keys(categories).length >= 3) {
        this.slowProbes.push({
          source: source,
          totalEvents: evts.length,
          durationMs: duration,
          avgGapMs: Math.round(avgGap),
          categories: Object.keys(categories),
          isLikelyFingerprinting: true
        });
      }
    }
  }
};

CorrelationEngine.prototype._detectCrossFrame = function() {
  var byFrame = {};
  for (var i = 0; i < this.events.length; i++) {
    var e = this.events[i];
    var fid = e.frameId || 'main';
    if (!byFrame[fid]) byFrame[fid] = { origin: e.origin || 'unknown', categories: {} };
    byFrame[fid].categories[e.cat] = (byFrame[fid].categories[e.cat] || 0) + 1;
  }

  var frameIds = Object.keys(byFrame);
  for (var a = 0; a < frameIds.length; a++) {
    for (var b = a + 1; b < frameIds.length; b++) {
      var f1 = byFrame[frameIds[a]];
      var f2 = byFrame[frameIds[b]];
      var cats1 = Object.keys(f1.categories);
      var cats2 = Object.keys(f2.categories);
      var shared = [];

      for (var c = 0; c < cats1.length; c++) {
        if (cats2.indexOf(cats1[c]) !== -1 && cats1[c] !== 'system') {
          shared.push(cats1[c]);
        }
      }

      if (shared.length >= 3) {
        this.crossFrameCorrelations.push({
          frame1: { id: frameIds[a], origin: f1.origin },
          frame2: { id: frameIds[b], origin: f2.origin },
          sharedCategories: shared,
          isCoordinatedFingerprinting: shared.length >= 5
        });
      }
    }
  }
};

CorrelationEngine.prototype._detectExfiltration = function() {
  var exfilApis = ['Navigator.prototype.sendBeacon', 'XMLHttpRequest.prototype.send',
    'fetch', 'WebSocket', 'Image.prototype.src', 'HTMLImageElement.prototype.src',
    'EventSource'];

  for (var i = 0; i < this.events.length; i++) {
    var e = this.events[i];
    if (e.cat === 'exfiltration' || exfilApis.indexOf(e.api) !== -1) {
      this.exfilAlerts.push({
        tracker: e.origin || 'unknown',
        method: e.api,
        url: e.detail || e.value || '',
        timestamp: e.ts,
        risk: 'high'
      });
    }
  }
};

CorrelationEngine.prototype._calculateEntropy = function() {
  var fpCategories = ['canvas', 'webgl', 'audio', 'font-detection', 'fingerprint',
    'math-fingerprint', 'speech', 'client-hints', 'intl-fingerprint',
    'css-fingerprint', 'offscreen-canvas', 'webassembly', 'keyboard-layout',
    'sensor-apis', 'hardware', 'screen', 'media-devices', 'property-enum',
    'webrtc', 'credential'];

  var detected = {};
  for (var i = 0; i < this.events.length; i++) {
    detected[this.events[i].cat] = true;
  }

  var fpDetected = 0;
  for (var c = 0; c < fpCategories.length; c++) {
    if (detected[fpCategories[c]]) fpDetected++;
  }

  var catScore = Math.min(40, fpDetected * 4);
  var burstScore = Math.min(30, this.burstWindows.length * 10);
  var attrScore = this.attributions.length > 0 ? 20 : 0;
  var slowScore = this.slowProbes.length > 0 ? 10 : 0;

  this.entropy = {
    fingerprintLikelihood: Math.min(100, catScore + burstScore + attrScore + slowScore),
    fpCategoriesDetected: fpDetected,
    totalFpCategories: fpCategories.length,
    burstCount: this.burstWindows.length,
    libraryMatches: this.attributions.length
  };
};

CorrelationEngine.prototype.getReport = function() {
  return {
    burstWindows: this.burstWindows,
    attributions: this.attributions,
    exfilAlerts: this.exfilAlerts,
    slowProbes: this.slowProbes,
    crossFrameCorrelations: this.crossFrameCorrelations,
    entropy: this.entropy,
    summary: {
      fingerprintBursts: this.burstWindows.filter(function(b) { return b.isFingerprinting; }).length,
      exfilAttempts: this.exfilAlerts.length,
      honeypotTriggered: this.events.some(function(e) { return e.cat === 'honeypot'; }),
      slowProbeDetected: this.slowProbes.length > 0,
      fpv5Detected: this.attributions.some(function(a) { return a.library === 'FingerprintJS v5'; }),
      creepJSDetected: this.attributions.some(function(a) { return a.library === 'CreepJS'; }),
      crossFrameDetected: this.crossFrameCorrelations.some(function(c) { return c.isCoordinatedFingerprinting; })
    }
  };
};

module.exports = { CorrelationEngine };
