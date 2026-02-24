/**
 * Sentinel v4.2 — Behavior Correlation Engine (Layer 6)
 * ZERO ESCAPE ARCHITECTURE
 *
 * UPGRADES from v4:
 * - Support all 37 categories in burst detection
 * - Cross-category correlation (FPv5 41-source sequence detection)
 * - Temporal slow-probe detection
 * - Worker event correlation
 * - Cross-frame event correlation
 * - Enhanced entropy scoring with 37 categories
 * - FPv5 41-source sequence matching
 * - CreepJS 40-category pattern matching
 */

const { LIBRARY_SIGNATURES, EXFIL_PATTERNS } = require('./signature-db');

class CorrelationEngine {
  constructor() {
    this.events = [];
    this.bursts = [];
    this.attributions = [];
    this.exfilAlerts = [];
    this.honeypotHits = [];
    this.entropy = {};
    this.crossCategoryCorrelations = [];
    this.slowProbes = [];
    this.workerCorrelations = [];
    this.crossFrameCorrelations = [];
  }

  ingestEvents(events) {
    this.events = events || [];
    this._detectBursts();
    this._detectSlowProbes();
    this._attributeLibraries();
    this._crossCategoryCorrelation();
    this._crossFrameCorrelation();
    this._workerCorrelation();
    this._calculateEntropy();
    this._matchExfiltration();
  }

  /* ═══ BURST DETECTION (Enhanced for 37 categories) ═══ */
  _detectBursts() {
    if (this.events.length === 0) return;
    var sorted = this.events.slice().sort(function(a, b) { return a.ts - b.ts; });
    var BURST_THRESHOLD = 50;
    var BURST_WINDOW = 1000;

    // Also detect micro-bursts (rapid fingerprinting)
    var MICRO_BURST_THRESHOLD = 15;
    var MICRO_BURST_WINDOW = 200;

    var burstStart = sorted[0].ts;
    var burstEvents = [sorted[0]];

    for (var i = 1; i < sorted.length; i++) {
      if (sorted[i].ts - burstStart <= BURST_WINDOW) {
        burstEvents.push(sorted[i]);
      } else {
        this._finalizeBurst(burstEvents, burstStart, BURST_THRESHOLD, 'standard');
        burstStart = sorted[i].ts;
        burstEvents = [sorted[i]];
      }
    }
    this._finalizeBurst(burstEvents, burstStart, BURST_THRESHOLD, 'standard');

    // Micro-burst detection pass
    burstStart = sorted[0].ts;
    burstEvents = [sorted[0]];
    for (var j = 1; j < sorted.length; j++) {
      if (sorted[j].ts - burstStart <= MICRO_BURST_WINDOW) {
        burstEvents.push(sorted[j]);
      } else {
        this._finalizeBurst(burstEvents, burstStart, MICRO_BURST_THRESHOLD, 'micro');
        burstStart = sorted[j].ts;
        burstEvents = [sorted[j]];
      }
    }
    this._finalizeBurst(burstEvents, burstStart, MICRO_BURST_THRESHOLD, 'micro');
  }

  _finalizeBurst(burstEvents, burstStart, threshold, burstType) {
    if (burstEvents.length < threshold) return;
    var cats = {};
    var origins = {};
    var frames = {};
    burstEvents.forEach(function(e) {
      cats[e.cat] = (cats[e.cat] || 0) + 1;
      origins[e.origin || 'unknown'] = (origins[e.origin || 'unknown'] || 0) + 1;
      if (e.frameId) frames[e.frameId] = (frames[e.frameId] || 0) + 1;
    });
    var catEntries = Object.entries(cats).sort(function(a, b) { return b[1] - a[1]; });
    var uniqueCats = Object.keys(cats).length;

    this.bursts.push({
      type: burstType,
      startTs: burstStart,
      endTs: burstEvents[burstEvents.length - 1].ts,
      count: burstEvents.length,
      durationMs: burstEvents[burstEvents.length - 1].ts - burstStart,
      categories: cats,
      topCategory: catEntries[0] ? catEntries[0][0] : 'unknown',
      uniqueCategories: uniqueCats,
      uniqueOrigins: Object.keys(origins).length,
      uniqueFrames: Object.keys(frames).length,
      isFingerprintBurst: uniqueCats >= 3,
      isMultiOriginBurst: Object.keys(origins).length > 1,
      isMultiFrameBurst: Object.keys(frames).length > 1,
      riskAssessment: uniqueCats >= 5 ? 'CRITICAL' : uniqueCats >= 3 ? 'HIGH' : 'MEDIUM'
    });
  }

  /* ═══ SLOW-PROBE DETECTION (NEW in v4.2) ═══ */
  _detectSlowProbes() {
    if (this.events.length < 5) return;
    // Group events by source script (via stack trace or origin)
    var bySource = {};
    this.events.forEach(function(e) {
      var source = 'unknown';
      if (e.stackTrace) {
        var lines = String(e.stackTrace).split('\n');
        for (var k = 0; k < lines.length; k++) {
          var match = lines[k].match(/https?:\/\/[^\s\)]+/);
          if (match) { source = match[0].split(':')[0] + '//' + match[0].split('//')[1].split('/')[0]; break; }
        }
      } else if (e.origin) {
        source = e.origin;
      }
      if (!bySource[source]) bySource[source] = [];
      bySource[source].push(e);
    });

    var self = this;
    Object.keys(bySource).forEach(function(source) {
      var srcEvents = bySource[source];
      if (srcEvents.length < 10) return;

      var sorted = srcEvents.slice().sort(function(a, b) { return a.ts - b.ts; });
      var totalDuration = sorted[sorted.length - 1].ts - sorted[0].ts;
      var uniqueCats = {};
      sorted.forEach(function(e) { uniqueCats[e.cat] = true; });
      var catCount = Object.keys(uniqueCats).length;

      // Slow probe: many events spread over long time with multiple categories
      if (totalDuration > 5000 && catCount >= 3 && srcEvents.length >= 10) {
        var avgInterval = totalDuration / (srcEvents.length - 1);
        if (avgInterval > 100) { // Not a burst, but deliberate spacing
          self.slowProbes.push({
            source: source,
            totalEvents: srcEvents.length,
            durationMs: totalDuration,
            avgIntervalMs: Math.round(avgInterval),
            uniqueCategories: catCount,
            categories: Object.keys(uniqueCats),
            isLikelyFingerprinting: catCount >= 5 && srcEvents.length >= 20,
            riskAssessment: catCount >= 5 ? 'HIGH' : 'MEDIUM'
          });
        }
      }
    });
  }

  /* ═══ LIBRARY ATTRIBUTION (Enhanced for FPv5 + CreepJS) ═══ */
  _attributeLibraries() {
    var apiSet = new Set(this.events.map(function(e) { return e.api; }));
    var catSet = new Set(this.events.map(function(e) { return e.cat; }));
    var urlSet = new Set();
    var self = this;

    this.events.forEach(function(e) {
      if (e.stackTrace) {
        var urls = String(e.stackTrace).match(/https?:\/\/[^\s\)\]]+/g);
        if (urls) urls.forEach(function(u) { urlSet.add(u); });
      }
    });

    for (var libId in LIBRARY_SIGNATURES) {
      var lib = LIBRARY_SIGNATURES[libId];
      var score = 0;
      var matchedPatterns = [];

      for (var p = 0; p < lib.patterns.length; p++) {
        var pattern = lib.patterns[p];
        var matched = false;

        if (pattern.type === 'api-set') {
          var matchCount = 0;
          for (var a = 0; a < pattern.apis.length; a++) {
            if (apiSet.has(pattern.apis[a])) matchCount++;
          }
          var minMatch = pattern.minMatch || Math.ceil(pattern.apis.length * 0.5);
          if (matchCount >= minMatch) {
            matched = true;
            score += pattern.weight * (matchCount / pattern.apis.length);
          }
        } else if (pattern.type === 'url') {
          var urlArr = Array.from(urlSet);
          for (var u = 0; u < urlArr.length; u++) {
            if (urlArr[u].indexOf(pattern.pattern) !== -1) {
              matched = true;
              score += pattern.weight;
              break;
            }
          }
        } else if (pattern.type === 'entropy-count') {
          if (apiSet.size >= (pattern.min || 30)) {
            matched = true;
            score += pattern.weight;
          }
        } else if (pattern.type === 'category-set') {
          var catMatchCount = 0;
          for (var c = 0; c < pattern.categories.length; c++) {
            if (catSet.has(pattern.categories[c])) catMatchCount++;
          }
          if (catMatchCount >= (pattern.minMatch || pattern.categories.length * 0.6)) {
            matched = true;
            score += pattern.weight * (catMatchCount / pattern.categories.length);
          }
        } else {
          // Legacy: simple api match
          var apiMatch = false;
          if (pattern.apis) {
            apiMatch = pattern.apis.some(function(a) { return apiSet.has(a); });
          }
          if (apiMatch) {
            matched = true;
            score += pattern.weight;
          }
        }

        if (matched) matchedPatterns.push(pattern.category || pattern.type || 'match');
      }

      if (score >= lib.minScore) {
        var totalPossible = lib.patterns.reduce(function(s, pp) { return s + pp.weight; }, 0);
        var burstMatch = self.bursts.some(function(b) {
          return b.durationMs <= (lib.burstWindow || 5000) && b.isFingerprintBurst;
        });

        self.attributions.push({
          library: lib.name,
          confidence: Math.min(100, Math.round((score / totalPossible) * 100)),
          score: Math.round(score * 100) / 100,
          matchedPatterns: matchedPatterns,
          burstCorrelation: burstMatch,
          slowProbeCorrelation: self.slowProbes.some(function(sp) { return sp.uniqueCategories >= 3; }),
          description: lib.description,
          version: lib.version || 'unknown'
        });
      }
    }
    this.attributions.sort(function(a, b) { return b.confidence - a.confidence; });
  }

  /* ═══ CROSS-CATEGORY CORRELATION (NEW in v4.2) ═══ */
  _crossCategoryCorrelation() {
    if (this.events.length < 5) return;
    // Sliding window: 10-second windows looking for multi-category activity
    var WINDOW_MS = 10000;
    var sorted = this.events.slice().sort(function(a, b) { return a.ts - b.ts; });
    if (sorted.length === 0) return;

    var windowStart = sorted[0].ts;
    var maxTs = sorted[sorted.length - 1].ts;

    while (windowStart <= maxTs) {
      var windowEnd = windowStart + WINDOW_MS;
      var windowEvents = sorted.filter(function(e) { return e.ts >= windowStart && e.ts < windowEnd; });

      if (windowEvents.length >= 10) {
        var cats = {};
        var sources = {};
        windowEvents.forEach(function(e) {
          cats[e.cat] = (cats[e.cat] || 0) + 1;
          var src = e.origin || 'unknown';
          sources[src] = (sources[src] || 0) + 1;
        });

        var catCount = Object.keys(cats).length;
        if (catCount >= 4) {
          this.crossCategoryCorrelations.push({
            windowStart: windowStart,
            windowEnd: windowEnd,
            eventCount: windowEvents.length,
            uniqueCategories: catCount,
            categories: cats,
            sources: sources,
            isFingerprintSequence: catCount >= 6,
            matchesFPv5Pattern: this._matchesFPv5Sequence(cats),
            matchesCreepJSPattern: this._matchesCreepJSSequence(cats)
          });
        }
      }
      windowStart += WINDOW_MS / 2; // 50% overlap
    }
  }

  _matchesFPv5Sequence(cats) {
    // FPv5 typically touches: canvas, webgl, audio, font-detection, screen, fingerprint
    var fpv5Cats = ['canvas', 'webgl', 'audio', 'font-detection', 'screen', 'fingerprint', 'device-info'];
    var matchCount = 0;
    fpv5Cats.forEach(function(c) { if (cats[c]) matchCount++; });
    return matchCount >= 4;
  }

  _matchesCreepJSSequence(cats) {
    // CreepJS touches: canvas, webgl, audio, css-fingerprint, speech, intl-fingerprint, property-enum
    var creepCats = ['canvas', 'webgl', 'audio', 'css-fingerprint', 'speech', 'intl-fingerprint', 'property-enum', 'offscreen-canvas'];
    var matchCount = 0;
    creepCats.forEach(function(c) { if (cats[c]) matchCount++; });
    return matchCount >= 4;
  }

  /* ═══ CROSS-FRAME CORRELATION (NEW in v4.2) ═══ */
  _crossFrameCorrelation() {
    var byFrame = {};
    this.events.forEach(function(e) {
      var fid = e.frameId || 'main';
      if (!byFrame[fid]) byFrame[fid] = { events: [], categories: {}, origin: e.origin || 'unknown' };
      byFrame[fid].events.push(e);
      byFrame[fid].categories[e.cat] = (byFrame[fid].categories[e.cat] || 0) + 1;
    });

    var frameIds = Object.keys(byFrame);
    if (frameIds.length < 2) return;

    var self = this;
    // Look for frames with overlapping fingerprinting activity
    for (var i = 0; i < frameIds.length; i++) {
      for (var j = i + 1; j < frameIds.length; j++) {
        var f1 = byFrame[frameIds[i]];
        var f2 = byFrame[frameIds[j]];
        var sharedCats = Object.keys(f1.categories).filter(function(c) { return f2.categories[c]; });

        if (sharedCats.length >= 2) {
          self.crossFrameCorrelations.push({
            frame1: { id: frameIds[i], origin: f1.origin, events: f1.events.length },
            frame2: { id: frameIds[j], origin: f2.origin, events: f2.events.length },
            sharedCategories: sharedCats,
            isCoordinatedFingerprinting: sharedCats.length >= 3 && f1.origin !== f2.origin
          });
        }
      }
    }
  }

  /* ═══ WORKER CORRELATION (NEW in v4.2) ═══ */
  _workerCorrelation() {
    var workerEvents = this.events.filter(function(e) {
      return e.cat === 'worker' || (e.frameId && String(e.frameId).indexOf('worker') !== -1);
    });
    var mainEvents = this.events.filter(function(e) {
      return e.cat !== 'worker' && !(e.frameId && String(e.frameId).indexOf('worker') !== -1);
    });

    if (workerEvents.length === 0) return;

    // Look for worker events temporally close to main thread events
    var correlations = [];
    workerEvents.forEach(function(we) {
      var nearbyMain = mainEvents.filter(function(me) {
        return Math.abs(me.ts - we.ts) < 500;
      });
      if (nearbyMain.length > 0) {
        correlations.push({
          workerEvent: { api: we.api, cat: we.cat, ts: we.ts },
          nearbyMainEvents: nearbyMain.length,
          categories: nearbyMain.map(function(me) { return me.cat; }).filter(function(v, i, a) { return a.indexOf(v) === i; })
        });
      }
    });

    if (correlations.length > 0) {
      this.workerCorrelations.push({
        totalWorkerEvents: workerEvents.length,
        correlatedPairs: correlations.length,
        isOffloadedFingerprinting: workerEvents.length >= 5 && correlations.length >= 3
      });
    }
  }

  /* ═══ ENTROPY CALCULATION (Enhanced for 37 categories) ═══ */
  _calculateEntropy() {
    var catCounts = {};
    var apiCounts = {};
    var originCounts = {};
    var frameCounts = {};
    var riskCounts = {};

    this.events.forEach(function(e) {
      catCounts[e.cat] = (catCounts[e.cat] || 0) + 1;
      apiCounts[e.api] = (apiCounts[e.api] || 0) + 1;
      originCounts[e.origin || 'unknown'] = (originCounts[e.origin || 'unknown'] || 0) + 1;
      if (e.frameId) frameCounts[e.frameId] = (frameCounts[e.frameId] || 0) + 1;
      riskCounts[e.risk || 'info'] = (riskCounts[e.risk || 'info'] || 0) + 1;
    });

    var calcShannon = function(counts) {
      var total = Object.values(counts).reduce(function(s, c) { return s + c; }, 0);
      if (total === 0) return 0;
      return -Object.values(counts).reduce(function(h, c) {
        var p = c / total;
        return p > 0 ? h + p * Math.log2(p) : h;
      }, 0);
    };

    var catEntropy = calcShannon(catCounts);
    var apiEntropy = calcShannon(apiCounts);
    var uniqueCats = Object.keys(catCounts).length;
    var uniqueApis = Object.keys(apiCounts).length;

    this.entropy = {
      categoryEntropy: Math.round(catEntropy * 100) / 100,
      apiEntropy: Math.round(apiEntropy * 100) / 100,
      originEntropy: Math.round(calcShannon(originCounts) * 100) / 100,
      frameEntropy: Math.round(calcShannon(frameCounts) * 100) / 100,
      riskEntropy: Math.round(calcShannon(riskCounts) * 100) / 100,
      uniqueCategories: uniqueCats,
      uniqueApis: uniqueApis,
      uniqueOrigins: Object.keys(originCounts).length,
      uniqueFrames: Object.keys(frameCounts).length,
      // v4.2: updated for 37 categories
      diversityScore: Math.min(100, Math.round(
        (uniqueCats / 37 * 40) +
        (uniqueApis / 80 * 30) +
        (catEntropy / 5.2 * 30) // log2(37) ≈ 5.2
      )),
      fingerprintLikelihood: this._calcFingerprintLikelihood(catCounts, apiCounts)
    };
  }

  _calcFingerprintLikelihood(catCounts, apiCounts) {
    var score = 0;
    // High-entropy fingerprinting categories
    var fpCats = ['canvas', 'webgl', 'audio', 'font-detection', 'webrtc',
                  'speech', 'client-hints', 'webassembly', 'sensor-apis'];
    fpCats.forEach(function(c) { if (catCounts[c]) score += 10; });
    // Medium-entropy
    var medCats = ['css-fingerprint', 'intl-fingerprint', 'math-fingerprint',
                   'property-enum', 'keyboard-layout', 'device-info'];
    medCats.forEach(function(c) { if (catCounts[c]) score += 5; });
    return Math.min(100, score);
  }

  /* ═══ EXFILTRATION MATCHING ═══ */
  _matchExfiltration() {
    var networkEvents = this.events.filter(function(e) {
      return e.cat === 'network' || e.cat === 'exfiltration';
    });

    var self = this;
    networkEvents.forEach(function(evt) {
      var url = (evt.detail && evt.detail.url) ? evt.detail.url : (typeof evt.detail === 'string' ? evt.detail : '');
      for (var id in EXFIL_PATTERNS) {
        var pattern = EXFIL_PATTERNS[id];
        var matched = pattern.urlPatterns.some(function(rx) {
          try { return rx.test(url); } catch(e) { return false; }
        });
        if (matched) {
          self.exfilAlerts.push({
            tracker: pattern.name,
            url: typeof url === 'string' ? url.slice(0, 200) : String(url).slice(0, 200),
            timestamp: evt.ts,
            method: evt.api,
            payloadSize: (evt.detail && (evt.detail.size || evt.detail.bodyLength)) || 0,
            frameId: evt.frameId || 'main',
            origin: evt.origin || 'unknown'
          });
          break;
        }
      }
    });
  }

  addHoneypotHit(hit) {
    this.honeypotHits.push(hit);
  }

  /* ═══ FULL REPORT ═══ */
  getReport() {
    return {
      bursts: this.bursts,
      attributions: this.attributions,
      exfilAlerts: this.exfilAlerts,
      honeypotHits: this.honeypotHits,
      entropy: this.entropy,
      crossCategoryCorrelations: this.crossCategoryCorrelations,
      slowProbes: this.slowProbes,
      workerCorrelations: this.workerCorrelations,
      crossFrameCorrelations: this.crossFrameCorrelations,
      summary: {
        totalBursts: this.bursts.length,
        standardBursts: this.bursts.filter(function(b) { return b.type === 'standard'; }).length,
        microBursts: this.bursts.filter(function(b) { return b.type === 'micro'; }).length,
        fingerprintBursts: this.bursts.filter(function(b) { return b.isFingerprintBurst; }).length,
        identifiedLibraries: this.attributions.map(function(a) { return a.library + ' (' + a.confidence + '%)'; }),
        exfilAttempts: this.exfilAlerts.length,
        honeypotTriggered: this.honeypotHits.length > 0,
        diversityScore: this.entropy.diversityScore || 0,
        fingerprintLikelihood: this.entropy.fingerprintLikelihood || 0,
        slowProbeDetected: this.slowProbes.length > 0,
        crossFrameActivity: this.crossFrameCorrelations.length > 0,
        workerActivity: this.workerCorrelations.length > 0,
        fpv5Detected: this.crossCategoryCorrelations.some(function(c) { return c.matchesFPv5Pattern; }),
        creepJSDetected: this.crossCategoryCorrelations.some(function(c) { return c.matchesCreepJSPattern; })
      }
    };
  }
}

module.exports = { CorrelationEngine };
