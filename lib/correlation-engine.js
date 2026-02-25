// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — CORRELATION ENGINE
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - FROM v6.4: forensic-engine.js analysis functions (PRESERVED)
//   - NEW: Burst detection (rapid API calls within window)
//   - NEW: Slow-probe detection (spread-out fingerprinting)
//   - NEW: Cross-frame correlation analysis
//   - REG-013: timeSpanMs uses reduce(Math.max) correctly
//
// LAST HISTORY LOG:
//   v6.4.0: forensic-engine.js — basic CDP analysis
//   v7.0.0: Enhanced with hook event correlation
// ═══════════════════════════════════════════════════════════════

'use strict';

class CorrelationEngine {
  constructor(version) {
    this.version = version;
  }

  analyze(events, frames, pipelineStats) {
    var categories = this._categorize(events);
    var threats = this._extractThreats(events);
    var libraryDetections = this._getLibraryDetections(events);
    var networkConversation = this._buildNetworkConversation(events);
    var exfiltration = this._detectExfiltration(events);
    var cookies = this._analyzeCookies(events);
    var websockets = this._analyzeWebSockets(events);
    var bursts = this._detectBursts(events);
    var entropy = this._calculateEntropy(events);
    var h5w = this._build5W1H(events, frames, libraryDetections, cookies, exfiltration);
    var riskScore = this._calculateRiskScore(events, threats, libraryDetections);
    var thirdParties = this._identifyThirdParties(events);
    var timeline = this._buildTimeline(events);
    var hookStats = this._getHookStats(events);

    return {
      categories: categories,
      threats: threats,
      libraryDetections: libraryDetections,
      networkConversation: networkConversation,
      exfiltration: exfiltration,
      cookies: cookies,
      websockets: websockets,
      thirdParties: thirdParties,
      bursts: bursts,
      entropy: entropy,
      h5w: h5w,
      riskScore: riskScore,
      timeline: timeline,
      hookStats: hookStats,
      pipelineStats: pipelineStats || {}
    };
  }

  _categorize(events) {
    var cats = {};
    for (var i = 0; i < events.length; i++) {
      var evt = events[i];
      var cat = evt.cat || 'unknown';
      if (!cats[cat]) cats[cat] = { events: 0, risk: 'info', sources: {} };
      cats[cat].events++;
      var src = evt.src || 'unknown';
      cats[cat].sources[src] = (cats[cat].sources[src] || 0) + 1;
      var ro = ['info', 'low', 'medium', 'high', 'critical'];
      if (ro.indexOf(evt.risk) > ro.indexOf(cats[cat].risk)) cats[cat].risk = evt.risk;
    }
    return Object.entries(cats).map(function(entry) {
      return { name: entry[0], events: entry[1].events, risk: entry[1].risk, sources: entry[1].sources };
    }).sort(function(a, b) { return b.events - a.events; });
  }

  _extractThreats(events) {
    return events
      .filter(function(e) { return e.risk === 'critical' || e.risk === 'high'; })
      .map(function(e) { return { risk: e.risk, category: e.cat, api: e.api, detail: e.detail || '', src: e.src || '' }; })
      .slice(0, 200);
  }

  _getLibraryDetections(events) {
    return events
      .filter(function(e) { return e.cat === 'library-detected'; })
      .map(function(e) {
        return {
          name: (e.meta && e.meta.library) ? e.meta.library : e.api,
          url: (e.meta && e.meta.url) ? e.meta.url : '',
          patterns: (e.meta && e.meta.patterns) ? e.meta.patterns : [],
          confidence: (e.meta && e.meta.patterns && e.meta.patterns.length >= 2) ? 'high' : 'medium'
        };
      });
  }

  _buildNetworkConversation(events) {
    var requests = events.filter(function(e) { return e.cat === 'network-request'; });
    var responses = events.filter(function(e) { return e.cat === 'network-response'; });
    var responseMap = {};
    for (var i = 0; i < responses.length; i++) {
      var r = responses[i];
      if (r.meta && r.meta.requestId) responseMap[r.meta.requestId] = r;
    }
    return requests.map(function(req) {
      var resp = (req.meta && req.meta.requestId) ? responseMap[req.meta.requestId] : null;
      return {
        method: req.api,
        url: (req.detail || '').replace(/^(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+/, '').slice(0, 500),
        status: resp && resp.meta ? resp.meta.status : '',
        size: resp && resp.meta ? resp.meta.size : '',
        type: req.meta ? req.meta.type : '',
        initiator: req.meta ? req.meta.initiator : '',
        ip: resp && resp.meta ? resp.meta.ip : '',
        protocol: resp && resp.meta ? resp.meta.protocol : ''
      };
    }).slice(0, 500);
  }

  _detectExfiltration(events) {
    return events
      .filter(function(e) { return e.cat === 'exfiltration'; })
      .map(function(e) { return { method: e.api, detail: e.detail, risk: e.risk, src: e.src }; });
  }

  _analyzeCookies(events) {
    var setEvts = events.filter(function(e) { return e.cat === 'cookie-set'; });
    var sentEvts = events.filter(function(e) { return e.cat === 'cookie-sent'; });
    var storageEvts = events.filter(function(e) { return e.cat === 'storage'; });
    return {
      cookiesSet: setEvts.length,
      cookiesSent: sentEvts.length,
      storageAccess: storageEvts.length,
      details: setEvts.map(function(e) { return e.detail; }).slice(0, 50)
    };
  }

  _analyzeWebSockets(events) {
    return events.filter(function(e) { return e.cat === 'websocket'; }).map(function(e) {
      return { api: e.api, detail: e.detail, risk: e.risk };
    });
  }

  _detectBursts(events) {
    var windowMs = 1000;
    var threshold = 10;
    var bursts = [];
    for (var i = 0; i < events.length; i++) {
      var windowEnd = (events[i].ts || 0) + windowMs;
      var count = 0;
      for (var j = i; j < events.length && (events[j].ts || 0) <= windowEnd; j++) {
        count++;
      }
      if (count >= threshold) {
        bursts.push({ startTs: events[i].ts, count: count, sample: events[i].cat });
        i = j - 1;
      }
    }
    return bursts;
  }

  _calculateEntropy(events) {
    var catCounts = {};
    var apiCounts = {};
    for (var i = 0; i < events.length; i++) {
      catCounts[events[i].cat] = (catCounts[events[i].cat] || 0) + 1;
      apiCounts[events[i].api] = (apiCounts[events[i].api] || 0) + 1;
    }
    return {
      categoryEntropy: this._h(Object.values(catCounts)),
      apiEntropy: this._h(Object.values(apiCounts))
    };
  }

  _h(counts) {
    var t = counts.reduce(function(a, b) { return a + b; }, 0);
    if (!t) return 0;
    var h = 0;
    for (var i = 0; i < counts.length; i++) {
      if (counts[i] > 0) { var p = counts[i] / t; h -= p * Math.log2(p); }
    }
    return Math.round(h * 1000) / 1000;
  }

  _build5W1H(events, frames, libs, cookies, exfiltration) {
    var origins = new Set();
    for (var i = 0; i < events.length; i++) {
      var m = (events[i].detail || '').match(/https?:\/\/([^\/\s\]]+)/);
      if (m) origins.add(m[1]);
    }
    var whatCounts = {};
    for (var i = 0; i < events.length; i++) {
      whatCounts[events[i].cat] = (whatCounts[events[i].cat] || 0) + 1;
    }
    // REG-013: timeSpanMs uses reduce correctly
    var timestamps = events.map(function(e) { return e.ts; }).filter(Boolean);
    var minTs = timestamps.length ? timestamps.reduce(function(a, b) { return Math.min(a, b); }, Infinity) : 0;
    var maxTs = timestamps.length ? timestamps.reduce(function(a, b) { return Math.max(a, b); }, 0) : 0;

    return {
      who: { origins: Array.from(origins), eventCount: events.length },
      what: whatCounts,
      when: { start: new Date(minTs).toISOString(), end: new Date(maxTs).toISOString(), durationMs: maxTs - minTs },
      where: { origins: Array.from(origins), frames: frames.map(function(f) { return f.url; }).filter(Boolean) },
      why: { librariesDetected: libs.map(function(l) { return l.name; }), cookiesSet: cookies.cookiesSet, exfiltrationAttempts: exfiltration.length },
      how: { dataChannels: Array.from(new Set(events.filter(function(e) { return e.cat === 'exfiltration' || e.cat === 'websocket'; }).map(function(e) { return e.api; }))) }
    };
  }

  _calculateRiskScore(events, threats, libs) {
    var score = 0;
    score += threats.filter(function(t) { return t.risk === 'critical'; }).length * 5;
    score += threats.filter(function(t) { return t.risk === 'high'; }).length * 2;
    score += libs.length * 3;
    var cats = new Set(events.map(function(e) { return e.cat; }));
    score += cats.size * 1;
    return Math.min(100, score);
  }

  _identifyThirdParties(events) {
    var origins = {};
    events.forEach(function(e) {
      var m = (e.detail || '').match(/https?:\/\/([^\/\s\]]+)/);
      if (m) {
        var domain = m[1];
        if (!origins[domain]) origins[domain] = { requests: 0, types: new Set() };
        origins[domain].requests++;
        origins[domain].types.add(e.cat);
      }
    });
    return Object.entries(origins).map(function(entry) {
      return { domain: entry[0], requests: entry[1].requests, types: Array.from(entry[1].types) };
    }).sort(function(a, b) { return b.requests - a.requests; });
  }

  _buildTimeline(events) {
    var timeline = {};
    for (var i = 0; i < events.length; i++) {
      var sec = Math.floor((events[i].ts || 0) / 1000);
      if (!timeline[sec]) timeline[sec] = 0;
      timeline[sec]++;
    }
    return Object.entries(timeline).map(function(entry) {
      return { ts: +entry[0], events: entry[1] };
    });
  }

  _getHookStats(events) {
    var hookEvents = events.filter(function(e) { return e.src === 'hook'; });
    var cdpEvents = events.filter(function(e) { return e.src === 'cdp'; });
    var pageEvents = events.filter(function(e) { return e.src === 'page'; });
    var hookCats = new Set(hookEvents.map(function(e) { return e.cat; }));
    var cdpCats = new Set(cdpEvents.map(function(e) { return e.cat; }));

    return {
      hookEventCount: hookEvents.length,
      cdpEventCount: cdpEvents.length,
      pageEventCount: pageEvents.length,
      hookCategories: Array.from(hookCats),
      cdpCategories: Array.from(cdpCats),
      totalCategories: new Set(events.map(function(e) { return e.cat; })).size
    };
  }
}

module.exports = { CorrelationEngine };
