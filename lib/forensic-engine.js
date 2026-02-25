/**
 * ForensicEngine v6.2.0
 * 
 * Analyzes collected events and produces the 5W1H forensic summary.
 * WHO, WHAT, WHEN, WHERE, WHY, HOW — per domain.
 */

'use strict';

class ForensicEngine {
  constructor(version) {
    this.version = version;
  }

  analyze(events, frames, injectionStatus) {
    const categories = this._categorize(events);
    const threats = this._extractThreats(events);
    const libraryAttribution = this._attributeLibraries(events);
    const networkConversation = this._buildNetworkConversation(events);
    const bursts = this._detectBursts(events);
    const entropy = this._calculateEntropy(events);
    const h5w = this._build5W1H(events, frames, libraryAttribution);
    const valueCaptures = this._extractValueCaptures(events);
    const riskScore = this._calculateRiskScore(threats, categories);

    return {
      categories,
      threats,
      libraryAttribution,
      networkConversation,
      bursts,
      entropy,
      h5w,
      valueCaptures,
      riskScore,
      injectionStatus,
    };
  }

  _categorize(events) {
    const cats = {};
    for (const evt of events) {
      const cat = evt.cat || 'unknown';
      if (!cats[cat]) cats[cat] = { events: 0, risk: 'low' };
      cats[cat].events++;
      // Escalate risk
      const riskOrder = ['info', 'low', 'medium', 'high', 'critical'];
      const current = riskOrder.indexOf(cats[cat].risk);
      const incoming = riskOrder.indexOf(evt.risk || 'low');
      if (incoming > current) cats[cat].risk = evt.risk;
    }
    return Object.entries(cats).map(([name, data]) => ({ name, ...data }));
  }

  _extractThreats(events) {
    return events
      .filter(e => e.risk === 'critical' || e.risk === 'high')
      .map(e => ({
        risk: e.risk,
        category: e.cat,
        api: e.api,
        detail: e.detail || '',
      }))
      .slice(0, 100); // cap at 100
  }

  _attributeLibraries(events) {
    const libs = {
      'FingerprintJS': {
        patterns: ['Math.sin', 'Math.cos', 'Math.tan', 'getParameter', 'toDataURL', 'createOscillator', 'fillText', 'getComputedStyle', 'getBoundingClientRect', 'resolvedOptions', 'getVoices', 'getImageData'],
        matched: 0, total: 12,
      },
      'CreepJS': {
        patterns: ['Math.sin', 'Math.cos', 'Math.tan', 'getParameter', 'toDataURL', 'createOscillator', 'fillText', 'getBoundingClientRect', 'RTCPeerConnection', 'createElement', 'encode', 'getComputedStyle', 'matchMedia'],
        matched: 0, total: 13,
      },
      'BotD': {
        patterns: ['seleniumevaluate', 'nightmare', 'phantomas', 'domAutomation'],
        matched: 0, total: 4,
      },
      'BrowserScan': {
        patterns: ['Math.sin', 'toDataURL', 'RTCPeerConnection', 'createOscillator', 'getParameter', 'getBoundingClientRect', 'fillText', 'getComputedStyle', 'getVoices', 'matchMedia', 'performance.now'],
        matched: 0, total: 11,
      },
      'ClientJS': {
        patterns: ['toDataURL', 'fillText', 'getParameter', 'createOscillator'],
        matched: 0, total: 4,
      },
      'Cloudflare Bot Management': {
        patterns: ['performance.now', 'addEventListener', 'Math.sin', 'getComputedStyle', 'createElement'],
        matched: 0, total: 5,
      },
      'DataDome': {
        patterns: ['performance.now', 'addEventListener', 'toDataURL', 'Math.sin', 'getComputedStyle', 'createElement'],
        matched: 0, total: 6,
      },
    };

    const usedApis = new Set(events.map(e => e.api));
    for (const [name, lib] of Object.entries(libs)) {
      lib.matched = lib.patterns.filter(p => usedApis.has(p)).length;
    }

    return Object.entries(libs).map(([name, data]) => ({
      name,
      matched: `${data.matched}/${data.total}`,
      confidence: data.matched / data.total > 0.7 ? 'high' :
                  data.matched / data.total > 0.5 ? 'medium' : 'low',
    }));
  }

  _buildNetworkConversation(events) {
    return events
      .filter(e => e.cat === 'exfiltration' || (e.cat === 'cdp-network' && e.api === 'responseReceived'))
      .map(e => ({
        method: e.detail?.startsWith('POST') ? 'POST' : 'GET',
        url: (e.detail || '').replace(/^(GET|POST)\s*/, '').slice(0, 300),
        status: e.meta?.status || '',
        size: e.meta?.size || '',
      }))
      .slice(0, 200);
  }

  _detectBursts(events) {
    const buckets = {};
    for (const evt of events) {
      const ts = evt.ts || 0;
      const bucket = Math.floor(ts / 1000) * 1000;
      if (!buckets[bucket]) buckets[bucket] = { events: 0, cats: new Set() };
      buckets[bucket].events++;
      buckets[bucket].cats.add(evt.cat);
    }

    return Object.entries(buckets)
      .map(([ts, data]) => ({
        startTs: parseInt(ts),
        events: data.events,
        categories: data.cats.size,
        topCategories: [...data.cats].slice(0, 5).join(', '),
      }))
      .filter(b => b.events > 10)
      .slice(0, 20);
  }

  _calculateEntropy(events) {
    const catCounts = {};
    const apiCounts = {};
    for (const evt of events) {
      catCounts[evt.cat] = (catCounts[evt.cat] || 0) + 1;
      apiCounts[evt.api] = (apiCounts[evt.api] || 0) + 1;
    }
    return {
      categoryEntropy: this._entropy(Object.values(catCounts)),
      apiEntropy: this._entropy(Object.values(apiCounts)),
    };
  }

  _entropy(counts) {
    const total = counts.reduce((a, b) => a + b, 0);
    if (total === 0) return 0;
    let h = 0;
    for (const c of counts) {
      if (c > 0) {
        const p = c / total;
        h -= p * Math.log2(p);
      }
    }
    return Math.round(h * 1000) / 1000;
  }

  _build5W1H(events, frames, libs) {
    // WHO: source origins
    const origins = new Set();
    for (const evt of events) {
      if (evt.detail) {
        const urlMatch = evt.detail.match(/https?:\/\/([^\/\s]+)/);
        if (urlMatch) origins.add(urlMatch[1]);
      }
    }

    // WHAT: category breakdown
    const whatCounts = {};
    for (const evt of events) {
      whatCounts[evt.cat] = (whatCounts[evt.cat] || 0) + 1;
    }

    // WHEN: timeline
    const timestamps = events.map(e => e.ts).filter(Boolean);
    const minTs = Math.min(...timestamps);
    const maxTs = Math.max(...timestamps);

    // WHERE: frame URLs
    const frameUrls = frames.map(f => f.url).filter(Boolean);

    // WHY: attributed libraries
    const why = libs.filter(l => l.confidence === 'high' || l.confidence === 'medium');

    // HOW: methods used
    const methods = new Set();
    for (const evt of events) {
      if (evt.cat === 'exfiltration' || evt.cat === 'network') {
        methods.add(evt.api);
      }
    }

    return {
      who: { source: 'unknown', eventCount: events.length, origins: [...origins] },
      what: whatCounts,
      when: { start: minTs, end: maxTs, durationMs: maxTs - minTs },
      where: { origins: [...origins], frames: frameUrls },
      why,
      how: { methods: [...methods] },
    };
  }

  _extractValueCaptures(events) {
    return events
      .filter(e => e.val !== undefined && e.val !== '')
      .map(e => ({
        ts: e.ts,
        category: e.cat,
        api: e.api,
        value: e.val,
        direction: e.dir || 'response',
      }))
      .slice(0, 50);
  }

  _calculateRiskScore(threats, categories) {
    let score = 0;
    const criticals = threats.filter(t => t.risk === 'critical').length;
    const highs = threats.filter(t => t.risk === 'high').length;
    score += criticals * 5;
    score += highs * 2;

    // Cap at 100
    return Math.min(100, score);
  }
}

module.exports = { ForensicEngine };
