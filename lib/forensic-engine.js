/**
 * ForensicEngine v6.3.0
 * 
 * Analyzes CDP events and produces 5W1H forensic summary.
 * All data comes from passive CDP observation — no JS hooks needed.
 */

'use strict';

class ForensicEngine {
  constructor(version) {
    this.version = version;
  }

  analyze(events, frames, injectionStatus) {
    const categories = this._categorize(events);
    const threats = this._extractThreats(events);
    const libraryDetections = this._getLibraryDetections(events);
    const networkConversation = this._buildNetworkConversation(events);
    const exfiltration = this._detectExfiltration(events);
    const cookies = this._analyzeCookies(events);
    const websockets = this._analyzeWebSockets(events);
    const bursts = this._detectBursts(events);
    const entropy = this._calculateEntropy(events);
    const h5w = this._build5W1H(events, frames, libraryDetections, cookies, exfiltration);
    const riskScore = this._calculateRiskScore(events, threats, libraryDetections);
    const thirdParties = this._identifyThirdParties(events);
    const timeline = this._buildTimeline(events);

    return {
      categories,
      threats,
      libraryDetections,
      networkConversation,
      exfiltration,
      cookies,
      websockets,
      thirdParties,
      bursts,
      entropy,
      h5w,
      riskScore,
      timeline,
      injectionStatus,
    };
  }

  _categorize(events) {
    const cats = {};
    for (const evt of events) {
      const cat = evt.cat || 'unknown';
      if (!cats[cat]) cats[cat] = { events: 0, risk: 'info' };
      cats[cat].events++;
      const ro = ['info', 'low', 'medium', 'high', 'critical'];
      if (ro.indexOf(evt.risk) > ro.indexOf(cats[cat].risk)) cats[cat].risk = evt.risk;
    }
    return Object.entries(cats).map(([name, data]) => ({ name, ...data })).sort((a, b) => b.events - a.events);
  }

  _extractThreats(events) {
    return events
      .filter(e => e.risk === 'critical' || e.risk === 'high')
      .map(e => ({ risk: e.risk, category: e.cat, api: e.api, detail: e.detail || '' }))
      .slice(0, 100);
  }

  _getLibraryDetections(events) {
    return events
      .filter(e => e.cat === 'library-detected')
      .map(e => ({
        name: e.meta?.library || e.api,
        url: e.meta?.url || '',
        patterns: e.meta?.patterns || [],
        confidence: (e.meta?.patterns?.length || 0) >= 2 ? 'high' : 'medium',
      }));
  }

  _buildNetworkConversation(events) {
    const requests = events.filter(e => e.cat === 'network-request');
    const responses = events.filter(e => e.cat === 'network-response');

    const responseMap = {};
    for (const r of responses) {
      if (r.meta?.requestId) responseMap[r.meta.requestId] = r;
    }

    return requests.map(req => {
      const resp = responseMap[req.meta?.requestId];
      return {
        method: req.api,
        url: (req.detail || '').replace(/^(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+/, '').slice(0, 500),
        status: resp?.meta?.status || '',
        size: resp?.meta?.size || '',
        type: req.meta?.type || '',
        initiator: req.meta?.initiator || '',
        ip: resp?.meta?.ip || '',
        protocol: resp?.meta?.protocol || '',
      };
    }).slice(0, 300);
  }

  _detectExfiltration(events) {
    return events
      .filter(e => e.cat === 'exfiltration')
      .map(e => ({
        method: e.api,
        detail: e.detail,
        risk: e.risk,
      }));
  }

  _analyzeCookies(events) {
    const set = events.filter(e => e.cat === 'cookie-set');
    const sent = events.filter(e => e.cat === 'cookie-sent');
    return {
      cookiesSet: set.length,
      cookiesSent: sent.length,
      details: set.map(e => e.detail).slice(0, 50),
    };
  }

  _analyzeWebSockets(events) {
    return events.filter(e => e.cat === 'websocket').map(e => ({
      api: e.api,
      detail: e.detail,
      risk: e.risk,
    }));
  }

  _identifyThirdParties(events) {
    const domains = new Map();
    for (const evt of events) {
      if (!evt.detail) continue;
      const m = evt.detail.match(/https?:\/\/([^\/\s\]]+)/);
      if (m) {
        const domain = m[1];
        if (!domains.has(domain)) domains.set(domain, { requests: 0, types: new Set(), risk: 'info' });
        const d = domains.get(domain);
        d.requests++;
        d.types.add(evt.cat);
        const ro = ['info', 'low', 'medium', 'high', 'critical'];
        if (ro.indexOf(evt.risk) > ro.indexOf(d.risk)) d.risk = evt.risk;
      }
    }
    return [...domains.entries()]
      .map(([domain, data]) => ({
        domain,
        requests: data.requests,
        categories: [...data.types],
        risk: data.risk,
      }))
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 50);
  }

  _detectBursts(events) {
    const buckets = {};
    for (const evt of events) {
      const bucket = Math.floor((evt.ts || 0) / 1000) * 1000;
      if (!buckets[bucket]) buckets[bucket] = { events: 0, cats: new Set() };
      buckets[bucket].events++;
      buckets[bucket].cats.add(evt.cat);
    }
    return Object.entries(buckets)
      .map(([ts, d]) => ({ startTs: +ts, events: d.events, categories: d.cats.size, topCategories: [...d.cats].slice(0, 5).join(', ') }))
      .filter(b => b.events > 5)
      .slice(0, 30);
  }

  _calculateEntropy(events) {
    const catCounts = {}, apiCounts = {};
    for (const e of events) {
      catCounts[e.cat] = (catCounts[e.cat] || 0) + 1;
      apiCounts[e.api] = (apiCounts[e.api] || 0) + 1;
    }
    return { categoryEntropy: this._h(Object.values(catCounts)), apiEntropy: this._h(Object.values(apiCounts)) };
  }

  _h(counts) {
    const t = counts.reduce((a, b) => a + b, 0);
    if (!t) return 0;
    let h = 0;
    for (const c of counts) { if (c > 0) { const p = c / t; h -= p * Math.log2(p); } }
    return Math.round(h * 1000) / 1000;
  }

  _build5W1H(events, frames, libs, cookies, exfiltration) {
    const origins = new Set();
    for (const e of events) {
      const m = (e.detail || '').match(/https?:\/\/([^\/\s\]]+)/);
      if (m) origins.add(m[1]);
    }

    const whatCounts = {};
    for (const e of events) whatCounts[e.cat] = (whatCounts[e.cat] || 0) + 1;

    const timestamps = events.map(e => e.ts).filter(Boolean);
    const minTs = timestamps.length ? Math.min(...timestamps) : 0;
    const maxTs = timestamps.length ? Math.max(...timestamps) : 0;

    return {
      who: { origins: [...origins], eventCount: events.length },
      what: whatCounts,
      when: { start: new Date(minTs).toISOString(), end: new Date(maxTs).toISOString(), durationMs: maxTs - minTs },
      where: { origins: [...origins], frames: frames.map(f => f.url).filter(Boolean) },
      why: { librariesDetected: libs.map(l => l.name), cookiesSet: cookies.cookiesSet, exfiltrationAttempts: exfiltration.length },
      how: { dataChannels: [...new Set(events.filter(e => e.cat === 'exfiltration' || e.cat === 'websocket').map(e => e.api))] },
    };
  }

  _calculateRiskScore(events, threats, libs) {
    let score = 0;
    score += threats.filter(t => t.risk === 'critical').length * 5;
    score += threats.filter(t => t.risk === 'high').length * 2;
    score += libs.length * 3;
    return Math.min(100, score);
  }

  _buildTimeline(events) {
    // Group by second
    const timeline = {};
    for (const e of events) {
      const sec = Math.floor((e.ts || 0) / 1000);
      if (!timeline[sec]) timeline[sec] = 0;
      timeline[sec]++;
    }
    return Object.entries(timeline).map(([ts, count]) => ({ ts: +ts, events: count }));
  }
}

module.exports = { ForensicEngine };
