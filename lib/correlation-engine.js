/**
 * Sentinel v4.1 — Behavior Correlation Engine (Layer 6)
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
  }

  ingestEvents(events) {
    this.events = events || [];
    this._detectBursts();
    this._attributeLibraries();
    this._calculateEntropy();
    this._matchExfiltration();
  }

  _detectBursts() {
    if (this.events.length === 0) return;
    const sorted = [...this.events].sort((a, b) => a.ts - b.ts);
    const BURST_THRESHOLD = 50;
    const BURST_WINDOW = 1000;

    let burstStart = sorted[0].ts;
    let burstEvents = [sorted[0]];

    for (let i = 1; i < sorted.length; i++) {
      if (sorted[i].ts - burstStart <= BURST_WINDOW) {
        burstEvents.push(sorted[i]);
      } else {
        if (burstEvents.length >= BURST_THRESHOLD) {
          const cats = {};
          burstEvents.forEach(e => { cats[e.cat] = (cats[e.cat] || 0) + 1; });
          this.bursts.push({
            startTs: burstStart,
            endTs: burstEvents[burstEvents.length - 1].ts,
            count: burstEvents.length,
            durationMs: burstEvents[burstEvents.length - 1].ts - burstStart,
            categories: cats,
            topCategory: Object.entries(cats).sort((a, b) => b[1] - a[1])[0]?.[0] || 'unknown',
            isFingerprintBurst: Object.keys(cats).length >= 3
          });
        }
        burstStart = sorted[i].ts;
        burstEvents = [sorted[i]];
      }
    }
    if (burstEvents.length >= BURST_THRESHOLD) {
      const cats = {};
      burstEvents.forEach(e => { cats[e.cat] = (cats[e.cat] || 0) + 1; });
      this.bursts.push({
        startTs: burstStart,
        endTs: burstEvents[burstEvents.length - 1].ts,
        count: burstEvents.length,
        durationMs: burstEvents[burstEvents.length - 1].ts - burstStart,
        categories: cats,
        topCategory: Object.entries(cats).sort((a, b) => b[1] - a[1])[0]?.[0] || 'unknown',
        isFingerprintBurst: Object.keys(cats).length >= 3
      });
    }
  }

  _attributeLibraries() {
    const apiSet = new Set(this.events.map(e => e.api));

    for (const [libId, lib] of Object.entries(LIBRARY_SIGNATURES)) {
      let score = 0;
      const matchedPatterns = [];
      for (const pattern of lib.patterns) {
        const apiMatch = pattern.apis.some(a => apiSet.has(a));
        if (apiMatch) {
          score += pattern.weight;
          matchedPatterns.push(pattern.category);
        }
      }
      if (score >= lib.minScore) {
        const burstMatch = this.bursts.some(b => b.durationMs <= lib.burstWindow && b.isFingerprintBurst);
        this.attributions.push({
          library: lib.name,
          confidence: Math.min(100, Math.round((score / (lib.patterns.reduce((s, p) => s + p.weight, 0))) * 100)),
          score,
          matchedPatterns,
          burstCorrelation: burstMatch,
          description: lib.description
        });
      }
    }
    this.attributions.sort((a, b) => b.confidence - a.confidence);
  }

  _calculateEntropy() {
    const catCounts = {};
    const apiCounts = {};
    const originCounts = {};
    this.events.forEach(e => {
      catCounts[e.cat] = (catCounts[e.cat] || 0) + 1;
      apiCounts[e.api] = (apiCounts[e.api] || 0) + 1;
      originCounts[e.origin] = (originCounts[e.origin] || 0) + 1;
    });

    const calcShannon = (counts) => {
      const total = Object.values(counts).reduce((s, c) => s + c, 0);
      if (total === 0) return 0;
      return -Object.values(counts).reduce((h, c) => {
        const p = c / total;
        return p > 0 ? h + p * Math.log2(p) : h;
      }, 0);
    };

    this.entropy = {
      categoryEntropy: Math.round(calcShannon(catCounts) * 100) / 100,
      apiEntropy: Math.round(calcShannon(apiCounts) * 100) / 100,
      originEntropy: Math.round(calcShannon(originCounts) * 100) / 100,
      uniqueCategories: Object.keys(catCounts).length,
      uniqueApis: Object.keys(apiCounts).length,
      uniqueOrigins: Object.keys(originCounts).length,
      diversityScore: Math.min(100, Math.round(
        (Object.keys(catCounts).length / 30 * 40) +
        (Object.keys(apiCounts).length / 50 * 30) +
        (calcShannon(catCounts) / 5 * 30)
      ))
    };
  }

  _matchExfiltration() {
    const networkEvents = this.events.filter(e => e.cat === 'network' || e.cat === 'exfiltration');
    for (const evt of networkEvents) {
      const url = evt.detail || '';
      const urlStr = typeof url === 'string' ? url : String(url);
      for (const [id, pattern] of Object.entries(EXFIL_PATTERNS)) {
        if (pattern.urlPatterns.some(rx => rx.test(urlStr))) {
          this.exfilAlerts.push({
            tracker: pattern.name,
            url: urlStr.slice(0, 200),
            timestamp: evt.ts,
            method: evt.api
          });
          break;
        }
      }
    }
  }

  getReport() {
    return {
      bursts: this.bursts,
      attributions: this.attributions,
      exfilAlerts: this.exfilAlerts,
      honeypotHits: this.honeypotHits,
      entropy: this.entropy,
      summary: {
        totalBursts: this.bursts.length,
        fingerprintBursts: this.bursts.filter(b => b.isFingerprintBurst).length,
        identifiedLibraries: this.attributions.map(a => a.library + ' (' + a.confidence + '%)'),
        exfilAttempts: this.exfilAlerts.length,
        honeypotTriggered: this.honeypotHits.length > 0,
        diversityScore: this.entropy.diversityScore || 0
      }
    };
  }
}

module.exports = { CorrelationEngine };
