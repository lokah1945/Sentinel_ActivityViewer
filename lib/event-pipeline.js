// ═══════════════════════════════════════════════════════════════
//  SENTINEL v6.0.0 — EVENT PIPELINE
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.0.0 (2026-02-25):
//   - NEW: EventEmitter-based pipeline for real-time event streaming
//   - NEW: Dedup by composite key (ts:cat:api:source)
//   - NEW: Category and risk filtering
//   - NEW: Stats aggregation
//
// LAST HISTORY LOG:
//   v6.0.0: Initial creation — replaces batch collection from v5
// ═══════════════════════════════════════════════════════════════

var EventEmitter = require('events');

class EventPipeline extends EventEmitter {
  constructor(options) {
    super();
    options = options || {};
    this.events = [];
    this.maxEvents = options.maxEvents || 100000;
    this.dedup = new Set();
    this.startTime = Date.now();
  }

  push(event) {
    if (this.events.length >= this.maxEvents) return;
    event._id = this.events.length;
    event._ts = Date.now();
    event._relTs = Date.now() - this.startTime;
    var key = (event.ts || 0) + ':' + (event.cat || '') + ':' + (event.api || '') + ':' + (event.source || '');
    if (this.dedup.has(key)) return;
    this.dedup.add(key);
    this.events.push(event);
    this.emit('event', event);
    if (event.risk === 'critical' || event.risk === 'high') {
      this.emit('alert', event);
    }
  }

  pushBatch(events) {
    if (!events || !Array.isArray(events)) return;
    for (var i = 0; i < events.length; i++) {
      this.push(events[i]);
    }
  }

  getAll() {
    return this.events;
  }

  getByCategory(cat) {
    return this.events.filter(function(e) { return e.cat === cat; });
  }

  getByRisk(minRisk) {
    var levels = { low: 0, medium: 1, high: 2, critical: 3 };
    var min = levels[minRisk] || 0;
    return this.events.filter(function(e) { return (levels[e.risk] || 0) >= min; });
  }

  getStats() {
    var cats = {};
    var risks = { low: 0, medium: 0, high: 0, critical: 0 };
    for (var i = 0; i < this.events.length; i++) {
      var e = this.events[i];
      cats[e.cat] = (cats[e.cat] || 0) + 1;
      if (risks[e.risk] !== undefined) risks[e.risk]++;
    }
    return {
      total: this.events.length,
      categories: cats,
      risks: risks,
      duration: Date.now() - this.startTime
    };
  }
}

module.exports = { EventPipeline };
