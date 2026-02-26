/**
 * EventPipeline v6.3.0
 * 
 * Central event bus. In v6.3 ALL events come from CDP (no page injection).
 * Deduplication, buffering, and stats tracking.
 */

'use strict';

class EventPipeline {
  constructor(opts = {}) {
    this.maxBuffer = opts.maxBuffer || 100000;
    this.events = [];
    this.dedupeSet = new Set();
    this.stats = {
      totalPushed: 0,
      cdpEvents: 0,
      networkEntries: 0,
      consoleEvents: 0,
      domEvents: 0,
      workerEvents: 0,
    };
  }

  pushCdp(evt) {
    this.stats.totalPushed++;
    this.stats.cdpEvents++;

    evt.ts = evt.ts || Date.now();
    evt.src = evt.src || 'cdp';
    evt.id = this.stats.totalPushed;

    // Category-specific counters
    if (evt.cat === 'network-response') this.stats.networkEntries++;
    if (evt.cat === 'console') this.stats.consoleEvents++;
    if (evt.cat === 'dom-mutation') this.stats.domEvents++;
    if (evt.cat?.includes('worker')) this.stats.workerEvents++;

    // Dedup: allow critical and unique events through
    const key = `${evt.cat}|${evt.api}|${(evt.detail || '').slice(0, 100)}`;
    if (evt.risk !== 'critical' && evt.risk !== 'high' && this.dedupeSet.has(key)) {
      return;
    }
    this.dedupeSet.add(key);

    if (this.events.length < this.maxBuffer) {
      this.events.push(evt);
    }
  }

  // Legacy compatibility for any code that calls push()
  push(evt) {
    this.pushCdp(evt);
  }

  drain() {
    return [...this.events];
  }

  getStats() {
    return {
      ...this.stats,
      totalDeduped: this.events.length,
    };
  }

  clear() {
    this.events = [];
    this.dedupeSet.clear();
    Object.keys(this.stats).forEach(k => this.stats[k] = 0);
  }
}

module.exports = { EventPipeline };
