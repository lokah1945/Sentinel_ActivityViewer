/**
 * EventPipeline v6.2.0
 * 
 * Central event bus with deduplication, buffering, and backpressure.
 * All sources (API interceptor, CDP collectors, frame attacher) push here.
 * The ForensicEngine reads from here.
 */

'use strict';

class EventPipeline {
  constructor(opts = {}) {
    this.maxBuffer = opts.maxBuffer || 50000;
    this.events = [];
    this.cdpEvents = [];
    this.dedupeSet = new Set();
    this.stats = {
      totalPushed: 0,
      totalDeduped: 0,
      cdpEvents: 0,
      workerEvents: 0,
      networkEntries: 0,
    };
  }

  push(evt) {
    this.stats.totalPushed++;

    // Dedup key: cat + api + first 80 chars of detail
    const key = (evt.cat || '') + '|' + (evt.api || '') + '|' + (evt.detail || '').slice(0, 80);

    // Allow critical events through even if duplicate
    if (evt.risk !== 'critical' && this.dedupeSet.has(key)) {
      return;
    }
    this.dedupeSet.add(key);

    if (this.events.length < this.maxBuffer) {
      this.events.push(evt);
    }
    this.stats.totalDeduped = this.events.length;
  }

  pushCdp(evt) {
    this.stats.cdpEvents++;
    evt.ts = evt.ts || Date.now();
    evt.src = evt.src || 'cdp';

    if (evt.cat === 'cdp-network' && evt.api === 'responseReceived') {
      this.stats.networkEntries++;
    }
    if (evt.cat === 'cdp-worker') {
      this.stats.workerEvents++;
    }

    this.cdpEvents.push(evt);
  }

  drain() {
    return [...this.events];
  }

  drainAll() {
    return {
      inPage: [...this.events],
      cdp: [...this.cdpEvents],
    };
  }

  getStats() {
    return {
      ...this.stats,
      totalDeduped: this.events.length,
    };
  }

  clear() {
    this.events = [];
    this.cdpEvents = [];
    this.dedupeSet.clear();
    this.stats = { totalPushed: 0, totalDeduped: 0, cdpEvents: 0, workerEvents: 0, networkEntries: 0 };
  }
}

module.exports = { EventPipeline };
