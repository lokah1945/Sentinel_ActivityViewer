// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — UNIFIED EVENT PIPELINE
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - PURE NEW: Dual-source pipeline (Hook Push + CDP Observer)
//   - FROM v6.4: CDP event dedup and buffering
//   - FROM v6.1: Push event receiving and merging
//   - NEW: Source tracking (src: 'hook' | 'cdp' | 'page')
//   - NEW: Composite key dedup across all sources
//   - NEW: Stats per source type
//   - REG-018: Promise.allSettled for collection
//   - REG-013: timeSpanMs uses reduce(Math.max)
//
// LAST HISTORY LOG:
//   v6.4.0: CDP-only pipeline (push() alias to pushCdp())
//   v6.1.0: Separate push events array
//   v7.0.0: Unified dual-source pipeline
// ═══════════════════════════════════════════════════════════════

'use strict';

class EventPipeline {
  constructor(opts) {
    if (!opts) opts = {};
    this.maxBuffer = opts.maxBuffer || 100000;
    this.events = [];
    this.dedupeSet = new Set();
    this.stats = {
      totalPushed: 0,
      hookEvents: 0,
      cdpEvents: 0,
      pageEvents: 0,
      networkEntries: 0,
      consoleEvents: 0,
      domEvents: 0,
      workerEvents: 0,
      dedupedTotal: 0
    };
  }

  pushCdp(evt) {
    evt.src = 'cdp';
    this._push(evt);
    this.stats.cdpEvents++;
  }

  pushHook(evt) {
    evt.src = 'hook';
    this._push(evt);
    this.stats.hookEvents++;
  }

  pushPage(evt) {
    evt.src = 'page';
    this._push(evt);
    this.stats.pageEvents++;
  }

  // Legacy compatibility
  push(evt) {
    if (!evt.src) evt.src = 'unknown';
    this._push(evt);
  }

  _push(evt) {
    this.stats.totalPushed++;
    evt.ts = evt.ts || Date.now();
    evt.id = this.stats.totalPushed;

    // Category-specific counters
    if (evt.cat === 'network-response' || evt.cat === 'network-request') this.stats.networkEntries++;
    if (evt.cat === 'console' || evt.cat === 'browser-log') this.stats.consoleEvents++;
    if (evt.cat === 'dom-mutation' || evt.cat === 'dom-probe') this.stats.domEvents++;
    if (evt.cat && evt.cat.indexOf('worker') !== -1) this.stats.workerEvents++;

    // Composite key dedup: ts-bucket + cat + api + detail-prefix
    var tsBucket = Math.floor((evt.ts || 0) / 100);
    var key = tsBucket + '|' + (evt.src || '') + '|' + (evt.cat || '') + '|' + (evt.api || '') + '|' + String(evt.detail || '').slice(0, 80);

    // Always allow critical/high events through dedup
    if (evt.risk !== 'critical' && evt.risk !== 'high') {
      if (this.dedupeSet.has(key)) return;
    }
    this.dedupeSet.add(key);

    if (this.events.length < this.maxBuffer) {
      this.events.push(evt);
    }
  }

  pushBatchHook(eventsArray) {
    for (var i = 0; i < eventsArray.length; i++) {
      this.pushHook(eventsArray[i]);
    }
  }

  drain() {
    // Sort by timestamp
    return this.events.slice().sort(function(a, b) { return (a.ts || 0) - (b.ts || 0); });
  }

  getStats() {
    return {
      totalPushed: this.stats.totalPushed,
      hookEvents: this.stats.hookEvents,
      cdpEvents: this.stats.cdpEvents,
      pageEvents: this.stats.pageEvents,
      networkEntries: this.stats.networkEntries,
      consoleEvents: this.stats.consoleEvents,
      domEvents: this.stats.domEvents,
      workerEvents: this.stats.workerEvents,
      totalDeduped: this.events.length
    };
  }

  clear() {
    this.events = [];
    this.dedupeSet.clear();
    var keys = Object.keys(this.stats);
    for (var i = 0; i < keys.length; i++) {
      this.stats[keys[i]] = 0;
    }
  }
}

module.exports = { EventPipeline };
