// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — EVENT PIPELINE (Dual-Source Unified)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - NEW: Unified pipeline for 3 sources: hook, cdp, page
//   - NEW: Composite-key dedup (tsBucket|src|cat|api|detail-prefix)
//   - NEW: Critical/high risk events bypass dedup
//   - pushBatchHook: batch push from interceptor push telemetry
//   - pushCDP: individual CDP event push
//   - pushPage: individual Playwright page event push
//   - drain: returns all events sorted by timestamp, resets buffer
//   - getStats: returns source-level counts
// ═══════════════════════════════════════════════════════════════

'use strict';

function EventPipeline(opts) {
  this._events = [];
  this._maxBuffer = (opts && opts.maxBuffer) || 100000;
  this._hookCount = 0;
  this._cdpCount = 0;
  this._pageCount = 0;
  this._dedupSet = new Set();
}

EventPipeline.prototype._dedupKey = function(ev) {
  var tsBucket = Math.floor((ev.ts || 0) / 50);
  var detailPre = (ev.detail || '').slice(0, 40);
  return tsBucket + '|' + (ev.src || '') + '|' + (ev.cat || '') + '|' + (ev.api || '') + '|' + detailPre;
};

EventPipeline.prototype._shouldDedup = function(ev) {
  if (ev.risk === 'critical' || ev.risk === 'high') return false;
  var key = this._dedupKey(ev);
  if (this._dedupSet.has(key)) return true;
  this._dedupSet.add(key);
  return false;
};

EventPipeline.prototype.pushBatchHook = function(events) {
  for (var i = 0; i < events.length; i++) {
    if (this._events.length >= this._maxBuffer) return;
    var ev = events[i];
    ev.src = 'hook';
    if (!this._shouldDedup(ev)) {
      this._events.push(ev);
      this._hookCount++;
    }
  }
};

EventPipeline.prototype.pushCDP = function(ev) {
  if (this._events.length >= this._maxBuffer) return;
  ev.src = 'cdp';
  ev.ts = ev.ts || Date.now();
  if (!this._shouldDedup(ev)) {
    this._events.push(ev);
    this._cdpCount++;
  }
};

EventPipeline.prototype.pushPage = function(ev) {
  if (this._events.length >= this._maxBuffer) return;
  ev.src = 'page';
  ev.ts = ev.ts || Date.now();
  if (!this._shouldDedup(ev)) {
    this._events.push(ev);
    this._pageCount++;
  }
};

EventPipeline.prototype.drain = function() {
  var sorted = this._events.slice().sort(function(a, b) { return (a.ts || 0) - (b.ts || 0); });
  this._events = [];
  this._dedupSet.clear();
  return sorted;
};

EventPipeline.prototype.getStats = function() {
  return {
    total: this._events.length,
    hookEvents: this._hookCount,
    cdpEvents: this._cdpCount,
    pageEvents: this._pageCount,
    dedupCacheSize: this._dedupSet.size
  };
};

module.exports = { EventPipeline: EventPipeline };
