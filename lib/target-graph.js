// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — TARGET GRAPH (Recursive Auto-Attach)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - FROM v6.4: Recursive auto-attach with infinite depth
//   - REG-016: setAutoAttach with flatten: true
//   - Worker pipeline: Network.enable per discovered worker
//   - Target inventory tracking for coverage proof
// ═══════════════════════════════════════════════════════════════

'use strict';

function TargetGraph(pipeline, cdp, context) {
  this._pipeline = pipeline;
  this._cdp = cdp;
  this._context = context;
  this._targets = new Map();
  this._discovered = 0;
  this._attached = 0;
  this._handlers = [];
}

TargetGraph.prototype.start = async function() {
  var self = this;
  var cdp = this._cdp;
  var p = this._pipeline;

  // REG-016: recursive auto-attach with flatten
  try {
    await cdp.send('Target.setAutoAttach', {
      autoAttach: true,
      waitForDebuggerOnStart: false,
      flatten: true
    });
  } catch(e) {}

  // Listen for attached targets
  var onAttached = function(params) {
    self._discovered++;
    var info = params.targetInfo || {};
    var targetId = info.targetId || params.sessionId || '';
    var type = info.type || 'unknown';
    var url = info.url || '';

    self._targets.set(targetId, {
      type: type,
      url: url,
      sessionId: params.sessionId,
      attached: true,
      ts: Date.now()
    });

    p.pushCDP({
      cat: 'target-attached',
      api: type,
      risk: 'info',
      detail: 'Target: ' + type + ' - ' + url.slice(0, 300)
    });

    // Worker pipeline: enable Network for workers
    if (type === 'worker' || type === 'service_worker' || type === 'shared_worker') {
      self._attached++;
      p.pushCDP({
        cat: 'worker-detected',
        api: type,
        risk: 'high',
        detail: 'Worker discovered: ' + type + ' - ' + url.slice(0, 300)
      });

      // Try to enable Network on worker session
      if (params.sessionId) {
        self._enableWorkerNetwork(params.sessionId, url);
      }
    }

    // iframe targets
    if (type === 'iframe' || type === 'page') {
      self._attached++;
    }
  };

  cdp.on('Target.attachedToTarget', onAttached);
  this._handlers.push({ event: 'Target.attachedToTarget', handler: onAttached });

  // Detach events
  var onDetached = function(params) {
    var targetId = params.targetId || params.sessionId || '';
    var target = self._targets.get(targetId);
    if (target) {
      target.attached = false;
      target.detachedTs = Date.now();
    }
  };
  cdp.on('Target.detachedFromTarget', onDetached);
  this._handlers.push({ event: 'Target.detachedFromTarget', handler: onDetached });

  // Target info changed
  var onInfoChanged = function(params) {
    var info = params.targetInfo || {};
    var existing = self._targets.get(info.targetId);
    if (existing) {
      existing.url = info.url || existing.url;
      existing.title = info.title || existing.title;
    }
  };
  cdp.on('Target.targetInfoChanged', onInfoChanged);
  this._handlers.push({ event: 'Target.targetInfoChanged', handler: onInfoChanged });
};

TargetGraph.prototype._enableWorkerNetwork = async function(sessionId, url) {
  var p = this._pipeline;
  try {
    // Create a CDPSession for the worker via the parent session
    // In flatten mode, we can send commands with the sessionId
    await this._cdp.send('Network.enable', {}, sessionId);
    p.pushCDP({
      cat: 'worker-detected',
      api: 'network-enabled',
      risk: 'info',
      detail: 'Network.enable on worker: ' + (url || '').slice(0, 200)
    });
  } catch(e) {
    // Worker session might not support Network.enable — expected for some types
  }
};

TargetGraph.prototype.getStats = function() {
  return {
    discovered: this._discovered,
    attached: this._attached,
    total: this._targets.size
  };
};

TargetGraph.prototype.getInventory = function() {
  var result = [];
  this._targets.forEach(function(val, key) {
    result.push({
      id: key,
      type: val.type,
      url: val.url,
      attached: val.attached,
      ts: val.ts,
      detachedTs: val.detachedTs || null
    });
  });
  return result;
};

TargetGraph.prototype.stop = function() {
  for (var i = 0; i < this._handlers.length; i++) {
    try { this._cdp.off(this._handlers[i].event, this._handlers[i].handler); } catch(e) {}
  }
  this._handlers = [];
};

module.exports = { TargetGraph: TargetGraph };
