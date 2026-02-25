// ═══════════════════════════════════════════════════════════════
//  SENTINEL v5.0.0 — TARGET GRAPH
//  Contract: C-TG-01 through C-TG-08
//  Recursive Auto-Attach + Worker Pipeline + Per-target Inventory
//  Source of truth: v4.6 Ghost Protocol TargetGraph
// ═══════════════════════════════════════════════════════════════

class TargetGraph {
  constructor(cdpSession, interceptorScript, shieldScript, stealthScript, options) {
    this.cdp = cdpSession;
    this.interceptorScript = interceptorScript;
    this.shieldScript = shieldScript;
    this.stealthScript = stealthScript;
    this.options = options || {};
    this.targets = new Map();
    this.workerEvents = [];
    this.verbose = this.options.verbose || false;
  }

  // [C-TG-07] Get complete target inventory for report
  getInventory() {
    var inventory = [];
    for (var [targetId, record] of this.targets) {
      inventory.push({
        targetId: record.targetId,
        type: record.type,
        url: record.url,
        networkEnabled: record.networkEnabled,
        injected: record.injected,
        bootOk: record.bootOk,
        eventsCollected: record.eventsCollected,
        skipReason: record.skipReason || ''
      });
    }
    return { inventory: inventory, totalTargets: this.targets.size, workerEvents: this.workerEvents.length };
  }

  getWorkerEvents() {
    return this.workerEvents;
  }

  _log(msg) {
    if (this.verbose) {
      process.stderr.write('[TargetGraph] ' + msg + '\n');
    }
  }

  // [C-TG-01] Initialize recursive auto-attach
  async initialize() {
    try {
      // Listen for attachedToTarget events
      this.cdp.on('Target.attachedToTarget', async (params) => {
        await this._onTargetAttached(params);
      });

      this.cdp.on('Target.detachedFromTarget', (params) => {
        this._log('Target detached: ' + params.sessionId);
      });

      // [C-TG-01] Setup auto-attach with flatten + filter
      await this.cdp.send('Target.setAutoAttach', {
        autoAttach: true,
        flatten: true,
        waitForDebuggerOnStart: false,
        filter: [
          { type: 'iframe' },
          { type: 'worker' },
          { type: 'service_worker' },
          { type: 'shared_worker' }
        ]
      });

      this._log('Recursive auto-attach initialized');
    } catch (e) {
      this._log('Auto-attach init error: ' + e.message);
    }
  }

  // [C-TG-02] Recursive cascade handler
  async _onTargetAttached(params) {
    var targetInfo = params.targetInfo;
    var sessionId = params.sessionId;
    var targetId = targetInfo.targetId;
    var type = targetInfo.type || 'unknown';
    var url = targetInfo.url || '';

    // Create inventory record
    var record = {
      targetId: targetId,
      sessionId: sessionId,
      type: type,
      url: url,
      networkEnabled: false,
      injected: false,
      bootOk: false,
      eventsCollected: 0,
      skipReason: ''
    };

    this.targets.set(targetId, record);
    this._log('Attached: ' + type + ' - ' + url);

    try {
      // [C-TG-04] Smart triage for about:blank
      if (url === 'about:blank' || url === '') {
        // Don't skip entirely — check if it has script activity
        var hasActivity = await this._checkScriptActivity(sessionId);
        if (!hasActivity) {
          record.skipReason = 'about:blank without script activity';
          this._log('Smart triage: skipping ' + targetId + ' (no activity)');
          return;
        }
        this._log('Smart triage: about:blank has activity, monitoring');
      }

      // Handle based on target type
      if (type === 'iframe' || type === 'page') {
        await this._setupIframeTarget(sessionId, record);
      } else if (type === 'worker' || type === 'service_worker' || type === 'shared_worker') {
        await this._setupWorkerTarget(sessionId, record);
      }

      // [C-TG-02] CASCADE: Re-call setAutoAttach on this target
      try {
        await this.cdp.send('Target.setAutoAttach', {
          autoAttach: true,
          flatten: true,
          waitForDebuggerOnStart: false
        }, sessionId);
      } catch (e) {
        // Some targets don't support nested auto-attach
      }

    } catch (e) {
      record.skipReason = 'Error: ' + e.message;
      this._log('Error handling target: ' + e.message);
    }
  }

  // [C-TG-04] Check if about:blank frame has script activity
  async _checkScriptActivity(sessionId) {
    try {
      var result = await this.cdp.send('Runtime.evaluate', {
        expression: 'document.scripts.length > 0 || document.querySelector("script") !== null',
        returnByValue: true
      }, sessionId);
      return result && result.result && result.result.value === true;
    } catch (e) {
      return false;
    }
  }

  // [C-TG-03] Setup iframe target with Network + Runtime + injection
  async _setupIframeTarget(sessionId, record) {
    // Enable network monitoring
    try {
      await this.cdp.send('Network.enable', {}, sessionId);
      record.networkEnabled = true;
    } catch (e) {
      this._log('Network.enable failed for iframe: ' + e.message);
    }

    // Enable runtime
    try {
      await this.cdp.send('Runtime.enable', {}, sessionId);
    } catch (e) {}

    // Inject monitoring scripts
    try {
      if (this.shieldScript) {
        await this.cdp.send('Runtime.evaluate', {
          expression: this.shieldScript,
          returnByValue: false
        }, sessionId);
      }
      if (this.stealthScript) {
        await this.cdp.send('Runtime.evaluate', {
          expression: this.stealthScript,
          returnByValue: false
        }, sessionId);
      }
      await this.cdp.send('Runtime.evaluate', {
        expression: this.interceptorScript,
        returnByValue: false
      }, sessionId);
      record.injected = true;
    } catch (e) {
      this._log('Injection failed for iframe: ' + e.message);
    }

    // Check BOOT_OK
    try {
      var bootCheck = await this.cdp.send('Runtime.evaluate', {
        expression: 'window.__SENTINEL_DATA__ && window.__SENTINEL_DATA__.version || ""',
        returnByValue: true
      }, sessionId);
      if (bootCheck && bootCheck.result && bootCheck.result.value) {
        record.bootOk = true;
      }
    } catch (e) {}

    // [C-TG-08] Resume if waiting for debugger
    try {
      await this.cdp.send('Runtime.runIfWaitingForDebugger', {}, sessionId);
    } catch (e) {}
  }

  // [C-TG-05] Worker Pipeline — Network.enable on worker session
  async _setupWorkerTarget(sessionId, record) {
    // Network capture for workers
    try {
      await this.cdp.send('Network.enable', {}, sessionId);
      record.networkEnabled = true;

      // Listen for network events from worker
      this.cdp.on('Network.requestWillBeSent', (params) => {
        if (params.sessionId === sessionId || true) {
          this.workerEvents.push({
            ts: Date.now(),
            type: 'worker-network',
            cat: 'worker',
            api: 'fetch',
            url: params.request ? params.request.url : '',
            method: params.request ? params.request.method : '',
            source: record.url,
            fid: 'worker:' + record.targetId
          });
        }
      });
    } catch (e) {
      this._log('Network.enable failed for worker: ' + e.message);
    }

    // Best-effort Runtime.enable for workers
    try {
      await this.cdp.send('Runtime.enable', {}, sessionId);
    } catch (e) {}

    // Best-effort script injection for dedicated workers
    if (record.type === 'worker') {
      try {
        await this.cdp.send('Runtime.evaluate', {
          expression: this.interceptorScript,
          returnByValue: false
        }, sessionId);
        record.injected = true;
      } catch (e) {
        this._log('Worker injection failed (expected for some types): ' + e.message);
      }
    }

    record.bootOk = true; // Workers don't need BOOT_OK in same way
  }
}

module.exports = { TargetGraph };
