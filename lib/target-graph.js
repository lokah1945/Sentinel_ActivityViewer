/**
 * Sentinel v4.6 — Target Graph Walker
 * 
 * PURPOSE: Maintain a tree of ALL browser targets (page, iframe, nested iframe,
 * worker, service_worker) and ensure each one gets:
 *   (a) Network capture (Network.enable on its CDP session)
 *   (b) Runtime hooks injection (via Runtime.evaluate when possible)
 *   (c) Push telemetry binding (via Runtime.addBinding)
 *   (d) BOOT_OK proof per target
 *
 * KEY FIX from v4.5: CDP Target.setAutoAttach is NOT recursive by default.
 * We must call it again on every newly attached target to cascade into
 * nested iframes/workers. This is the "Target Graph Walker" pattern.
 *
 * PHILOSOPHY: Every "room" in the "restaurant" gets a CCTV camera.
 */

class TargetGraph {
  constructor(options = {}) {
    this.nodes = new Map(); // targetId -> TargetNode
    this.events = [];       // Collected from all targets
    this.options = options;
    this.injectionScript = options.injectionScript || '';
    this.shieldScript = options.shieldScript || '';
    this.stealthScript = options.stealthScript || '';
    this.verbose = options.verbose || false;
  }

  /**
   * Initialize the graph from a CDPSession on the main page.
   * This sets up the recursive auto-attach chain.
   */
  async initialize(cdpSession, pageTargetId) {
    this._log('Initializing Target Graph Walker...');

    // Register the main page as root node
    this.nodes.set(pageTargetId || 'main', {
      targetId: pageTargetId || 'main',
      type: 'page',
      url: '',
      sessionId: null,  // main session
      parentId: null,
      attachedAt: Date.now(),
      networkEnabled: false,
      injected: false,
      bootOk: false,
      eventsCollected: 0,
      cdpDomains: []
    });

    // Setup binding for push telemetry on main session
    try {
      await cdpSession.send('Runtime.addBinding', { name: '__SENTINEL_PUSH__' });
      this._log('Push binding registered on main session');
    } catch(e) {
      // May already exist
    }

    // Listen for binding calls from ALL sessions
    cdpSession.on('Runtime.bindingCalled', (params) => {
      if (params.name === '__SENTINEL_PUSH__') {
        this._handlePushEvent(params);
      }
    });

    // Setup auto-attach with flatten:true
    // flatten:true means all child sessions come through the SAME root CDP connection
    try {
      await cdpSession.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: true,
        flatten: true,
        filter: [
          { type: 'iframe' },
          { type: 'worker' },
          { type: 'service_worker' },
          { type: 'shared_worker' }
        ]
      });
      this._log('Auto-attach enabled (recursive via flatten)');
    } catch(e) {
      // Fallback without filter (older Chrome versions)
      try {
        await cdpSession.send('Target.setAutoAttach', {
          autoAttach: true,
          waitForDebuggerOnStart: true,
          flatten: true
        });
        this._log('Auto-attach enabled (fallback, no filter)');
      } catch(e2) {
        this._log('WARNING: Auto-attach failed: ' + e2.message);
      }
    }

    // Listen for new targets
    cdpSession.on('Target.attachedToTarget', async (event) => {
      await this._onTargetAttached(cdpSession, event);
    });

    cdpSession.on('Target.detachedFromTarget', (event) => {
      this._onTargetDetached(event);
    });

    return this;
  }

  /**
   * Called when a new target is auto-attached.
   * This is the CORE of recursive auto-attach.
   */
  async _onTargetAttached(rootSession, event) {
    const { sessionId, targetInfo } = event;
    if (!targetInfo) return;

    const node = {
      targetId: targetInfo.targetId,
      type: targetInfo.type,
      url: targetInfo.url || '',
      sessionId: sessionId,
      parentId: null,
      attachedAt: Date.now(),
      networkEnabled: false,
      injected: false,
      bootOk: false,
      eventsCollected: 0,
      cdpDomains: []
    };

    this.nodes.set(targetInfo.targetId, node);
    this._log(`Target attached: ${targetInfo.type} [${targetInfo.targetId.slice(0,8)}] url=${(targetInfo.url || '').slice(0,60)}`);

    // CRITICAL: Resume the target (it's paused because waitForDebuggerOnStart=true)
    try {
      await rootSession.send('Runtime.runIfWaitingForDebugger', {}, sessionId);
    } catch(e) {
      // Try without sessionId for older protocol
      try { await rootSession.send('Runtime.runIfWaitingForDebugger'); } catch(e2) {}
    }

    // Enable Network on this target's session
    await this._enableNetwork(rootSession, sessionId, node);

    // For iframe targets: inject monitoring script + recursive auto-attach
    if (targetInfo.type === 'iframe') {
      await this._injectIntoTarget(rootSession, sessionId, node);
      // RECURSIVE: enable auto-attach on THIS target too
      // This is what v4.5 was missing — cascade into nested iframes
      await this._enableRecursiveAutoAttach(rootSession, sessionId);
    }

    // For worker targets: enable network + limited runtime monitoring
    if (['worker', 'service_worker', 'shared_worker'].includes(targetInfo.type)) {
      await this._setupWorkerMonitoring(rootSession, sessionId, node);
    }
  }

  /**
   * Enable Network domain on a target session to capture all traffic
   */
  async _enableNetwork(rootSession, sessionId, node) {
    try {
      await rootSession.send('Network.enable', {
        maxTotalBufferSize: 10000000,
        maxResourceBufferSize: 5000000
      }, sessionId);
      node.networkEnabled = true;
      node.cdpDomains.push('Network');
      this._log(`  Network.enable OK on ${node.type} [${node.targetId.slice(0,8)}]`);
    } catch(e) {
      // Some targets don't support Network domain
      this._log(`  Network.enable FAILED on ${node.type}: ${e.message}`);
    }
  }

  /**
   * Inject monitoring scripts into an iframe target via CDP Runtime
   */
  async _injectIntoTarget(rootSession, sessionId, node) {
    // Don't inject into about:blank unless it has activity
    const url = node.url || '';
    if (url === 'about:blank' || url === '' || url === 'about:srcdoc') {
      // TRIAGE: Check if this blank frame has any JS context
      try {
        const result = await rootSession.send('Runtime.evaluate', {
          expression: 'typeof document !== "undefined" && document.scripts && document.scripts.length > 0',
          returnByValue: true
        }, sessionId);
        if (!result || !result.result || result.result.value !== true) {
          node.injected = false;
          node.skipReason = 'blank_no_scripts';
          this._log(`  Skip injection: ${url || 'blank'} (no scripts detected)`);
          return;
        }
        // Has scripts — proceed with injection
        this._log(`  about:blank has scripts — proceeding with injection`);
      } catch(e) {
        node.skipReason = 'blank_eval_failed';
        return;
      }
    }

    try {
      // Inject shield first
      if (this.shieldScript) {
        await rootSession.send('Runtime.evaluate', {
          expression: this.shieldScript,
          awaitPromise: false
        }, sessionId);
      }

      // Inject stealth cleanup
      if (this.stealthScript) {
        await rootSession.send('Runtime.evaluate', {
          expression: this.stealthScript,
          awaitPromise: false
        }, sessionId);
      }

      // Inject main interceptor
      if (this.injectionScript) {
        await rootSession.send('Runtime.evaluate', {
          expression: this.injectionScript,
          awaitPromise: false
        }, sessionId);
      }

      // Verify injection
      const check = await rootSession.send('Runtime.evaluate', {
        expression: 'typeof window.__SENTINEL_DATA__ !== "undefined" || Object.getOwnPropertyNames(window).some(function(k){ return k.indexOf("_sd") === 0; })',
        returnByValue: true
      }, sessionId);

      node.injected = check && check.result && check.result.value === true;
      node.bootOk = node.injected;
      if (node.injected) {
        this._log(`  Injection OK: ${node.type} [${node.targetId.slice(0,8)}]`);
      }
    } catch(e) {
      node.injected = false;
      node.skipReason = 'inject_error: ' + e.message;
      this._log(`  Injection FAILED: ${e.message}`);
    }
  }

  /**
   * Enable recursive auto-attach on a child target
   * THIS IS THE KEY v4.6 FIX: cascade auto-attach to nested iframes
   */
  async _enableRecursiveAutoAttach(rootSession, sessionId) {
    try {
      await rootSession.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: true,
        flatten: true
      }, sessionId);
      this._log(`  Recursive auto-attach enabled on session ${sessionId.slice(0,8)}`);
    } catch(e) {
      // Not all targets support this — that's OK
    }
  }

  /**
   * Setup monitoring for worker targets
   * Workers can't have DOM hooks but we CAN capture their network + runtime
   */
  async _setupWorkerMonitoring(rootSession, sessionId, node) {
    // Network is already enabled above

    // Try to enable Runtime for console/error monitoring
    try {
      await rootSession.send('Runtime.enable', {}, sessionId);
      node.cdpDomains.push('Runtime');
      this._log(`  Runtime.enable OK on ${node.type} [${node.targetId.slice(0,8)}]`);
    } catch(e) {}

    // Listen for console messages from workers (fingerprinting scripts sometimes log)
    // This is handled by the Runtime.consoleAPICalled event on the root session

    // Try to inject a minimal interceptor into the worker context
    try {
      const workerScript = `
        (function() {
          if (self.__SENTINEL_WORKER__) return;
          self.__SENTINEL_WORKER__ = true;
          var _origFetch = self.fetch;
          var _wEvents = [];
          self.fetch = function() {
            var url = arguments[0];
            if (typeof url === 'object' && url.url) url = url.url;
            _wEvents.push({ ts: Date.now(), api: 'worker.fetch', url: String(url).slice(0,300), type: '${node.type}' });
            return _origFetch.apply(self, arguments);
          };
          var _origXHR = self.XMLHttpRequest;
          if (_origXHR) {
            var _origOpen = _origXHR.prototype.open;
            _origXHR.prototype.open = function(method, url) {
              _wEvents.push({ ts: Date.now(), api: 'worker.xhr', method: method, url: String(url).slice(0,300), type: '${node.type}' });
              return _origOpen.apply(this, arguments);
            };
          }
          // Expose events for collection
          self.__SENTINEL_WORKER_EVENTS__ = _wEvents;
        })();
      `;
      await rootSession.send('Runtime.evaluate', {
        expression: workerScript,
        awaitPromise: false
      }, sessionId);
      node.injected = true;
      this._log(`  Worker interceptor injected: ${node.type} [${node.targetId.slice(0,8)}]`);
    } catch(e) {
      // Worker injection may fail for cross-origin workers
      node.skipReason = 'worker_inject_failed: ' + e.message;
    }
  }

  _onTargetDetached(event) {
    const { targetId } = event;
    const node = this.nodes.get(targetId);
    if (node) {
      node.detachedAt = Date.now();
      this._log(`Target detached: ${node.type} [${targetId.slice(0,8)}]`);
    }
  }

  _handlePushEvent(params) {
    try {
      const data = JSON.parse(params.payload);
      if (data.events && Array.isArray(data.events)) {
        this.events.push(...data.events);
      }
    } catch(e) {}
  }

  /**
   * Collect worker events from all attached worker targets
   */
  async collectWorkerEvents(rootSession) {
    const workerEvents = [];
    for (const [targetId, node] of this.nodes) {
      if (!['worker', 'service_worker', 'shared_worker'].includes(node.type)) continue;
      if (!node.sessionId || node.detachedAt) continue;

      try {
        const result = await rootSession.send('Runtime.evaluate', {
          expression: 'JSON.stringify(self.__SENTINEL_WORKER_EVENTS__ || [])',
          returnByValue: true
        }, node.sessionId);

        if (result && result.result && result.result.value) {
          const events = JSON.parse(result.result.value);
          workerEvents.push(...events.map(e => ({
            ...e,
            targetId: targetId,
            workerType: node.type,
            workerUrl: node.url
          })));
          node.eventsCollected = events.length;
        }
      } catch(e) {
        // Worker may have been terminated
      }
    }
    return workerEvents;
  }

  /**
   * Get a proof-of-coverage inventory
   * This is the "coverage proof" that v4.5 was missing
   */
  getInventory() {
    const inventory = [];
    for (const [targetId, node] of this.nodes) {
      inventory.push({
        targetId: targetId.slice(0, 12),
        type: node.type,
        url: node.url ? node.url.slice(0, 120) : '',
        networkEnabled: node.networkEnabled,
        injected: node.injected,
        bootOk: node.bootOk,
        eventsCollected: node.eventsCollected,
        cdpDomains: node.cdpDomains,
        skipReason: node.skipReason || null,
        detached: !!node.detachedAt,
        lifetimeMs: (node.detachedAt || Date.now()) - node.attachedAt
      });
    }
    return inventory;
  }

  /**
   * Get summary stats
   */
  getSummary() {
    const all = Array.from(this.nodes.values());
    const attached = all.filter(n => !n.detachedAt);
    const injected = all.filter(n => n.injected);
    const networkEnabled = all.filter(n => n.networkEnabled);
    const workers = all.filter(n => ['worker', 'service_worker', 'shared_worker'].includes(n.type));
    const iframes = all.filter(n => n.type === 'iframe');

    return {
      totalTargets: all.length,
      attachedTargets: attached.length,
      injectedTargets: injected.length,
      networkEnabledTargets: networkEnabled.length,
      workers: workers.length,
      iframes: iframes.length,
      workerEventsTotal: workers.reduce((s, w) => s + w.eventsCollected, 0),
      pushEventsTotal: this.events.length,
      coveragePercent: all.length > 0 ? Math.round((injected.length / all.length) * 100) : 0
    };
  }

  _log(msg) {
    if (this.verbose) {
      console.log(`  [TargetGraph] ${msg}`);
    }
  }
}

module.exports = { TargetGraph };
