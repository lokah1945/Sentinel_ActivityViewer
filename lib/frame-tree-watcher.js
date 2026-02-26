/**
 * FrameTreeWatcher v6.3.0
 * 
 * Monitors ALL targets (iframes, workers, service workers, shared workers)
 * via CDP Target.setAutoAttach with flatten=true.
 * 
 * When a new target (iframe/worker) is discovered, we enable Network observation
 * on it too, creating a complete picture of ALL network activity across
 * the entire browser tab and its sub-resources.
 * 
 * PASSIVE: no JS injection. Just CDP event subscription on child targets.
 * Handles iframe-in-iframe-in-iframe to infinite depth.
 */

'use strict';

class FrameTreeWatcher {
  constructor(pipeline, cdpSession, context) {
    this.pipeline = pipeline;
    this.cdp = cdpSession;
    this.context = context;
    this.targetInventory = [];
    this.childSessions = new Map();
    this.stats = { discovered: 0, attached: 0, workers: 0 };
  }

  async start() {
    // ─── Auto-attach to ALL child targets recursively ───
    try {
      await this.cdp.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: false,
        flatten: true,
      });
      // Also discover existing targets
      await this.cdp.send('Target.setDiscoverTargets', { discover: true });
    } catch (e) {
      console.error('[FrameTree] setAutoAttach failed:', e.message);
    }

    // ─── New target attached ───
    this.cdp.on('Target.attachedToTarget', async (params) => {
      const { sessionId, targetInfo, waitingForDebugger } = params;
      this.stats.discovered++;

      const target = {
        targetId: targetInfo.targetId,
        type: targetInfo.type,
        url: targetInfo.url,
        title: targetInfo.title,
        sessionId,
        attached: false,
        networkEnabled: false,
      };

      this.pipeline.pushCdp({
        cat: 'target-attached',
        api: targetInfo.type,
        risk: targetInfo.type === 'service_worker' ? 'high' : 'info',
        detail: `Target attached: [${targetInfo.type}] ${targetInfo.url}`,
        meta: { targetId: targetInfo.targetId, sessionId, type: targetInfo.type },
      });

      // Enable Network on child target for full observation
      try {
        await this.cdp.send('Network.enable', {
          maxTotalBufferSize: 5 * 1024 * 1024,
        }, sessionId);
        target.networkEnabled = true;
      } catch (e) {}

      // Enable Page events on child if it's a page/iframe
      if (targetInfo.type === 'page' || targetInfo.type === 'iframe') {
        try {
          await this.cdp.send('Page.enable', {}, sessionId);
        } catch (e) {}
      }

      // For workers, track separately
      if (targetInfo.type === 'worker' || targetInfo.type === 'service_worker' || targetInfo.type === 'shared_worker') {
        this.stats.workers++;
        this.pipeline.pushCdp({
          cat: 'worker-detected',
          api: targetInfo.type,
          risk: 'high',
          detail: `Worker: [${targetInfo.type}] ${targetInfo.url}`,
          meta: { targetId: targetInfo.targetId, type: targetInfo.type },
        });
      }

      // Set recursive auto-attach on this child too (infinite depth)
      try {
        await this.cdp.send('Target.setAutoAttach', {
          autoAttach: true,
          waitForDebuggerOnStart: false,
          flatten: true,
        }, sessionId);
      } catch (e) {}

      // Resume if waiting for debugger
      if (waitingForDebugger) {
        try {
          await this.cdp.send('Runtime.runIfWaitingForDebugger', {}, sessionId);
        } catch (e) {}
      }

      target.attached = true;
      this.stats.attached++;
      this.targetInventory.push(target);
      this.childSessions.set(sessionId, target);

      // Listen for network events from child sessions
      this._listenChildNetwork(sessionId, targetInfo);
    });

    // ─── Target detached ───
    this.cdp.on('Target.detachedFromTarget', (params) => {
      this.pipeline.pushCdp({
        cat: 'target-detached',
        api: 'detached',
        risk: 'info',
        detail: `Target detached: session=${params.sessionId}`,
        meta: { sessionId: params.sessionId },
      });
      this.childSessions.delete(params.sessionId);
    });

    // ─── Target info changed ───
    this.cdp.on('Target.targetInfoChanged', (params) => {
      const ti = params.targetInfo;
      this.pipeline.pushCdp({
        cat: 'target-changed',
        api: 'infoChanged',
        risk: 'info',
        detail: `Target changed: [${ti.type}] ${ti.url}`,
        meta: { targetId: ti.targetId, type: ti.type, url: ti.url },
      });
    });

    // ─── Target created ───
    this.cdp.on('Target.targetCreated', (params) => {
      this.pipeline.pushCdp({
        cat: 'target-created',
        api: params.targetInfo.type,
        risk: 'info',
        detail: `Target created: [${params.targetInfo.type}] ${params.targetInfo.url}`,
        meta: { targetId: params.targetInfo.targetId, type: params.targetInfo.type },
      });
    });

    // ─── Target destroyed ───
    this.cdp.on('Target.targetDestroyed', (params) => {
      this.pipeline.pushCdp({
        cat: 'target-destroyed',
        api: 'destroyed',
        risk: 'info',
        detail: `Target destroyed: ${params.targetId}`,
        meta: { targetId: params.targetId },
      });
    });

    // Also track from Playwright context level
    this.context.on('serviceworker', (worker) => {
      this.pipeline.pushCdp({
        cat: 'worker-detected',
        api: 'serviceWorker',
        risk: 'high',
        detail: `Service worker (PW): ${worker.url()}`,
      });
    });
  }

  _listenChildNetwork(sessionId, targetInfo) {
    // Child network events come through the main CDP session
    // with the sessionId parameter — they're already captured by
    // Network.enable on the child. Events bubble up automatically
    // when flatten=true is used in setAutoAttach.
    //
    // We don't need to add separate listeners here —
    // the main CDP session receives all child events.
  }

  getStats() {
    return this.stats;
  }

  getTargetInventory() {
    return this.targetInventory;
  }
}

module.exports = { FrameTreeWatcher };
