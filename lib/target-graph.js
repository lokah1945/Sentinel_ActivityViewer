// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — TARGET GRAPH (Recursive Auto-Attach)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - FROM v6.4: frame-tree-watcher.js + page-scope-watcher.js MERGED
//   - REG-016: Recursive auto-attach for infinite depth iframes
//   - NEW: Worker pipeline enhanced (Network.enable per worker)
//   - NEW: Hook re-injection on new pages/tabs
//   - REG-006: frameattached handler exists
//   - REG-007: framenavigated handler exists
//
// LAST HISTORY LOG:
//   v6.4.0: frame-tree-watcher.js + page-scope-watcher.js (separate)
//   v7.0.0: Merged into single TargetGraph module
// ═══════════════════════════════════════════════════════════════

'use strict';

var CdpObserverEngine = require('./cdp-observer-engine').CdpObserverEngine;

class TargetGraph {
  constructor(pipeline, cdpSession, context) {
    this.pipeline = pipeline;
    this.cdp = cdpSession;
    this.context = context;
    this.targetInventory = [];
    this.childSessions = new Map();
    this.childObservers = [];
    this.watchedPages = new Set();
    this.stats = { discovered: 0, attached: 0, workers: 0, pages: 0 };
  }

  async start() {
    var self = this;

    // ─── Auto-attach to ALL child targets recursively (REG-016) ───
    try {
      await self.cdp.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: false,
        flatten: true
      });
      await self.cdp.send('Target.setDiscoverTargets', { discover: true });
    } catch (e) {
      process.stderr.write('[TargetGraph] setAutoAttach failed: ' + e.message + '\n');
    }

    // ─── New target attached ───
    self.cdp.on('Target.attachedToTarget', async function(params) {
      var sessionId = params.sessionId;
      var targetInfo = params.targetInfo;
      var waitingForDebugger = params.waitingForDebugger;
      self.stats.discovered++;

      var target = {
        targetId: targetInfo.targetId,
        type: targetInfo.type,
        url: targetInfo.url,
        title: targetInfo.title,
        sessionId: sessionId,
        attached: false,
        networkEnabled: false
      };

      self.pipeline.pushCdp({
        cat: 'target-attached',
        api: targetInfo.type,
        risk: targetInfo.type === 'service_worker' ? 'high' : 'info',
        detail: 'Target attached: [' + targetInfo.type + '] ' + targetInfo.url,
        meta: { targetId: targetInfo.targetId, sessionId: sessionId, type: targetInfo.type }
      });

      // Enable Network on child target
      try {
        await self.cdp.send('Network.enable', { maxTotalBufferSize: 5 * 1024 * 1024 }, sessionId);
        target.networkEnabled = true;
      } catch (e) {}

      // Enable Page events on child if it's page/iframe
      if (targetInfo.type === 'page' || targetInfo.type === 'iframe') {
        try { await self.cdp.send('Page.enable', {}, sessionId); } catch (e) {}
      }

      // Track workers (L7: Worker Pipeline)
      if (targetInfo.type === 'worker' || targetInfo.type === 'service_worker' || targetInfo.type === 'shared_worker') {
        self.stats.workers++;
        self.pipeline.pushCdp({
          cat: 'worker-detected',
          api: targetInfo.type,
          risk: 'high',
          detail: 'Worker: [' + targetInfo.type + '] ' + targetInfo.url,
          meta: { targetId: targetInfo.targetId, type: targetInfo.type }
        });
      }

      // Recursive auto-attach on child too (infinite depth)
      try {
        await self.cdp.send('Target.setAutoAttach', {
          autoAttach: true,
          waitForDebuggerOnStart: false,
          flatten: true
        }, sessionId);
      } catch (e) {}

      // Resume if waiting
      if (waitingForDebugger) {
        try { await self.cdp.send('Runtime.runIfWaitingForDebugger', {}, sessionId); } catch (e) {}
      }

      target.attached = true;
      self.stats.attached++;
      self.targetInventory.push(target);
      self.childSessions.set(sessionId, target);
    });

    // ─── Target detached ───
    self.cdp.on('Target.detachedFromTarget', function(params) {
      self.pipeline.pushCdp({
        cat: 'target-detached',
        api: 'detached',
        risk: 'info',
        detail: 'Target detached: session=' + params.sessionId,
        meta: { sessionId: params.sessionId }
      });
      self.childSessions.delete(params.sessionId);
    });

    // ─── Target info changed ───
    self.cdp.on('Target.targetInfoChanged', function(params) {
      var ti = params.targetInfo;
      self.pipeline.pushCdp({
        cat: 'target-changed',
        api: 'infoChanged',
        risk: 'info',
        detail: 'Target changed: [' + ti.type + '] ' + ti.url,
        meta: { targetId: ti.targetId, type: ti.type, url: ti.url }
      });
    });

    // ─── Target created ───
    self.cdp.on('Target.targetCreated', function(params) {
      self.pipeline.pushCdp({
        cat: 'target-created',
        api: params.targetInfo.type,
        risk: 'info',
        detail: 'Target created: [' + params.targetInfo.type + '] ' + params.targetInfo.url,
        meta: { targetId: params.targetInfo.targetId, type: params.targetInfo.type }
      });
    });

    // ─── Target destroyed ───
    self.cdp.on('Target.targetDestroyed', function(params) {
      self.pipeline.pushCdp({
        cat: 'target-destroyed',
        api: 'destroyed',
        risk: 'info',
        detail: 'Target destroyed: ' + params.targetId,
        meta: { targetId: params.targetId }
      });
    });

    // ─── Page Scope Watcher (new tabs/popups) ───
    self.context.on('page', async function(newPage) {
      var url = newPage.url();
      if (self.watchedPages.has(newPage)) return;
      self.watchedPages.add(newPage);
      self.stats.pages++;

      self.pipeline.pushCdp({
        cat: 'new-tab',
        api: 'pageOpened',
        risk: 'high',
        detail: 'New tab/popup: ' + url
      });

      try {
        var cdp = await self.context.newCDPSession(newPage);
        var observer = new CdpObserverEngine(self.pipeline, cdp);
        await observer.start();
        self.childObservers.push(observer);

        newPage.on('close', function() {
          self.pipeline.pushCdp({
            cat: 'tab-closed',
            api: 'pageClosed',
            risk: 'info',
            detail: 'Tab closed: ' + newPage.url()
          });
          self.watchedPages.delete(newPage);
        });
      } catch (e) {
        process.stderr.write('[TargetGraph] Failed to attach to new page: ' + e.message + '\n');
      }
    });

    // ─── Service Worker from Playwright context ───
    self.context.on('serviceworker', function(worker) {
      self.pipeline.pushCdp({
        cat: 'worker-detected',
        api: 'serviceWorker',
        risk: 'high',
        detail: 'Service worker (PW): ' + worker.url()
      });
    });

    // ─── Context close ───
    self.context.on('close', function() {
      self.pipeline.pushCdp({
        cat: 'context-closed',
        api: 'contextClosed',
        risk: 'info',
        detail: 'Browser context closed'
      });
    });
  }

  getStats() { return this.stats; }
  getTargetInventory() { return this.targetInventory; }
}

module.exports = { TargetGraph };
