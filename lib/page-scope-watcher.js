/**
 * PageScopeWatcher v6.3.0
 * 
 * Watches for new pages/tabs opened within the browser context.
 * When a website opens a popup or new tab, we automatically
 * enable CDP observation on it too.
 * 
 * PASSIVE: no JS injection. Just CDP event subscription on new pages.
 */

'use strict';

const { CdpObserverEngine } = require('./cdp-observer-engine');
const { FrameTreeWatcher } = require('./frame-tree-watcher');

class PageScopeWatcher {
  constructor(pipeline, context) {
    this.pipeline = pipeline;
    this.context = context;
    this.watchedPages = new Set();
    this.childObservers = [];
  }

  async start() {
    // Watch for new pages (tabs, popups)
    this.context.on('page', async (newPage) => {
      const url = newPage.url();
      if (this.watchedPages.has(newPage)) return;
      this.watchedPages.add(newPage);

      this.pipeline.pushCdp({
        cat: 'new-tab',
        api: 'pageOpened',
        risk: 'high',
        detail: `New tab/popup: ${url}`,
      });

      try {
        // Create CDP session on the new page
        const cdp = await this.context.newCDPSession(newPage);

        // Start full observation on new page
        const observer = new CdpObserverEngine(this.pipeline, cdp);
        await observer.start();
        this.childObservers.push(observer);

        // Start frame tree watching on new page
        const frameWatcher = new FrameTreeWatcher(this.pipeline, cdp, this.context);
        await frameWatcher.start();

        // Track page close
        newPage.on('close', () => {
          this.pipeline.pushCdp({
            cat: 'tab-closed',
            api: 'pageClosed',
            risk: 'info',
            detail: `Tab closed: ${newPage.url()}`,
          });
          this.watchedPages.delete(newPage);
        });

      } catch (e) {
        console.error(`[PageScope] Failed to attach to new page: ${e.message}`);
      }
    });

    // Watch for page close
    this.context.on('close', () => {
      this.pipeline.pushCdp({
        cat: 'context-closed',
        api: 'contextClosed',
        risk: 'info',
        detail: 'Browser context closed',
      });
    });
  }
}

module.exports = { PageScopeWatcher };
