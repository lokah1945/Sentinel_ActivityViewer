/**
 * RecursiveFrameAttacher v6.2.0
 * 
 * Recursively attaches monitoring to ALL frames, iframes, and nested iframes.
 * Also monitors for new frames added dynamically via MutationObserver.
 * Handles iframe-in-iframe-in-iframe to the deepest level.
 * 
 * Persists across navigation within frames.
 */

'use strict';

class RecursiveFrameAttacher {
  constructor(pipeline, interceptor, context) {
    this.pipeline = pipeline;
    this.interceptor = interceptor;
    this.context = context;
    this.attachedFrames = new Set();
    this.stats = { checked: 0, collected: 0 };
  }

  async attach(page) {
    // ─── Attach to all existing frames ───
    const frames = page.frames();
    for (const frame of frames) {
      await this._attachToFrame(frame);
    }

    // ─── Listen for new frames ───
    page.on('frameattached', async (frame) => {
      await this._attachToFrame(frame);
    });

    page.on('framenavigated', async (frame) => {
      // Re-inject on navigation within frame
      const fid = this._getFrameId(frame);
      if (this.attachedFrames.has(fid)) {
        this.attachedFrames.delete(fid);
      }
      await this._attachToFrame(frame);
    });

    // ─── Dynamic iframe detection via page-level MutationObserver ───
    try {
      await page.addInitScript(`
        (() => {
          if (window.__sentinel_frame_observer_v62__) return;
          window.__sentinel_frame_observer_v62__ = true;

          const observer = new MutationObserver((mutations) => {
            for (const m of mutations) {
              for (const node of m.addedNodes) {
                if (node.tagName === 'IFRAME' || node.tagName === 'FRAME') {
                  // Frame added dynamically — Playwright's frameattached event handles this
                  // But we also track it as an event
                  if (typeof window.__sentinel_push__ === 'function') {
                    window.__sentinel_push__(JSON.stringify({
                      id: 0, ts: Date.now(), relTs: 0,
                      cat: 'system', api: 'iframe-dynamic',
                      risk: 'info', detail: 'Dynamic iframe: ' + (node.src || 'about:blank'),
                      src: 'observer', dir: 'call', fid: 'main',
                    }));
                  }
                }
              }
            }
          });

          observer.observe(document.documentElement || document.body || document, {
            childList: true, subtree: true,
          });
        })();
      `);
    } catch (e) {}

    // ─── Worker monitoring ───
    this.context.on('serviceworker', async (worker) => {
      this.pipeline.pushCdp({
        cat: 'cdp-worker',
        api: 'serviceWorker',
        risk: 'high',
        detail: 'Service worker: ' + worker.url(),
      });
    });
  }

  async _attachToFrame(frame) {
    const fid = this._getFrameId(frame);
    if (this.attachedFrames.has(fid)) return;

    this.stats.checked++;
    this.attachedFrames.add(fid);

    try {
      const url = frame.url();
      // Skip about:blank but still count them
      if (url === 'about:blank' || url === '') {
        this.stats.collected++;
        return;
      }

      // Inject API interceptor into this frame
      const frameIdStr = 'frame-' + this.stats.checked;

      // Use frame.evaluate to inject monitoring
      try {
        await frame.addInitScript(this.interceptor._getInterceptorScript(frameIdStr));
      } catch (e) {
        // Cross-origin frame — can't inject directly, rely on CDP
      }

      this.stats.collected++;

      this.pipeline.pushCdp({
        cat: 'system',
        api: 'frame-attach',
        risk: 'info',
        detail: `Attached to frame ${frameIdStr}: ${url.slice(0, 200)}`,
      });
    } catch (e) {
      // Frame detached or cross-origin
      this.stats.collected++;
    }
  }

  _getFrameId(frame) {
    try {
      return frame.url() + '|' + frame.name();
    } catch (e) {
      return 'unknown-' + Math.random();
    }
  }

  getStats() {
    return this.stats;
  }
}

module.exports = { RecursiveFrameAttacher };
