/**
 * AntiDetectionShield v6.2.0
 * 
 * Defense-in-depth layer that works WITH rebrowser-patches.
 * rebrowser-patches handles the critical Runtime.Enable leak at source level.
 * This module handles remaining surface-level indicators that stealth plugin misses.
 * 
 * IMPORTANT: This runs via CDP Page.addScriptToEvaluateOnNewDocument which
 * rebrowser-patches has made safe (no Runtime.Enable triggered for this injection).
 */

'use strict';

class AntiDetectionShield {
  async apply(page, cdpSession) {
    // ─── 1. Remove automation indicators via CDP ───
    // These are defense-in-depth; rebrowser-patches already prevents the main leak
    try {
      await cdpSession.send('Page.addScriptToEvaluateOnNewDocument', {
        source: this._getShieldScript(),
        worldName: undefined, // main world — safe because rebrowser-patches fixes the leak
      });
    } catch (e) {
      // Fallback: use Playwright's addInitScript
      await page.addInitScript(this._getShieldScript());
    }

    // ─── 2. Remove webdriver flag via CDP ───
    try {
      await cdpSession.send('Page.addScriptToEvaluateOnNewDocument', {
        source: `Object.defineProperty(navigator, 'webdriver', { get: () => undefined });`,
      });
    } catch (e) {}

    // ─── 3. Set proper permissions ───
    try {
      await cdpSession.send('Emulation.setAutoDarkMode', { enabled: false }).catch(() => {});
    } catch (e) {}
  }

  _getShieldScript() {
    return `
      // ═══ Sentinel v6.2.0 AntiDetection Shield ═══
      // This script runs in main world before any page script.
      // rebrowser-patches ensures this injection does NOT trigger Runtime.consoleAPICalled leak.

      (() => {
        'use strict';

        // ─── Remove automation-revealing properties ───
        const deleteProps = [
          'webdriver', '__webdriver_evaluate', '__selenium_evaluate',
          '__webdriver_script_function', '__webdriver_script_func',
          '__webdriver_script_fn', '__fxdriver_evaluate',
          '__driver_evaluate', '__webdriver_unwrapped',
          '__driver_unwrapped', '__selenium_unwrapped',
          '_Selenium_IDE_Recorder', '_selenium',
          'calledSelenium', '__nightmare',
          '_phantomChildren', '__phantomas',
          'Buffer', 'emit', 'spawn',
          'domAutomation', 'domAutomationController',
        ];

        for (const prop of deleteProps) {
          try {
            if (prop in window) {
              delete window[prop];
            }
            if (prop in document) {
              delete document[prop];
            }
          } catch (e) {}
        }

        // ─── navigator.webdriver ───
        try {
          Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
            configurable: true,
          });
        } catch (e) {}

        // ─── Prevent chrome.runtime detection in non-extension context ───
        if (!window.chrome) window.chrome = {};
        if (!window.chrome.runtime) {
          window.chrome.runtime = {
            connect: () => {},
            sendMessage: () => {},
            id: undefined,
          };
        }

        // ─── navigator.plugins — ensure realistic plugin array ───
        try {
          const pluginData = [
            { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: '' },
            { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: '' },
            { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: '' },
            { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: '' },
          ];

          Object.defineProperty(navigator, 'plugins', {
            get: () => {
              const arr = pluginData.map(p => {
                const plugin = Object.create(Plugin.prototype);
                Object.defineProperties(plugin, {
                  name: { value: p.name, enumerable: true },
                  filename: { value: p.filename, enumerable: true },
                  description: { value: p.description, enumerable: true },
                  length: { value: 1, enumerable: true },
                });
                return plugin;
              });
              arr.refresh = () => {};
              return arr;
            },
            configurable: true,
          });
        } catch (e) {}

        // ─── navigator.languages — ensure consistent ───
        try {
          Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
            configurable: true,
          });
        } catch (e) {}

        // ─── Prevent permission inconsistencies ───
        const originalQuery = window.navigator.permissions?.query;
        if (originalQuery) {
          window.navigator.permissions.query = (parameters) => {
            if (parameters.name === 'notifications') {
              return Promise.resolve({ state: Notification.permission });
            }
            return originalQuery.call(window.navigator.permissions, parameters);
          };
        }

        // ─── WebGL vendor/renderer — do NOT override, let real GPU show ───
        // Overriding these creates detectable inconsistencies.
        // Real hardware values are more convincing than spoofed ones.

        // ─── Prevent iframe detection of parent automation ───
        try {
          Object.defineProperty(window, 'frameElement', {
            get: () => null,
            configurable: true,
          });
        } catch (e) {}
      })();
    `;
  }
}

module.exports = { AntiDetectionShield };
