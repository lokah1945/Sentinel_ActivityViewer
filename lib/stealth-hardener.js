/**
 * StealthHardener v6.2.0
 * 
 * Additional hardening layer for stealth mode.
 * Works on top of:
 *   - rebrowser-patches (Runtime.Enable fix)
 *   - puppeteer-extra-plugin-stealth (12 evasion modules)
 *   - AntiDetectionShield (property cleanup)
 * 
 * This adds behavioral & timing-based evasion that plugins don't cover.
 */

'use strict';

class StealthHardener {
  async apply(page, cdpSession) {
    // ─── 1. Realistic viewport & device metrics ───
    try {
      await cdpSession.send('Emulation.setDeviceMetricsOverride', {
        width: 1280,
        height: 720,
        deviceScaleFactor: 1,
        mobile: false,
        screenWidth: 1280,
        screenHeight: 720,
        screenOrientation: { angle: 0, type: 'landscapePrimary' },
      });
    } catch (e) {}

    // ─── 2. Realistic User-Agent Client Hints ───
    try {
      await cdpSession.send('Emulation.setUserAgentOverride', {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        acceptLanguage: 'en-US,en;q=0.9',
        platform: 'Win32',
        userAgentMetadata: {
          brands: [
            { brand: 'Chromium', version: '131' },
            { brand: 'Not_A Brand', version: '24' },
            { brand: 'Google Chrome', version: '131' },
          ],
          fullVersionList: [
            { brand: 'Chromium', version: '131.0.6778.140' },
            { brand: 'Not_A Brand', version: '24.0.0.0' },
            { brand: 'Google Chrome', version: '131.0.6778.140' },
          ],
          fullVersion: '131.0.6778.140',
          platform: 'Windows',
          platformVersion: '15.0.0',
          architecture: 'x86',
          model: '',
          mobile: false,
          bitness: '64',
          wow64: false,
        },
      });
    } catch (e) {}

    // ─── 3. Inject behavioral patterns ───
    try {
      await cdpSession.send('Page.addScriptToEvaluateOnNewDocument', {
        source: this._getBehavioralScript(),
      });
    } catch (e) {
      await page.addInitScript(this._getBehavioralScript());
    }
  }

  _getBehavioralScript() {
    return `
      (() => {
        'use strict';

        // ─── Add realistic browser history length ───
        try {
          Object.defineProperty(window.history, 'length', {
            get: () => Math.floor(Math.random() * 5) + 2,
            configurable: true,
          });
        } catch (e) {}

        // ─── Ensure connection.rtt has realistic value ───
        try {
          if (navigator.connection) {
            Object.defineProperty(navigator.connection, 'rtt', {
              get: () => 50 + Math.floor(Math.random() * 100),
              configurable: true,
            });
          }
        } catch (e) {}

        // ─── Ensure battery API returns realistic data ───
        if (navigator.getBattery) {
          const origGetBattery = navigator.getBattery.bind(navigator);
          navigator.getBattery = () => origGetBattery().then(battery => {
            try {
              Object.defineProperty(battery, 'charging', { get: () => true, configurable: true });
              Object.defineProperty(battery, 'level', { get: () => 0.87 + Math.random() * 0.12, configurable: true });
            } catch (e) {}
            return battery;
          });
        }

        // ─── Ensure document.hasFocus() returns true ───
        const _origHasFocus = document.hasFocus;
        document.hasFocus = () => true;

        // ─── Prevent detection via Error stack trace ───
        // Some detectors check stack traces for automation frameworks
        const origPrepareStackTrace = Error.prepareStackTrace;
        Error.prepareStackTrace = function(error, stack) {
          const filtered = stack.filter(frame => {
            const fn = frame.getFileName() || '';
            return !fn.includes('puppeteer') && 
                   !fn.includes('playwright') && 
                   !fn.includes('pptr:') &&
                   !fn.includes('__playwright');
          });
          if (origPrepareStackTrace) {
            return origPrepareStackTrace(error, filtered);
          }
          return filtered.map(f => '    at ' + f.toString()).join('\\n');
        };
      })();
    `;
  }
}

module.exports = { StealthHardener };
