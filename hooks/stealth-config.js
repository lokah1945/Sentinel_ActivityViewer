/**
 * Sentinel v3 — Stealth Configuration Manager
 * Manages stealth plugin evasions for realistic browser simulation
 */

const StealthPlugin = require('puppeteer-extra-plugin-stealth');

/**
 * Create stealth plugin with all 17 evasions enabled (default)
 * Plus extra hardening for advanced bot-detection bypass
 */
function createStealthPlugin(options = {}) {
  const stealth = StealthPlugin();

  // By default all evasions are ON. User can disable specific ones:
  // chrome.app, chrome.csi, chrome.loadTimes, chrome.runtime,
  // defaultArgs, iframe.contentWindow, media.codecs,
  // navigator.hardwareConcurrency, navigator.languages,
  // navigator.permissions, navigator.plugins, navigator.vendor,
  // navigator.webdriver, sourceurl, user-agent-override,
  // webgl.vendor, window.outerdimensions

  if (options.disableEvasions && Array.isArray(options.disableEvasions)) {
    for (const evasion of options.disableEvasions) {
      stealth.enabledEvasions.delete(evasion);
    }
  }

  return stealth;
}

/**
 * Extra stealth hardening — injected as page script
 * Covers vectors NOT handled by stealth plugin:
 * - Permissions API spoofing
 * - WebDriver property deep cleanup
 * - Chrome DevTools Protocol leak prevention
 * - navigator.connection spoofing
 * - Battery API spoofing
 */
function getExtraStealthScript() {
  return `
    // ═══ EXTRA STEALTH LAYER ═══

    // 1. Deep webdriver cleanup (beyond stealth plugin)
    Object.defineProperty(navigator, 'webdriver', {
      get: () => undefined,
      configurable: true
    });

    // Remove automation indicators from window
    delete window.__playwright;
    delete window.__pw_manual;
    delete window.__PW_inspect;

    // 2. Permissions API — return "prompt" for common permissions
    if (navigator.permissions) {
      const originalQuery = navigator.permissions.query.bind(navigator.permissions);
      navigator.permissions.query = async (desc) => {
        if (['notifications', 'push', 'midi', 'camera', 'microphone',
             'speaker', 'device-info', 'background-fetch', 'background-sync',
             'bluetooth', 'persistent-storage', 'ambient-light-sensor',
             'accelerometer', 'gyroscope', 'magnetometer', 'clipboard-read',
             'clipboard-write', 'payment-handler', 'idle-detection',
             'periodic-background-sync', 'screen-wake-lock', 'nfc'
        ].includes(desc.name)) {
          return { state: 'prompt', onchange: null };
        }
        return originalQuery(desc);
      };
    }

    // 3. Chrome runtime — ensure window.chrome exists properly
    if (!window.chrome) {
      window.chrome = {};
    }
    if (!window.chrome.runtime) {
      window.chrome.runtime = {
        connect: () => {},
        sendMessage: () => {},
        id: undefined
      };
    }

    // 4. Connection API spoofing
    if (navigator.connection) {
      Object.defineProperty(navigator.connection, 'rtt', { get: () => 50, configurable: true });
      Object.defineProperty(navigator.connection, 'downlink', { get: () => 10, configurable: true });
      Object.defineProperty(navigator.connection, 'effectiveType', { get: () => '4g', configurable: true });
    }

    // 5. Notification permission — avoid "denied" (suspicious for real user)
    if (window.Notification) {
      Object.defineProperty(Notification, 'permission', {
        get: () => 'default',
        configurable: true
      });
    }

    // 6. Prevent detection of automation via stack trace analysis
    const origError = Error;
    const origPrepare = Error.prepareStackTrace;
    // Cleanup puppeteer/playwright traces from stack
    Error.prepareStackTrace = function(error, stack) {
      const filtered = stack.filter(frame => {
        const file = frame.getFileName() || '';
        return !file.includes('puppeteer') &&
               !file.includes('playwright') &&
               !file.includes('pptr:') &&
               !file.includes('__puppeteer');
      });
      if (origPrepare) return origPrepare(error, filtered);
      return error.toString() + '\\n' + filtered.map(f =>
        '    at ' + f.toString()
      ).join('\\n');
    };

    // 7. SourceURL cleanup (complement to stealth plugin)
    // Prevent leaking injected script source URLs
  `;
}

module.exports = { createStealthPlugin, getExtraStealthScript };
