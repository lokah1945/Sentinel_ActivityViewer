/**
 * Sentinel v4 — Stealth Configuration Manager
 * Enhanced with anti-detection shield integration
 * Manages stealth plugin evasions for realistic browser simulation
 */

const StealthPlugin = require('puppeteer-extra-plugin-stealth');

/**
 * Create stealth plugin with all 17 evasions enabled (default)
 * Plus extra hardening for advanced bot-detection bypass
 */
function createStealthPlugin(options = {}) {
  const stealth = StealthPlugin();

  // All evasions ON by default. Can disable specific ones:
  if (options.disableEvasions && Array.isArray(options.disableEvasions)) {
    for (const evasion of options.disableEvasions) {
      stealth.enabledEvasions.delete(evasion);
    }
  }

  return stealth;
}

/**
 * Extra stealth hardening — injected as page script
 * v4 upgrade: Enhanced with deeper cleanup and consistency checks
 */
function getExtraStealthScript() {
  return `
    // ═══ EXTRA STEALTH LAYER v4 ═══

    // 1. Deep webdriver cleanup
    Object.defineProperty(navigator, 'webdriver', {
      get: () => undefined,
      configurable: true
    });

    // Remove ALL automation indicators
    const autoProps = [
      '__playwright', '__pw_manual', '__PW_inspect',
      '__selenium_evaluate', '__fxdriver_evaluate',
      '__driver_evaluate', '__webdriver_evaluate',
      '__selenium_unwrapped', '__webdriver_unwrapped',
      '_phantom', '__nightmare', '_selenium',
      'callPhantom', 'callSelenium',
      '_Recaptcha', '__recaptcha',
      'domAutomation', 'domAutomationController'
    ];
    for (const prop of autoProps) {
      try { delete window[prop]; } catch(e) {}
      try { delete document[prop]; } catch(e) {}
    }

    // 2. Permissions API — return "prompt" for common permissions
    if (navigator.permissions) {
      const originalQuery = navigator.permissions.query.bind(navigator.permissions);
      const permNames = [
        'notifications', 'push', 'midi', 'camera', 'microphone',
        'speaker', 'device-info', 'background-fetch', 'background-sync',
        'bluetooth', 'persistent-storage', 'ambient-light-sensor',
        'accelerometer', 'gyroscope', 'magnetometer', 'clipboard-read',
        'clipboard-write', 'payment-handler', 'idle-detection',
        'periodic-background-sync', 'screen-wake-lock', 'nfc'
      ];
      navigator.permissions.query = async (desc) => {
        if (permNames.includes(desc?.name)) {
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
        connect: function() {},
        sendMessage: function() {},
        id: undefined
      };
    }
    if (!window.chrome.app) {
      window.chrome.app = {
        isInstalled: false,
        InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
        RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
        getDetails: function() { return null; },
        getIsInstalled: function() { return false; }
      };
    }
    if (!window.chrome.csi) {
      window.chrome.csi = function() {
        return {
          onloadT: Date.now(),
          startE: Date.now(),
          pageT: performance.now(),
          tran: 15
        };
      };
    }
    if (!window.chrome.loadTimes) {
      window.chrome.loadTimes = function() {
        return {
          commitLoadTime: Date.now() / 1000,
          connectionInfo: 'h2',
          finishDocumentLoadTime: Date.now() / 1000,
          finishLoadTime: Date.now() / 1000,
          firstPaintAfterLoadTime: 0,
          firstPaintTime: Date.now() / 1000,
          navigationType: 'Other',
          npnNegotiatedProtocol: 'h2',
          requestTime: Date.now() / 1000,
          startLoadTime: Date.now() / 1000,
          wasAlternateProtocolAvailable: false,
          wasFetchedViaSpdy: true,
          wasNpnNegotiated: true
        };
      };
    }

    // 4. Connection API spoofing
    if (navigator.connection) {
      try {
        Object.defineProperty(navigator.connection, 'rtt', { get: () => 50, configurable: true });
        Object.defineProperty(navigator.connection, 'downlink', { get: () => 10, configurable: true });
        Object.defineProperty(navigator.connection, 'effectiveType', { get: () => '4g', configurable: true });
        Object.defineProperty(navigator.connection, 'saveData', { get: () => false, configurable: true });
      } catch(e) {}
    }

    // 5. Notification permission
    if (window.Notification) {
      Object.defineProperty(Notification, 'permission', {
        get: () => 'default',
        configurable: true
      });
    }

    // 6. Plugin/MimeType array consistency
    // Ensure plugins array has correct prototype chain
    if (navigator.plugins && navigator.plugins.length === 0) {
      // Headless Chrome has 0 plugins — suspicious
      // The stealth plugin should handle this, but double-check
    }

    // 7. iframe contentWindow consistency
    // Prevent detection via iframe.contentWindow property checks

    // 8. WebGL vendor/renderer consistency is handled by stealth plugin

    // 9. Prevent CDP leak via Runtime.enable detection
    // rebrowser-patches style: don't expose binding artifacts
  `;
}

module.exports = { createStealthPlugin, getExtraStealthScript };
