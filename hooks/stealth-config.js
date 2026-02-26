/**
 * Sentinel v4.1 — Stealth Configuration Manager
 * Manages stealth plugin evasions for realistic browser simulation
 */

const StealthPlugin = require('puppeteer-extra-plugin-stealth');

function createStealthPlugin(options = {}) {
  const stealth = StealthPlugin();
  if (options.disableEvasions && Array.isArray(options.disableEvasions)) {
    for (const evasion of options.disableEvasions) {
      stealth.enabledEvasions.delete(evasion);
    }
  }
  return stealth;
}

function getExtraStealthScript() {
  return `
    // ═══ EXTRA STEALTH LAYER v4.1 ═══

    // 1. Deep webdriver cleanup
    try {
      Object.defineProperty(navigator, 'webdriver', {
        get: function() { return undefined; },
        configurable: true
      });
    } catch(e) {}

    // Remove automation indicators
    try {
      var autoProps = [
        '__playwright', '__pw_manual', '__PW_inspect',
        '__selenium_evaluate', '__fxdriver_evaluate',
        '__driver_evaluate', '__webdriver_evaluate',
        '__selenium_unwrapped', '__webdriver_unwrapped',
        '_phantom', '__nightmare', '_selenium',
        'callPhantom', 'callSelenium',
        'domAutomation', 'domAutomationController'
      ];
      for (var i = 0; i < autoProps.length; i++) {
        try { delete window[autoProps[i]]; } catch(e) {}
        try { delete document[autoProps[i]]; } catch(e) {}
      }
    } catch(e) {}

    // 2. Permissions API — return "prompt" for common permissions
    try {
      if (navigator.permissions) {
        var originalQuery = navigator.permissions.query.bind(navigator.permissions);
        var permNames = [
          'notifications', 'push', 'midi', 'camera', 'microphone',
          'speaker', 'device-info', 'background-fetch', 'background-sync',
          'bluetooth', 'persistent-storage', 'ambient-light-sensor',
          'accelerometer', 'gyroscope', 'magnetometer', 'clipboard-read',
          'clipboard-write', 'payment-handler', 'idle-detection',
          'periodic-background-sync', 'screen-wake-lock', 'nfc'
        ];
        navigator.permissions.query = function(desc) {
          if (desc && permNames.indexOf(desc.name) >= 0) {
            return Promise.resolve({ state: 'prompt', onchange: null });
          }
          return originalQuery(desc);
        };
      }
    } catch(e) {}

    // 3. Chrome runtime
    try {
      if (!window.chrome) window.chrome = {};
      if (!window.chrome.runtime) {
        window.chrome.runtime = { connect: function(){}, sendMessage: function(){}, id: undefined };
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
          return { onloadT: Date.now(), startE: Date.now(), pageT: performance.now(), tran: 15 };
        };
      }
      if (!window.chrome.loadTimes) {
        window.chrome.loadTimes = function() {
          return {
            commitLoadTime: Date.now() / 1000, connectionInfo: 'h2',
            finishDocumentLoadTime: Date.now() / 1000, finishLoadTime: Date.now() / 1000,
            firstPaintAfterLoadTime: 0, firstPaintTime: Date.now() / 1000,
            navigationType: 'Other', npnNegotiatedProtocol: 'h2',
            requestTime: Date.now() / 1000, startLoadTime: Date.now() / 1000,
            wasAlternateProtocolAvailable: false, wasFetchedViaSpdy: true, wasNpnNegotiated: true
          };
        };
      }
    } catch(e) {}

    // 4. Connection API
    try {
      if (navigator.connection) {
        Object.defineProperty(navigator.connection, 'rtt', { get: function(){ return 50; }, configurable: true });
        Object.defineProperty(navigator.connection, 'downlink', { get: function(){ return 10; }, configurable: true });
        Object.defineProperty(navigator.connection, 'effectiveType', { get: function(){ return '4g'; }, configurable: true });
        Object.defineProperty(navigator.connection, 'saveData', { get: function(){ return false; }, configurable: true });
      }
    } catch(e) {}

    // 5. Notification permission
    try {
      if (window.Notification) {
        Object.defineProperty(Notification, 'permission', {
          get: function(){ return 'default'; }, configurable: true
        });
      }
    } catch(e) {}
  `;
}

module.exports = { createStealthPlugin, getExtraStealthScript };
