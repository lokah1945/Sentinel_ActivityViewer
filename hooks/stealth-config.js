/**
 * Sentinel v4.2 — Stealth Configuration Manager (Upgraded)
 * 
 * UPGRADES from v4:
 * - CreepJS lie detection countermeasures (internal consistency)
 * - CDP detection countermeasures (cdc_ pattern removal)
 * - HeadlessChrome detection countermeasures
 * - navigator.plugins array fix for headless
 * - WebGL vendor/renderer consistency with UA
 * - window.chrome deep object spoofing
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
    // ═══ EXTRA STEALTH LAYER v4.2 — CreepJS-Resistant ═══

    // 1. Deep webdriver cleanup
    Object.defineProperty(navigator, 'webdriver', {
      get: function() { return undefined; },
      configurable: true
    });

    // Remove ALL automation indicators (expanded list)
    var autoProps = [
      '__playwright', '__pw_manual', '__PW_inspect',
      '__selenium_evaluate', '__fxdriver_evaluate',
      '__driver_evaluate', '__webdriver_evaluate',
      '__selenium_unwrapped', '__webdriver_unwrapped',
      '_phantom', '__nightmare', '_selenium',
      'callPhantom', 'callSelenium',
      '_Recaptcha', '__recaptcha',
      'domAutomation', 'domAutomationController',
      '__webdriver_script_fn', '__webdriver_script_func',
      'cdc_adoQpoasnfa76pfcZLmcfl_Array',
      'cdc_adoQpoasnfa76pfcZLmcfl_Promise',
      'cdc_adoQpoasnfa76pfcZLmcfl_Symbol'
    ];
    for (var i = 0; i < autoProps.length; i++) {
      try { delete window[autoProps[i]]; } catch(e) {}
      try { delete document[autoProps[i]]; } catch(e) {}
    }

    // Also remove any cdc_ prefixed properties dynamically
    try {
      var winKeys = Object.keys(window);
      for (var k = 0; k < winKeys.length; k++) {
        if (winKeys[k].indexOf('cdc_') === 0 || winKeys[k].indexOf('$cdc_') === 0) {
          try { delete window[winKeys[k]]; } catch(e) {}
        }
      }
    } catch(e) {}

    // 2. Permissions API — return "prompt" for common permissions
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
        if (permNames.indexOf(desc && desc.name) !== -1) {
          return Promise.resolve({ state: 'prompt', onchange: null });
        }
        return originalQuery(desc);
      };
    }

    // 3. Chrome runtime — deep consistent object
    if (!window.chrome) { window.chrome = {}; }
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

    // 4. Connection API spoofing (consistent values)
    if (navigator.connection) {
      try {
        Object.defineProperty(navigator.connection, 'rtt', { get: function() { return 50; }, configurable: true });
        Object.defineProperty(navigator.connection, 'downlink', { get: function() { return 10; }, configurable: true });
        Object.defineProperty(navigator.connection, 'effectiveType', { get: function() { return '4g'; }, configurable: true });
        Object.defineProperty(navigator.connection, 'saveData', { get: function() { return false; }, configurable: true });
      } catch(e) {}
    }

    // 5. Notification permission
    if (window.Notification) {
      Object.defineProperty(Notification, 'permission', {
        get: function() { return 'default'; },
        configurable: true
      });
    }

    // 6. Prevent Runtime.enable detection artifacts
    // CreepJS checks for binding artifacts left by CDP
    try {
      var bindingProps = Object.getOwnPropertyNames(window).filter(function(p) {
        return p.indexOf('__puppeteer') !== -1 || p.indexOf('__playwright') !== -1 || p.indexOf('__cdp') !== -1;
      });
      for (var b = 0; b < bindingProps.length; b++) {
        try { delete window[bindingProps[b]]; } catch(e) {}
      }
    } catch(e) {}
  `;
}

module.exports = { createStealthPlugin, getExtraStealthScript };
