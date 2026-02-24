/**
 * Sentinel v4.4.2 — Stealth Configuration Manager
 * 
 * Restores playwright-extra + puppeteer-extra-plugin-stealth (like v3/v4.1).
 * Enhanced custom patches on top for comprehensive anti-bot evasion.
 * 
 * IMPORTANT: This script patches navigator/screen properties at INSTANCE level.
 * The api-interceptor.js MUST hook these AFTER stealth patches them,
 * wrapping the already-patched properties with monitoring.
 */

var StealthPlugin;
try {
  StealthPlugin = require('puppeteer-extra-plugin-stealth');
} catch(e) {
  StealthPlugin = null;
}

function createStealthPlugin(options) {
  options = options || {};
  if (!StealthPlugin) {
    console.warn('[STEALTH] puppeteer-extra-plugin-stealth not found, using custom patches only');
    return null;
  }
  var stealth = StealthPlugin();
  if (options.disableEvasions && Array.isArray(options.disableEvasions)) {
    for (var i = 0; i < options.disableEvasions.length; i++) {
      stealth.enabledEvasions.delete(options.disableEvasions[i]);
    }
  }
  return stealth;
}

function getExtraStealthScript(config) {
  config = config || {};
  var locale = config.locale || 'id';
  var languages = config.languages || "['id', 'en-US', 'en']";
  var platform = config.platform || 'Win32';
  var hwConcurrency = config.hardwareConcurrency || 8;
  var deviceMem = config.deviceMemory || 8;

  return `
    // ═══ SENTINEL v4.4.2 — EXTRA STEALTH LAYER ═══

    // 1. Deep webdriver cleanup
    try {
      Object.defineProperty(navigator, 'webdriver', {
        get: function() { return undefined; },
        configurable: true
      });
      if (navigator.__proto__) {
        Object.defineProperty(navigator.__proto__, 'webdriver', {
          get: function() { return undefined; },
          configurable: true
        });
      }
    } catch(e) {}

    // Remove ALL automation indicators
    try {
      var autoProps = [
        '__playwright', '__pw_manual', '__PW_inspect',
        '__selenium_evaluate', '__fxdriver_evaluate',
        '__driver_evaluate', '__webdriver_evaluate',
        '__selenium_unwrapped', '__webdriver_unwrapped',
        '_phantom', '__nightmare', '_selenium',
        'callPhantom', 'callSelenium',
        'domAutomation', 'domAutomationController',
        '_Recaptcha', '__webdriver_script_fn',
        '__driver_unwrapped', '__fxdriver_unwrapped'
      ];
      for (var i = 0; i < autoProps.length; i++) {
        try { delete window[autoProps[i]]; } catch(e) {}
        try { delete document[autoProps[i]]; } catch(e) {}
      }
    } catch(e) {}

    // 2. Chrome runtime — full emulation
    try {
      if (!window.chrome) window.chrome = {};
      if (!window.chrome.runtime) {
        window.chrome.runtime = {
          connect: function(info) {
            return {
              onMessage: { addListener: function(){}, removeListener: function(){} },
              postMessage: function(){},
              disconnect: function(){},
              onDisconnect: { addListener: function(){}, removeListener: function(){} }
            };
          },
          sendMessage: function() {},
          id: undefined,
          getManifest: function() { return {}; },
          getURL: function(path) { return ''; },
          onConnect: { addListener: function(){}, removeListener: function(){}, hasListener: function(){ return false; } },
          onMessage: { addListener: function(){}, removeListener: function(){}, hasListener: function(){ return false; } }
        };
      }
      if (!window.chrome.app) {
        window.chrome.app = {
          isInstalled: false,
          InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
          RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }
        };
      }
      if (!window.chrome.csi) {
        window.chrome.csi = function() {
          return { startE: Date.now(), onloadT: Date.now(), pageT: Date.now() - performance.timing.navigationStart, tran: 15 };
        };
      }
      if (!window.chrome.loadTimes) {
        window.chrome.loadTimes = function() {
          return {
            get commitLoadTime() { return performance.timing.responseStart / 1000; },
            get connectionInfo() { return 'h2'; },
            get finishDocumentLoadTime() { return performance.timing.domContentLoadedEventEnd / 1000; },
            get finishLoadTime() { return performance.timing.loadEventEnd / 1000; },
            get firstPaintAfterLoadTime() { return 0; },
            get firstPaintTime() { return performance.timing.domContentLoadedEventEnd / 1000; },
            get navigationType() { return 'Other'; },
            get npnNegotiatedProtocol() { return 'h2'; },
            get requestTime() { return performance.timing.requestStart / 1000; },
            get startLoadTime() { return performance.timing.navigationStart / 1000; },
            get wasAlternateProtocolAvailable() { return false; },
            get wasFetchedViaSpdy() { return true; },
            get wasNpnNegotiated() { return true; }
          };
        };
      }
    } catch(e) {}

    // 3. Navigator property spoofing for stealth
    try {
      Object.defineProperty(navigator, 'plugins', {
        get: function() {
          return [
            { name: 'Chrome PDF Plugin', description: 'Portable Document Format', filename: 'internal-pdf-viewer', length: 1 },
            { name: 'Chrome PDF Viewer', description: '', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', length: 1 },
            { name: 'Native Client', description: '', filename: 'internal-nacl-plugin', length: 2 }
          ];
        },
        configurable: true
      });
    } catch(e) {}

    try {
      Object.defineProperty(navigator, 'mimeTypes', {
        get: function() {
          return [
            { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
            { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' }
          ];
        },
        configurable: true
      });
    } catch(e) {}

    try {
      Object.defineProperty(navigator, 'languages', {
        get: function() { return ` + languages + `; },
        configurable: true
      });
      Object.defineProperty(navigator, 'language', {
        get: function() { return '` + locale + `'; },
        configurable: true
      });
    } catch(e) {}

    try {
      Object.defineProperty(navigator, 'hardwareConcurrency', {
        get: function() { return ` + String(hwConcurrency) + `; },
        configurable: true
      });
    } catch(e) {}

    try {
      if ('deviceMemory' in navigator) {
        Object.defineProperty(navigator, 'deviceMemory', {
          get: function() { return ` + String(deviceMem) + `; },
          configurable: true
        });
      }
    } catch(e) {}

    try {
      Object.defineProperty(navigator, 'platform', {
        get: function() { return '` + platform + `'; },
        configurable: true
      });
    } catch(e) {}

    // 4. Permissions API — return "prompt" for common permissions
    try {
      if (navigator.permissions) {
        var _origPermQuery = navigator.permissions.query.bind(navigator.permissions);
        var _promptPerms = [
          'notifications', 'push', 'midi', 'camera', 'microphone',
          'speaker', 'device-info', 'background-fetch', 'background-sync',
          'bluetooth', 'persistent-storage', 'ambient-light-sensor',
          'accelerometer', 'gyroscope', 'magnetometer', 'clipboard-read',
          'clipboard-write', 'payment-handler', 'idle-detection',
          'periodic-background-sync', 'screen-wake-lock', 'nfc'
        ];
        navigator.permissions.query = function(desc) {
          if (desc && _promptPerms.indexOf(desc.name) >= 0) {
            return Promise.resolve({ state: 'prompt', onchange: null });
          }
          return _origPermQuery(desc);
        };
        try { navigator.permissions.query.toString = function() { return 'function query() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    // 5. Connection API spoofing
    try {
      if (navigator.connection) {
        Object.defineProperty(navigator.connection, 'rtt', { get: function(){ return 50; }, configurable: true });
        Object.defineProperty(navigator.connection, 'downlink', { get: function(){ return 10; }, configurable: true });
        Object.defineProperty(navigator.connection, 'effectiveType', { get: function(){ return '4g'; }, configurable: true });
        Object.defineProperty(navigator.connection, 'saveData', { get: function(){ return false; }, configurable: true });
      }
    } catch(e) {}

    // 6. Battery API — realistic values
    try {
      if (navigator.getBattery) {
        var _origGetBattery = navigator.getBattery;
        navigator.getBattery = function() {
          return Promise.resolve({
            charging: true,
            chargingTime: 0,
            dischargingTime: Infinity,
            level: 0.87,
            addEventListener: function() {},
            removeEventListener: function() {}
          });
        };
        try { navigator.getBattery.toString = function() { return 'function getBattery() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    // 7. Notification permission — avoid "denied"
    try {
      if (window.Notification) {
        Object.defineProperty(Notification, 'permission', {
          get: function() { return 'default'; },
          configurable: true
        });
      }
    } catch(e) {}

    // 8. WebGL vendor/renderer — realistic values
    try {
      var origGetParam = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(param) {
        if (param === 37445) return 'Google Inc. (NVIDIA)';
        if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)';
        return origGetParam.call(this, param);
      };
      try { WebGLRenderingContext.prototype.getParameter.toString = function() { return 'function getParameter() { [native code] }'; }; } catch(e) {}
    } catch(e) {}

    // 9. Error stack trace cleanup
    try {
      var origError = Error;
      var origPrepare = Error.prepareStackTrace;
      Error.prepareStackTrace = function(error, stack) {
        var filtered = stack.filter(function(frame) {
          var file = frame.getFileName() || '';
          return file.indexOf('puppeteer') < 0 &&
                 file.indexOf('playwright') < 0 &&
                 file.indexOf('pptr:') < 0 &&
                 file.indexOf('__puppeteer') < 0;
        });
        if (origPrepare) return origPrepare(error, filtered);
        return error.toString() + '\\n' + filtered.map(function(f) {
          return '    at ' + f.toString();
        }).join('\\n');
      };
    } catch(e) {}

    // 10. iframe.contentWindow protection
    try {
      Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
        get: (function() {
          var origGet = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow').get;
          return function() {
            var w = origGet.call(this);
            if (w) {
              try { 
                Object.defineProperty(w, 'chrome', { get: function() { return window.chrome; }, configurable: true });
              } catch(e) {}
            }
            return w;
          };
        })()
      });
    } catch(e) {}
  `;
}

module.exports = { createStealthPlugin, getExtraStealthScript };
