/**
 * Sentinel v4.4 — Stealth Configuration Manager
 * 
 * CRITICAL FIX from v4.3:
 *   v4.3 removed playwright-extra and puppeteer-extra-plugin-stealth,
 *   relying only on custom scripts. This missed dozens of stealth patches
 *   that the plugin handles (WebGL, fonts, iframe contentWindow, etc.)
 *   
 *   v4.4 restores playwright-extra as primary stealth engine (like v4.1)
 *   PLUS enhanced custom patches on top.
 *
 * Bot Detection Root Causes Addressed:
 *   1. navigator.webdriver = true → patched to undefined
 *   2. Missing chrome.runtime → full chrome object emulation
 *   3. Locale/language mismatch → configurable locale passthrough
 *   4. Empty plugin array → realistic Chrome plugin list
 *   5. WebGL SwiftShader → realistic GPU vendor/renderer
 *   6. Playwright automation markers → cleaned from window/document
 *   7. Permission API inconsistencies → normalized responses
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

/**
 * Get extra stealth script — comprehensive anti-bot patches
 * Configurable locale for Indonesia or any other locale
 */
function getExtraStealthScript(config) {
  config = config || {};
  var locale = config.locale || 'id';
  var languages = config.languages || "['id', 'en-US', 'en']";
  var platform = config.platform || 'Win32';
  var hwConcurrency = config.hardwareConcurrency || 8;
  var deviceMem = config.deviceMemory || 8;

  return `
    // ═══ SENTINEL v4.4 — EXTRA STEALTH LAYER ═══

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
              onDisconnect: { addListener: function(){}, removeListener: function(){} }
            };
          },
          sendMessage: function(msg, cb) { if (cb) cb(undefined); },
          id: undefined,
          onConnect: { addListener: function(){}, removeListener: function(){} },
          onMessage: { addListener: function(){}, removeListener: function(){} }
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
    } catch(e) {}

    // 3. Permissions API — realistic responses
    try {
      if (navigator.permissions) {
        var _origPermQuery = navigator.permissions.query.bind(navigator.permissions);
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
          return _origPermQuery(desc);
        };
      }
    } catch(e) {}

    // 4. Plugins — realistic Chrome plugin list
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

    // 5. Languages — configurable, consistent with context locale
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

    // 6. Hardware specs — realistic values
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

    // 7. WebGL vendor/renderer — realistic GPU
    try {
      var _origGetParam = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(param) {
        var ext = this.getExtension('WEBGL_debug_renderer_info');
        if (ext) {
          if (param === ext.UNMASKED_VENDOR_WEBGL) return 'Google Inc. (Intel)';
          if (param === ext.UNMASKED_RENDERER_WEBGL) return 'ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.5)';
        }
        return _origGetParam.call(this, param);
      };
    } catch(e) {}
    try {
      if (typeof WebGL2RenderingContext !== 'undefined') {
        var _origGetParam2 = WebGL2RenderingContext.prototype.getParameter;
        WebGL2RenderingContext.prototype.getParameter = function(param) {
          var ext = this.getExtension('WEBGL_debug_renderer_info');
          if (ext) {
            if (param === ext.UNMASKED_VENDOR_WEBGL) return 'Google Inc. (Intel)';
            if (param === ext.UNMASKED_RENDERER_WEBGL) return 'ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.5)';
          }
          return _origGetParam2.call(this, param);
        };
      }
    } catch(e) {}

    // 8. Connection API
    try {
      if (navigator.connection) {
        Object.defineProperty(navigator.connection, 'rtt', { get: function(){ return 50; }, configurable: true });
        Object.defineProperty(navigator.connection, 'downlink', { get: function(){ return 10; }, configurable: true });
        Object.defineProperty(navigator.connection, 'effectiveType', { get: function(){ return '4g'; }, configurable: true });
        Object.defineProperty(navigator.connection, 'saveData', { get: function(){ return false; }, configurable: true });
      }
    } catch(e) {}

    // 9. Battery API — consistent
    try {
      if (navigator.getBattery) {
        var _origGetBattery = navigator.getBattery;
        navigator.getBattery = function() {
          return _origGetBattery.call(navigator).then(function(battery) {
            Object.defineProperty(battery, 'charging', { get: function() { return true; }, configurable: true });
            Object.defineProperty(battery, 'chargingTime', { get: function() { return 0; }, configurable: true });
            Object.defineProperty(battery, 'dischargingTime', { get: function() { return Infinity; }, configurable: true });
            Object.defineProperty(battery, 'level', { get: function() { return 1.0; }, configurable: true });
            return battery;
          });
        };
      }
    } catch(e) {}

    // 10. Notification permission
    try {
      if (window.Notification) {
        Object.defineProperty(Notification, 'permission', {
          get: function(){ return 'default'; }, configurable: true
        });
      }
    } catch(e) {}

    // 11. Screen properties — consistent with viewport
    try {
      var _screenProps = {
        availWidth: 1920, availHeight: 1040,
        width: 1920, height: 1080,
        colorDepth: 24, pixelDepth: 24,
        availLeft: 0, availTop: 0
      };
      var _spKeys = Object.keys(_screenProps);
      for (var si = 0; si < _spKeys.length; si++) {
        (function(k, v) {
          try {
            Object.defineProperty(screen, k, {
              get: function() { return v; },
              configurable: true
            });
          } catch(e) {}
        })(_spKeys[si], _screenProps[_spKeys[si]]);
      }
    } catch(e) {}
  `;
}

module.exports = { createStealthPlugin, getExtraStealthScript };
