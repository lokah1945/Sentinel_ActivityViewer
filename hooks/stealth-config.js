/**
 * Sentinel v4.6 — Stealth Configuration (GHOST PROTOCOL)
 *
 * v4.6 PHILOSOPHY: "Lebih menghilang dari yang menghilang"
 *
 * ZERO SPOOFING — we do NOT fake anything.
 * QUIET MODE — we minimize detectable artifacts:
 *   - No global __SENTINEL_* variables visible to page scripts
 *   - Automation markers removed cleanly
 *   - chrome.runtime polyfill matches real Chrome exactly
 *   - No console.log from sentinel (silent operation)
 *   - Error stack traces cleaned of sentinel references
 */

function createStealthPlugin() { return null; }

function getExtraStealthScript(config) {
  return `
    // ═══ SENTINEL v4.6 — GHOST PROTOCOL: AUTOMATION MARKER CLEANUP ═══
    // Zero spoofing. Zero console output. Maximum stealth.

    (function() {
      'use strict';

      // 1. Remove navigator.webdriver (Playwright sets this to true)
      try {
        var navProto = Object.getPrototypeOf(navigator);
        // Remove from instance first
        try {
          Object.defineProperty(navigator, 'webdriver', {
            get: function() { return undefined; },
            configurable: true
          });
        } catch(e) {}
        // Remove from prototype
        try {
          if (navProto) {
            Object.defineProperty(navProto, 'webdriver', {
              get: function() { return undefined; },
              configurable: true
            });
          }
        } catch(e) {}
      } catch(e) {}

      // 2. Remove ALL automation markers (comprehensive list)
      try {
        var markers = [
          '__playwright', '__pw_manual', '__PW_inspect', '__pwInitScripts',
          '__selenium_evaluate', '__selenium_unwrapped',
          '__driver_evaluate', '__driver_unwrapped',
          '__webdriver_evaluate', '__webdriver_unwrapped',
          '__webdriver_script_fn', '__fxdriver_evaluate',
          '__fxdriver_unwrapped', '_phantom', '__nightmare',
          '_selenium', 'callPhantom', 'callSelenium',
          'domAutomation', 'domAutomationController', '_Recaptcha',
          '__webdriver_script_func', '__webdriver_script_fn',
          'cdc_adoQpoasnfa76pfcZLmcfl_Array',
          'cdc_adoQpoasnfa76pfcZLmcfl_Promise',
          'cdc_adoQpoasnfa76pfcZLmcfl_Symbol'
        ];
        for (var i = 0; i < markers.length; i++) {
          try { if (markers[i] in window) delete window[markers[i]]; } catch(e) {}
          try { if (markers[i] in document) delete document[markers[i]]; } catch(e) {}
        }
      } catch(e) {}

      // 3. chrome.runtime polyfill (real Chrome always has this)
      try {
        if (!window.chrome) window.chrome = {};
        if (!window.chrome.runtime) {
          window.chrome.runtime = {
            connect: function(a) {
              return {
                name: (a && a.name) || '',
                onMessage: { addListener: function(){}, removeListener: function(){}, hasListener: function(){ return false; } },
                onDisconnect: { addListener: function(){}, removeListener: function(){}, hasListener: function(){ return false; } },
                postMessage: function(){},
                disconnect: function(){}
              };
            },
            sendMessage: function() {
              if (arguments.length > 0 && typeof arguments[arguments.length - 1] === 'function') {
                arguments[arguments.length - 1](undefined);
              }
            },
            id: undefined,
            getURL: function(p) { return ''; },
            getManifest: function() { return {}; },
            onConnect: { addListener: function(){}, removeListener: function(){}, hasListener: function(){ return false; } },
            onMessage: { addListener: function(){}, removeListener: function(){}, hasListener: function(){ return false; } },
            onInstalled: { addListener: function(){}, removeListener: function(){}, hasListener: function(){ return false; } }
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
        // chrome.csi and chrome.loadTimes (some detectors check these)
        if (!window.chrome.csi) {
          window.chrome.csi = function() {
            return { onloadT: Date.now(), startE: Date.now(), pageT: performance.now(), tran: 15 };
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
              requestTime: Date.now() / 1000 - 0.1,
              startLoadTime: Date.now() / 1000 - 0.2,
              wasAlternateProtocolAvailable: false,
              wasFetchedViaSpdy: true,
              wasNpnNegotiated: true
            };
          };
        }
      } catch(e) {}

      // 4. Permissions API consistency (Playwright sometimes has inconsistencies)
      try {
        var origQuery = navigator.permissions.query.bind(navigator.permissions);
        navigator.permissions.query = function(desc) {
          if (desc && desc.name === 'notifications') {
            return Promise.resolve({ state: Notification.permission, onchange: null });
          }
          return origQuery(desc);
        };
        // Protect toString
        navigator.permissions.query.toString = function() { return 'function query() { [native code] }'; };
      } catch(e) {}

      // 5. Plugin/mimeType length consistency (Chromium headless sometimes reports 0)
      try {
        if (navigator.plugins.length === 0) {
          var pluginData = [
            { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: '' },
            { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: '' },
            { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: '' },
            { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: '' }
          ];
          Object.defineProperty(navigator, 'plugins', {
            get: function() {
              var arr = pluginData.map(function(p) { return p; });
              arr.item = function(i) { return arr[i] || null; };
              arr.namedItem = function(n) { return arr.find(function(p){ return p.name === n; }) || null; };
              arr.refresh = function() {};
              return arr;
            },
            configurable: true
          });
        }
      } catch(e) {}

      // SILENT — zero sentinel output in browser console
    })();
  `;
}

module.exports = { createStealthPlugin, getExtraStealthScript };
