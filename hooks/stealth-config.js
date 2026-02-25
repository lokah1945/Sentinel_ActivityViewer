/**
 * Sentinel v4.6.2 — Stealth Configuration (GHOST PROTOCOL)
 *
 * v4.6.2 KEY CHANGES from v4.6.1:
 *
 *   REMOVED (were causing detection):
 *   - chrome.runtime polyfill → persistent context has real chrome.runtime
 *   - chrome.app polyfill → persistent context has real chrome.app
 *   - chrome.csi polyfill → only old Chrome pre-117 had this; adding to Chrome 145+ = MISMATCH
 *   - chrome.loadTimes polyfill → same, deprecated since Chrome 64
 *   - plugins polyfill → --use-gl=desktop + persistent context gives real plugins
 *
 *   KEPT (necessary):
 *   - navigator.webdriver removal → Playwright genuinely sets this
 *   - Playwright global markers removal → __playwright etc genuinely exist
 *   - Permissions API fix → real Playwright bug
 *
 *   PHILOSOPHY: "If the real browser already has it, don't fake it."
 *   Every polyfill is a detection vector. Persistent context + GPU flags
 *   give us real chrome.runtime, real plugins, real WebGL renderer.
 */

function createStealthPlugin() { return null; }

function getExtraStealthScript(config) {
  return `
    // ═══ SENTINEL v4.6.2 — GHOST PROTOCOL: MINIMAL CLEANUP ═══
    (function() {
      'use strict';

      // 1. Remove navigator.webdriver
      //    Playwright sets this to true. Real Chrome has it as false.
      try {
        var navProto = Object.getPrototypeOf(navigator);
        if (navProto) {
          try {
            Object.defineProperty(navProto, 'webdriver', {
              get: function() { return false; },
              configurable: true
            });
          } catch(e) {}
        }
        try {
          var instDesc = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
          if (instDesc) {
            Object.defineProperty(navigator, 'webdriver', {
              get: function() { return false; },
              configurable: true
            });
          }
        } catch(e) {}
      } catch(e) {}

      // 2. Remove Playwright global markers (only what actually exists)
      try {
        var markers = [
          '__playwright', '__pw_manual', '__PW_inspect', '__pwInitScripts',
          'cdc_adoQpoasnfa76pfcZLmcfl_Array',
          'cdc_adoQpoasnfa76pfcZLmcfl_Promise',
          'cdc_adoQpoasnfa76pfcZLmcfl_Symbol',
          'domAutomation', 'domAutomationController'
        ];
        for (var i = 0; i < markers.length; i++) {
          try { if (markers[i] in window) delete window[markers[i]]; } catch(e) {}
        }
      } catch(e) {}

      // 3. Permissions API consistency fix (real Playwright bug)
      try {
        var origQuery = navigator.permissions.query.bind(navigator.permissions);
        var patchedQuery = function(desc) {
          if (desc && desc.name === 'notifications') {
            return Promise.resolve({ state: Notification.permission, onchange: null });
          }
          return origQuery(desc);
        };
        Object.defineProperty(patchedQuery, 'toString', {
          value: function() { return 'function query() { [native code] }'; },
          writable: false, configurable: false
        });
        navigator.permissions.query = patchedQuery;
      } catch(e) {}

      // v4.6.2: NO chrome.runtime polyfill (persistent context provides it)
      // v4.6.2: NO chrome.csi/loadTimes (deprecated, mismatch on Chrome 145+)
      // v4.6.2: NO plugins polyfill (--use-gl=desktop provides real plugins)
    })();
  `;
}

module.exports = { createStealthPlugin, getExtraStealthScript };
