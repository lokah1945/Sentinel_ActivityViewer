/**
 * Sentinel v4.6.3 — Stealth Configuration (GHOST PROTOCOL)
 *
 * v4.6.3 CHANGES from v4.6.2:
 *   - Removed Permissions API patch (was interfering with interceptor's permissions hook)
 *   - Stealth is now MINIMAL: only webdriver removal + Playwright marker cleanup
 *   - Detection hooks belong to the interceptor, NOT stealth
 *   - No chrome.runtime/plugins/csi polyfills (persistent context provides them)
 *
 * PHILOSOPHY: Stealth should ONLY remove automation artifacts.
 *   It must NEVER wrap APIs that the interceptor needs to hook.
 */

function createStealthPlugin() { return null; }

function getExtraStealthScript(config) {
  return `
    // ═══ SENTINEL v4.6.3 GHOST PROTOCOL — MINIMAL STEALTH ═══
    (function() {
      'use strict';

      // ── 1. Remove navigator.webdriver ──
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

      // ── 2. Remove Playwright/CDP global markers ──
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

      // ── 3. Clean Error stack traces from automation paths ──
      try {
        if (Error.prepareStackTrace) {
          var _origPrepare = Error.prepareStackTrace;
          Error.prepareStackTrace = function(error, stack) {
            var result = _origPrepare ? _origPrepare(error, stack) : error.stack;
            if (typeof result === 'string') {
              result = result.replace(/playwright|puppeteer|chromium/gi, 'internal');
            }
            return result;
          };
        }
      } catch(e) {}

      // v4.6.3: NO Permissions API patch (was causing hook conflict with interceptor)
      // v4.6.3: NO chrome.runtime polyfill (persistent context provides real chrome object)
      // v4.6.3: NO chrome.csi/loadTimes (deprecated since Chrome 130+)
      // v4.6.3: NO plugins polyfill (--use-gl=desktop provides real plugin data)
    })();
  `;
}

module.exports = { createStealthPlugin, getExtraStealthScript };
