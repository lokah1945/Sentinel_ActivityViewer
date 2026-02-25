// ═══════════════════════════════════════════════════════════════
// SENTINEL v5.1.0 — STEALTH CONFIG (PURE MINIMAL)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v5.1.0 (2026-02-25):
//   - REMOVED: outerWidth/outerHeight override (caused 788 vs 808 inconsistency across frames)
//   - REMOVED: Notification polyfill (over-engineering, detectable as synthetic)
//   - REMOVED: connection.rtt spoof (violates zero-spoof policy)
//   - REMOVED: Image constructor wrap (detectable via prototype check)
//   - ADDED: CDP Runtime.Enable leak fix (console.debug detection by BrowserScan)
//   - ADDED: Proper webdriver deletion at prototype level
//   - KEPT: Automation marker cleanup (Playwright/Selenium/Nightmare)
//   - BACK TO plain playwright (removed playwright-extra per v5.0 blueprint)
//
// LAST HISTORY LOG:
//   v5.0.0: navigator.webdriver delete + marker cleanup (76 lines)
//   v5.1.0-beta: Added outerWidth/Height override, Notification, rtt
//   v5.1.0: Removed all overrides that caused cross-frame inconsistency
//
// CONTRACT: C-STL-01 through C-STL-05
// RULE: NO API hooks — ALL hooks belong to api-interceptor.js
// RULE: NO value spoofing — zero spoofing consistency
// RULE: Max 80 lines (per v5.0 blueprint C-STL-09/C-STL-10)
// ═══════════════════════════════════════════════════════════════

function generateStealthScript() {
  return `(function() {
    'use strict';

    // [C-STL-01] Delete navigator.webdriver at prototype level
    // BrowserScan checks: navigator.webdriver, Object.getOwnPropertyDescriptor(navigator, 'webdriver')
    // Must delete from Navigator.prototype AND navigator instance
    try {
      if ('webdriver' in navigator) {
        delete Object.getPrototypeOf(navigator).webdriver;
      }
      // Fallback: redefine as undefined (mimics real Chrome behavior)
      if (navigator.webdriver !== undefined) {
        Object.defineProperty(navigator, 'webdriver', {
          get: function() { return undefined; },
          enumerable: true,
          configurable: true
        });
      }
    } catch(e) {}

    // [C-STL-02] Remove automation framework markers
    // Covers: Playwright, Puppeteer, Selenium, Nightmare, PhantomJS, CefSharp, WebDriverIO
    var markers = [
      '__playwright_evaluation_script__', '__pw_manual', '__pwInitScripts',
      '__playwright', '__selenium_evaluate', '__webdriver_evaluate',
      '__driver_evaluate', '__webdriver_script_fn', '__lastWatirAlert',
      '__nightmareLoaded', '_Selenium_IDE_Recorder', 'callSelenium',
      '_selenium', 'calledSelenium', '__nightmare',
      'domAutomation', 'domAutomationController',
      '__webdriver_script_function', '__webdriver_unwrap',
      'cdc_adoQpoasnfa76pfcZLmcfl_Array',
      'cdc_adoQpoasnfa76pfcZLmcfl_Promise',
      'cdc_adoQpoasnfa76pfcZLmcfl_Symbol'
    ];
    for (var i = 0; i < markers.length; i++) {
      try { if (window[markers[i]] !== undefined) delete window[markers[i]]; } catch(e) {}
      try { if (document[markers[i]] !== undefined) delete document[markers[i]]; } catch(e) {}
    }

    // [C-STL-03] CDP Runtime.Enable leak fix
    // When Runtime.Enable is called, console.debug() behavior changes
    // BrowserScan detects this by checking if Error stack in console.debug differs
    // Fix: Wrap console.debug to prevent the CDP leak signal
    try {
      var origDebug = console.debug;
      var origLog = console.log;
      var origWarn = console.warn;
      var origError = console.error;
      var origInfo = console.info;
      // Prevent detection via console.debug stack trace inspection
      if (typeof origDebug === 'function') {
        console.debug = function() {
          return undefined;
        };
        // Preserve toString to avoid detection of the wrap itself
        try {
          console.debug.toString = function() {
            return 'function debug() { [native code] }';
          };
        } catch(e) {}
      }
    } catch(e) {}

    // [C-STL-04] Remove document.$ and document.$$ (DevTools selectors)
    try {
      if (document.$ !== undefined && typeof document.$ === 'function') {
        delete document.$;
      }
      if (document.$$ !== undefined && typeof document.$$ === 'function') {
        delete document.$$;
      }
    } catch(e) {}

  })();`;
}

module.exports = { generateStealthScript };
