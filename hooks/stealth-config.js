// ═══════════════════════════════════════════════════════════════
// SENTINEL v6.0.0 — STEALTH CONFIG (PATCHRIGHT EDITION)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.0.0 (2026-02-25):
//   FROM v5.1.0-Final:
//   - REMOVED: console.debug CDP leak wrap (Patchright handles Runtime.enable leak)
//   - REMOVED: console.debug toString masking (no longer needed)
//   - KEPT: navigator.webdriver deletion at prototype level
//   - KEPT: Automation marker cleanup (30+ markers)
//   - KEPT: DevTools selector cleanup (document.$, document.$$)
//
// LAST HISTORY LOG:
//   v5.0.0: navigator.webdriver delete + marker cleanup (76 lines)
//   v5.1.0-beta: Added outerWidth/Height override, Notification, rtt
//   v5.1.0: Removed overrides, added CDP console.debug leak fix
//   v5.1.0-Final: Removed all cross-frame inconsistency overrides
//   v6.0.0: Removed console.debug wrap (Patchright eliminates CDP leaks)
//
// CONTRACT: C-STL-01 through C-STL-04
// RULE: NO API hooks — ALL hooks belong to api-interceptor.js
// RULE: NO value spoofing — zero spoofing consistency
// ═══════════════════════════════════════════════════════════════

function generateStealthScript() {
  return `(function() {
    'use strict';

    // [C-STL-01] Delete navigator.webdriver at prototype level
    try {
      if ('webdriver' in navigator) {
        delete Object.getPrototypeOf(navigator).webdriver;
      }
      if (navigator.webdriver !== undefined) {
        Object.defineProperty(navigator, 'webdriver', {
          get: function() { return undefined; },
          enumerable: true,
          configurable: true
        });
      }
    } catch(e) {}

    // [C-STL-02] Remove automation framework markers
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

    // [C-STL-03] — REMOVED in v6.0.0
    // Patchright handles Runtime.enable and Console.enable leaks at CDP level.
    // No console.debug wrap or toString masking needed.

    // [C-STL-04] DevTools selectors cleanup
    try {
      if (document.$ !== undefined && typeof document.$ === 'function') delete document.$;
      if (document.$$ !== undefined && typeof document.$$ === 'function') delete document.$$;
    } catch(e) {}

  })();`;
}

module.exports = { generateStealthScript };
