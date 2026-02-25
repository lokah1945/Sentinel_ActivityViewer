// ═══════════════════════════════════════════════════════════════
//  SENTINEL v5.0.0 — STEALTH CONFIG (MINIMAL)
//  Contract: C-STL-01 through C-STL-10
//  RULE: This file must NEVER exceed 80 lines.
//  RULE: NO API hooks here — ALL hooks belong to interceptor.
//  RULE: NO spoofing — zero spoofing consistency philosophy.
// ═══════════════════════════════════════════════════════════════

function generateStealthScript() {
  return `(function() {
    'use strict';
    // [C-STL-01] Remove navigator.webdriver (Playwright artifact)
    try {
      Object.defineProperty(navigator, 'webdriver', {
        get: function() { return undefined; },
        enumerable: true, configurable: true
      });
    } catch(e) {}

    // [C-STL-02] Remove Playwright internal markers
    var markers = [
      '__playwright_evaluation_script__',
      '__pw_manual',
      '__pwInitScripts',
      '__playwright',
      '__selenium_evaluate',
      '__webdriver_evaluate',
      '__driver_evaluate',
      '__webdriver_script_fn',
      '__lastWatirAlert',
      '__nightmareLoaded',
      '_Selenium_IDE_Recorder',
      'callSelenium',
      '_selenium',
      'calledSelenium',
      '__nightmare',
      'domAutomation',
      'domAutomationController'
    ];
    for (var i = 0; i < markers.length; i++) {
      try { delete window[markers[i]]; } catch(e) {}
      try { delete document[markers[i]]; } catch(e) {}
    }

    // Chrome polyfill — only if persistent context doesn't provide them
    if (!window.chrome) { window.chrome = {}; }
    if (!window.chrome.runtime) {
      Object.defineProperty(window.chrome, 'runtime', {
        get: function() { return { OnInstalledReason: { CHROME_UPDATE: 'chrome_update', INSTALL: 'install', SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update' }, PlatformArch: {}, PlatformNaclArch: {}, PlatformOs: {}, RequestUpdateCheckStatus: {}, connect: function() { throw new Error('Could not establish connection.'); }, id: undefined, sendMessage: function() { throw new Error('Could not establish connection.'); } }; },
        enumerable: true, configurable: true
      });
    }
    if (!window.chrome.csi) {
      window.chrome.csi = function() { return { startE: Date.now(), onloadT: Date.now(), pageT: Math.random() * 1000, tran: 15 }; };
    }
    if (!window.chrome.loadTimes) {
      window.chrome.loadTimes = function() { return { commitLoadTime: Date.now() / 1000, connectionInfo: 'h2', finishDocumentLoadTime: Date.now() / 1000 + 0.1, finishLoadTime: Date.now() / 1000 + 0.2, firstPaintAfterLoadTime: 0, firstPaintTime: Date.now() / 1000 + 0.05, navigationType: 'Other', npnNegotiatedProtocol: 'h2', requestTime: Date.now() / 1000 - 0.3, startLoadTime: Date.now() / 1000 - 0.2, wasAlternateProtocolAvailable: false, wasFetchedViaSpdy: true, wasNpnNegotiated: true }; };
    }
  })();`;
}

module.exports = { generateStealthScript };
