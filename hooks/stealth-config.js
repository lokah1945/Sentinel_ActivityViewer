// Sentinel v4.4.2 — Stealth Config (Layer 4)
// NO UA/fingerprint spoofing — only clean automation markers
// Purpose: remove obvious Playwright/automation signals so monitoring isn't detected

function getStealthPatches(options) {
  var opts = options || {};
  return `
(function() {
  'use strict';
  if (window.__SENTINEL_STEALTH_APPLIED) return;
  window.__SENTINEL_STEALTH_APPLIED = true;

  // === CLEANUP AUTOMATION MARKERS ONLY ===
  // These are Playwright/CDP artifacts, not fingerprint spoofing

  // 1. navigator.webdriver — Playwright sets this to true
  try {
    Object.defineProperty(navigator, 'webdriver', {
      get: function() { return false; },
      configurable: true
    });
  } catch(e) {}

  // 2. Remove cdc_ variables (CDP leak markers)
  try {
    var cdcKeys = [];
    for (var key in document) {
      if (key.match(/^\\$cdc_|^cdc_|^\\$chrome_/)) cdcKeys.push(key);
    }
    for (var i = 0; i < cdcKeys.length; i++) {
      try { delete document[cdcKeys[i]]; } catch(e) {}
    }
  } catch(e) {}

  // 3. Chrome runtime (missing in Playwright = detection signal)
  try {
    if (!window.chrome) {
      window.chrome = {};
    }
    if (!window.chrome.runtime) {
      window.chrome.runtime = {
        connect: function() { return {}; },
        sendMessage: function() {},
        id: undefined
      };
    }
  } catch(e) {}

  // 4. Remove "Chrome is being controlled by automated test software" flag
  try {
    if (navigator.permissions) {
      var origQuery = navigator.permissions.query;
      navigator.permissions.query = function(parameters) {
        if (parameters.name === 'notifications') {
          return Promise.resolve({ state: Notification.permission });
        }
        return origQuery.call(this, parameters);
      };
    }
  } catch(e) {}

  // 5. Plugins array — Playwright has empty plugins (detection signal)
  try {
    if (navigator.plugins.length === 0) {
      Object.defineProperty(navigator, 'plugins', {
        get: function() {
          return [
            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
            { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' }
          ];
        },
        configurable: true
      });
    }
  } catch(e) {}

  // 6. MimeTypes — consistent with plugins
  try {
    if (navigator.mimeTypes.length === 0) {
      Object.defineProperty(navigator, 'mimeTypes', {
        get: function() {
          return [
            { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: navigator.plugins[0] }
          ];
        },
        configurable: true
      });
    }
  } catch(e) {}

  // 7. Clean window.navigator.connection if missing
  try {
    if (!navigator.connection) {
      Object.defineProperty(navigator, 'connection', {
        get: function() {
          return {
            effectiveType: '4g',
            rtt: 50,
            downlink: 10,
            saveData: false,
            type: 'wifi'
          };
        },
        configurable: true
      });
    }
  } catch(e) {}

})();
`;
}

function getStealthPluginConfig() {
  // Return configuration for playwright-extra stealth plugin
  return {
    enabledEvasions: new Set([
      'chrome.app',
      'chrome.csi',
      'chrome.loadTimes',
      'chrome.runtime',
      'navigator.hardwareConcurrency',
      'navigator.languages',
      'navigator.permissions',
      'navigator.plugins',
      'navigator.webdriver',
      'sourceurl',
      'user-agent-override',
      'webgl.vendor',
      'window.outerdimensions',
      'media.codecs'
    ])
  };
}

module.exports = { getStealthPatches, getStealthPluginConfig };
