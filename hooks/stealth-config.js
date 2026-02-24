/**
 * Sentinel v4.3 — Stealth Configuration
 * Counter-fingerprinting measures for stealth mode
 * Injected via addInitScript ONLY (not CDP)
 */

function getStealthConfig() {
  return {
    webdriver: function() {
      return "Object.defineProperty(navigator, 'webdriver', { get: function() { return undefined; } });\n" +
        "if (navigator.__proto__) { Object.defineProperty(navigator.__proto__, 'webdriver', { get: function() { return undefined; } }); }";
    },

    chromeRuntime: function() {
      return "if (!window.chrome) { window.chrome = {}; }\n" +
        "if (!window.chrome.runtime) {\n" +
        "  window.chrome.runtime = {\n" +
        "    connect: function() { return { onMessage: { addListener: function(){} }, postMessage: function(){}, onDisconnect: { addListener: function(){} } }; },\n" +
        "    sendMessage: function(msg, cb) { if (cb) cb(undefined); },\n" +
        "    id: undefined,\n" +
        "    onConnect: { addListener: function(){} },\n" +
        "    onMessage: { addListener: function(){} }\n" +
        "  };\n" +
        "}";
    },

    permissions: function() {
      return "var _origQuery = navigator.permissions ? navigator.permissions.query : null;\n" +
        "if (_origQuery) {\n" +
        "  navigator.permissions.query = function(desc) {\n" +
        "    if (desc && desc.name === 'notifications') {\n" +
        "      return Promise.resolve({ state: 'prompt', onchange: null });\n" +
        "    }\n" +
        "    return _origQuery.call(navigator.permissions, desc);\n" +
        "  };\n" +
        "}";
    },

    plugins: function() {
      return "Object.defineProperty(navigator, 'plugins', {\n" +
        "  get: function() {\n" +
        "    return [\n" +
        "      { name: 'Chrome PDF Plugin', description: 'Portable Document Format', filename: 'internal-pdf-viewer', length: 1 },\n" +
        "      { name: 'Chrome PDF Viewer', description: '', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', length: 1 },\n" +
        "      { name: 'Native Client', description: '', filename: 'internal-nacl-plugin', length: 2 }\n" +
        "    ];\n" +
        "  }\n" +
        "});";
    },

    languages: function() {
      return "Object.defineProperty(navigator, 'languages', {\n" +
        "  get: function() { return ['en-US', 'en']; }\n" +
        "});\n" +
        "Object.defineProperty(navigator, 'language', {\n" +
        "  get: function() { return 'en-US'; }\n" +
        "});";
    },

    hardwareConcurrency: function() {
      return "Object.defineProperty(navigator, 'hardwareConcurrency', {\n" +
        "  get: function() { return 8; }\n" +
        "});";
    },

    deviceMemory: function() {
      return "if ('deviceMemory' in navigator) {\n" +
        "  Object.defineProperty(navigator, 'deviceMemory', {\n" +
        "    get: function() { return 8; }\n" +
        "  });\n" +
        "}";
    },

    platform: function() {
      return "Object.defineProperty(navigator, 'platform', {\n" +
        "  get: function() { return 'Win32'; }\n" +
        "});";
    },

    webglVendor: function() {
      return "var _origGetParam = WebGLRenderingContext.prototype.getParameter;\n" +
        "WebGLRenderingContext.prototype.getParameter = function(param) {\n" +
        "  var ext = this.getExtension('WEBGL_debug_renderer_info');\n" +
        "  if (ext) {\n" +
        "    if (param === ext.UNMASKED_VENDOR_WEBGL) return 'Google Inc. (Intel)';\n" +
        "    if (param === ext.UNMASKED_RENDERER_WEBGL) return 'ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.5)';\n" +
        "  }\n" +
        "  return _origGetParam.call(this, param);\n" +
        "};";
    },

    connection: function() {
      return "if (navigator.connection) {\n" +
        "  Object.defineProperty(navigator.connection, 'rtt', { get: function() { return 50; }, configurable: true });\n" +
        "  Object.defineProperty(navigator.connection, 'downlink', { get: function() { return 10; }, configurable: true });\n" +
        "  Object.defineProperty(navigator.connection, 'effectiveType', { get: function() { return '4g'; }, configurable: true });\n" +
        "  Object.defineProperty(navigator.connection, 'saveData', { get: function() { return false; }, configurable: true });\n" +
        "}";
    },

    batteryCharging: function() {
      return "if (navigator.getBattery) {\n" +
        "  var _origGetBattery = navigator.getBattery;\n" +
        "  navigator.getBattery = function() {\n" +
        "    return _origGetBattery.call(navigator).then(function(battery) {\n" +
        "      Object.defineProperty(battery, 'charging', { get: function() { return true; }, configurable: true });\n" +
        "      Object.defineProperty(battery, 'chargingTime', { get: function() { return 0; }, configurable: true });\n" +
        "      Object.defineProperty(battery, 'dischargingTime', { get: function() { return Infinity; }, configurable: true });\n" +
        "      Object.defineProperty(battery, 'level', { get: function() { return 1.0; }, configurable: true });\n" +
        "      return battery;\n" +
        "    });\n" +
        "  };\n" +
        "}";
    }
  };
}

function getExtraStealthScript() {
  var config = getStealthConfig();
  var parts = [];
  var keys = Object.keys(config);
  for (var i = 0; i < keys.length; i++) {
    parts.push(config[keys[i]]());
  }
  return parts.join('\n\n');
}

module.exports = { getStealthConfig, getExtraStealthScript };
