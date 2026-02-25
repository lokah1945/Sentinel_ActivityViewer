// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — COMPREHENSIVE API INTERCEPTOR
//  42 Categories | 110+ Hook Points | ZERO Spoofing
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - PURE NEW: Full rewrite from v5.0.0 proven base
//   - 42 detection categories (was 0 in v6.3/v6.4 — REG-020)
//   - 110+ hook points covering ALL known fingerprinting vectors
//   - Uses Shield utilities (hookFunction, hookGetter, smartHookGetter)
//   - ZERO spoofing: hooks ONLY LOG values, never modify returns
//   - Push telemetry via SENTINEL_PUSH binding (REG-015: 500ms interval)
//   - BOOT-OK mandatory signal (REG-023)
//   - Filtered createElement: FP tags only (REG-024)
//   - Filtered property-enum: navigator/screen only (REG-025)
//   - Network dual-log: exfiltration + network (REG-005)
//   - Battery API hook restored (REG-003)
//   - matchMedia hook restored (REG-004)
//   - Event listener monitoring restored (REG-002)
//   - frameattached/framenavigated re-injection support
//   - FIX: smartHookGetter prevents prototype shadow (REG-010)
//   - FIX: hookGetterSetter for document.cookie read/write
//   - FIX: evalWithTimeout wrapper for safe evaluation (REG-019)
//
// LAST HISTORY LOG:
//   v6.4.0: REMOVED (zero injection) — 313 events, 19 categories
//   v6.3.0: REMOVED (zero injection) — 328 events
//   v6.2.0: Present but broken (rebrowser conflict) — 7 events
//   v6.1.0: Present and working — 1,799 events, 22 categories
//   v5.0.0: Present with 42 categories, 110+ hooks — proven working
//   v7.0.0: Restored and upgraded from v5.0.0
// ═══════════════════════════════════════════════════════════════

function getInterceptorScript(config) {
  var timeout = (config && config.timeout) ? config.timeout : 30000;
  var maxEvents = (config && config.maxEvents) ? config.maxEvents : 50000;
  var pushInterval = (config && config.pushInterval) ? config.pushInterval : 500;

  return `
(function() {
  'use strict';

  // ═══ SENTINEL DATA STORE ═══
  // REG-011: Consistent SENTINEL_DATA naming
  var _SENTINEL_DATA = {
    events: [],
    startTime: Date.now(),
    maxEvents: ${maxEvents},
    pushInterval: ${pushInterval},
    timeout: ${timeout},
    categoriesMonitored: 42,
    hookPoints: 0,
    version: 'v7.0.0',
    bootTime: 0,
    frameType: (window !== window.top) ? 'iframe' : 'top'
  };

  // Non-enumerable sentinel data (Quiet Mode — REG-017)
  Object.defineProperty(window, '_SENTINEL_DATA', {
    value: _SENTINEL_DATA,
    writable: true,
    enumerable: false,
    configurable: false
  });

  // ═══ CORE LOG FUNCTION ═══
  function log(category, api, detail, risk) {
    if (_SENTINEL_DATA.events.length >= _SENTINEL_DATA.maxEvents) return;
    var origin = 'unknown';
    try { origin = location.origin; } catch(e) {}
    _SENTINEL_DATA.events.push({
      ts: Date.now() - _SENTINEL_DATA.startTime,
      cat: category,
      api: api,
      detail: (typeof detail === 'object') ? JSON.stringify(detail).slice(0, 200) : String(detail || '').slice(0, 200),
      risk: risk || 'low',
      origin: origin,
      frame: _SENTINEL_DATA.frameType
    });
  }

  // ═══ SHIELD UTILITY REFERENCES ═══
  var H = window.__SENTINEL_HOOKS__;
  if (!H) {
    // Shield not loaded — create minimal fallbacks
    H = {
      hookFunction: function(obj, prop, handler) {
        if (!obj || typeof obj[prop] !== 'function') return false;
        var orig = obj[prop];
        var origStr = Function.prototype.toString.call(orig);
        obj[prop] = function() { handler.apply(this, arguments); return orig.apply(this, arguments); };
        obj[prop].toString = function() { return origStr; };
        try { Object.defineProperty(obj[prop], 'name', { value: orig.name, configurable: true }); } catch(e) {}
        return true;
      },
      hookGetter: function(obj, prop, handler) {
        if (!obj) return false;
        var desc = null; var t = obj;
        while (t && !desc) { desc = Object.getOwnPropertyDescriptor(t, prop); if (!desc) t = Object.getPrototypeOf(t); }
        if (!desc) return false;
        var oGet = desc.get; var oVal = desc.value;
        if (oGet) { Object.defineProperty(obj, prop, { get: function() { var v = oGet.call(this); handler(v); return v; }, set: desc.set, enumerable: desc.enumerable, configurable: true }); }
        else if ('value' in desc) { Object.defineProperty(obj, prop, { get: function() { handler(oVal); return oVal; }, enumerable: desc.enumerable, configurable: true }); }
        return true;
      },
      hookGetterSetter: function(obj, prop, gH, sH) {
        if (!obj) return false;
        var desc = Object.getOwnPropertyDescriptor(obj, prop);
        if (!desc && obj.__proto__) desc = Object.getOwnPropertyDescriptor(obj.__proto__, prop);
        if (!desc) return false;
        var ng = desc.get, ns = desc.set, nd = { enumerable: desc.enumerable, configurable: true };
        if (ng) nd.get = function() { var v = ng.call(this); gH(v); return v; };
        if (ns) nd.set = function(v) { sH(v); return ns.call(this, v); };
        Object.defineProperty(obj, prop, nd);
        return true;
      },
      smartHookGetter: function(inst, proto, prop, handler) {
        var id = Object.getOwnPropertyDescriptor(inst, prop);
        if (id) return H.hookGetter(inst, prop, handler);
        if (proto) { var pd = Object.getOwnPropertyDescriptor(proto, prop); if (pd) return H.hookGetter(proto, prop, handler); }
        if (prop in inst) return H.hookGetter(inst, prop, handler);
        return false;
      }
    };
  }

  var hookCount = 0;
  function hf(o,p,h) { if (H.hookFunction(o,p,h)) hookCount++; }
  function hg(o,p,h) { if (H.hookGetter(o,p,h)) hookCount++; }
  function hgs(o,p,g,s) { if (H.hookGetterSetter(o,p,g,s)) hookCount++; }
  function shg(i,pr,p,h) { if (H.smartHookGetter(i,pr,p,h)) hookCount++; }

  // ═══════════════════════════════════════════
  //  CATEGORY 1: CANVAS FINGERPRINTING (HIGH)
  // ═══════════════════════════════════════════
  if (typeof HTMLCanvasElement !== 'undefined') {
    hf(HTMLCanvasElement.prototype, 'toDataURL', function() {
      log('canvas', 'toDataURL', { type: arguments[0] || 'image/png' }, 'high');
    });
    hf(HTMLCanvasElement.prototype, 'toBlob', function() {
      log('canvas', 'toBlob', { type: arguments[1] || 'image/png' }, 'high');
    });
  }
  if (typeof CanvasRenderingContext2D !== 'undefined') {
    hf(CanvasRenderingContext2D.prototype, 'getImageData', function() {
      log('canvas', 'getImageData', { x: arguments[0], y: arguments[1], w: arguments[2], h: arguments[3] }, 'high');
    });
    hf(CanvasRenderingContext2D.prototype, 'fillText', function() {
      log('canvas', 'fillText', { text: String(arguments[0] || '').slice(0, 50), font: this.font }, 'medium');
    });
    hf(CanvasRenderingContext2D.prototype, 'measureText', function() {
      log('font-detection', 'measureText', { text: String(arguments[0] || '').slice(0, 30), font: this.font }, 'high');
    });
    hf(CanvasRenderingContext2D.prototype, 'isPointInPath', function() {
      log('canvas', 'isPointInPath', {}, 'medium');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 2: WEBGL FINGERPRINTING (HIGH)
  // ═══════════════════════════════════════════
  function hookWebGLProto(proto, ctxName) {
    if (!proto) return;
    hf(proto, 'getParameter', function() {
      log('webgl', 'getParameter', { param: arguments[0], ctx: ctxName }, 'high');
    });
    hf(proto, 'getExtension', function() {
      log('webgl', 'getExtension', { ext: arguments[0], ctx: ctxName }, 'medium');
    });
    hf(proto, 'getSupportedExtensions', function() {
      log('webgl', 'getSupportedExtensions', { ctx: ctxName }, 'medium');
    });
    hf(proto, 'getShaderPrecisionFormat', function() {
      log('webgl', 'getShaderPrecisionFormat', { ctx: ctxName }, 'high');
    });
    hf(proto, 'readPixels', function() {
      log('webgl', 'readPixels', { ctx: ctxName }, 'high');
    });
  }
  if (typeof WebGLRenderingContext !== 'undefined') hookWebGLProto(WebGLRenderingContext.prototype, 'webgl');
  if (typeof WebGL2RenderingContext !== 'undefined') hookWebGLProto(WebGL2RenderingContext.prototype, 'webgl2');

  // ═══════════════════════════════════════════
  //  CATEGORY 3: AUDIO FINGERPRINTING (CRITICAL)
  // ═══════════════════════════════════════════
  if (typeof AudioContext !== 'undefined' || typeof webkitAudioContext !== 'undefined') {
    var AC = typeof AudioContext !== 'undefined' ? AudioContext : webkitAudioContext;
    hf(AC.prototype, 'createOscillator', function() {
      log('audio', 'createOscillator', {}, 'critical');
    });
    hf(AC.prototype, 'createDynamicsCompressor', function() {
      log('audio', 'createDynamicsCompressor', {}, 'critical');
    });
    hf(AC.prototype, 'createAnalyser', function() {
      log('audio', 'createAnalyser', {}, 'high');
    });
    shg(AC.prototype, null, 'baseLatency', function(val) {
      log('audio', 'baseLatency', { val: val }, 'high');
    });
  }
  if (typeof OfflineAudioContext !== 'undefined') {
    hf(OfflineAudioContext.prototype, 'startRendering', function() {
      log('audio', 'startRendering', {}, 'critical');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 4: FONT DETECTION (CRITICAL)
  // ═══════════════════════════════════════════
  if (typeof Element !== 'undefined') {
    hf(Element.prototype, 'getBoundingClientRect', function() {
      log('font-detection', 'getBoundingClientRect', {}, 'high');
    });
  }
  if (typeof document !== 'undefined' && document.fonts) {
    hf(document.fonts, 'check', function() {
      log('font-detection', 'fonts.check', { font: arguments[0] }, 'critical');
    });
  }
  if (typeof FontFace !== 'undefined') {
    hf(FontFace.prototype, 'load', function() {
      log('font-detection', 'FontFace.load', {}, 'critical');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 5: NAVIGATOR FINGERPRINTING (HIGH)
  //  REG-010: smartHookGetter for 19 properties
  // ═══════════════════════════════════════════
  var navProps = [
    'userAgent', 'platform', 'vendor', 'language', 'languages',
    'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints',
    'appVersion', 'appName', 'appCodeName', 'product',
    'productSub', 'vendorSub', 'oscpu', 'cpuClass',
    'doNotTrack', 'cookieEnabled', 'pdfViewerEnabled'
  ];
  navProps.forEach(function(prop) {
    shg(navigator, Navigator.prototype, prop, function(val) {
      log('fingerprint', prop, { val: typeof val === 'object' ? JSON.stringify(val) : val }, 'high');
    });
  });

  // ═══════════════════════════════════════════
  //  CATEGORY 6: SCREEN INFO (MEDIUM)
  // ═══════════════════════════════════════════
  var screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
  screenProps.forEach(function(prop) {
    shg(screen, Screen.prototype, prop, function(val) {
      log('screen', prop, { val: val }, 'medium');
    });
  });
  shg(window, Window.prototype, 'devicePixelRatio', function(val) {
    log('screen', 'devicePixelRatio', { val: val }, 'medium');
  });
  shg(window, Window.prototype, 'outerWidth', function(val) {
    log('screen', 'outerWidth', { val: val }, 'medium');
  });
  shg(window, Window.prototype, 'outerHeight', function(val) {
    log('screen', 'outerHeight', { val: val }, 'medium');
  });
  shg(window, Window.prototype, 'innerWidth', function(val) {
    log('screen', 'innerWidth', { val: val }, 'low');
  });
  shg(window, Window.prototype, 'innerHeight', function(val) {
    log('screen', 'innerHeight', { val: val }, 'low');
  });

  // ═══════════════════════════════════════════
  //  CATEGORY 7: STORAGE (MEDIUM)
  //  REG: hookGetterSetter for cookie dual-hook
  // ═══════════════════════════════════════════
  hgs(document, 'cookie',
    function(val) { log('storage', 'cookie.get', { len: (val || '').length }, 'medium'); },
    function(val) { log('storage', 'cookie.set', { val: String(val).slice(0, 100) }, 'medium'); }
  );
  if (typeof Storage !== 'undefined') {
    hf(Storage.prototype, 'getItem', function() {
      log('storage', 'localStorage.getItem', { key: arguments[0] }, 'medium');
    });
    hf(Storage.prototype, 'setItem', function() {
      log('storage', 'localStorage.setItem', { key: arguments[0] }, 'medium');
    });
    hf(Storage.prototype, 'removeItem', function() {
      log('storage', 'localStorage.removeItem', { key: arguments[0] }, 'low');
    });
  }
  if (typeof indexedDB !== 'undefined') {
    hf(indexedDB, 'open', function() {
      log('storage', 'indexedDB.open', { name: arguments[0] }, 'medium');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 8: NETWORK IN-PAGE (MEDIUM)
  //  REG-005: Dual-log exfiltration + network
  // ═══════════════════════════════════════════
  if (typeof fetch === 'function') {
    hf(window, 'fetch', function() {
      var url = arguments[0];
      if (typeof url === 'object' && url.url) url = url.url;
      log('network', 'fetch', { url: String(url).slice(0, 200) }, 'medium');
      log('exfiltration', 'fetch', { url: String(url).slice(0, 200) }, 'high');
    });
  }
  if (typeof XMLHttpRequest !== 'undefined') {
    hf(XMLHttpRequest.prototype, 'open', function() {
      log('network', 'XHR.open', { method: arguments[0], url: String(arguments[1] || '').slice(0, 200) }, 'medium');
      log('exfiltration', 'XHR.open', { method: arguments[0], url: String(arguments[1] || '').slice(0, 200) }, 'high');
    });
    hf(XMLHttpRequest.prototype, 'send', function() {
      var bodyLen = arguments[0] ? String(arguments[0]).length : 0;
      log('network', 'XHR.send', { bodyLen: bodyLen }, 'medium');
    });
  }
  if (typeof EventSource !== 'undefined') {
    var origES = EventSource;
    window.EventSource = function(url, opts) {
      log('network', 'EventSource', { url: String(url).slice(0, 200) }, 'medium');
      return new origES(url, opts);
    };
    window.EventSource.prototype = origES.prototype;
    window.EventSource.toString = function() { return 'function EventSource() { [native code] }'; };
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 9: PERFORMANCE TIMING (MEDIUM)
  // ═══════════════════════════════════════════
  if (typeof Performance !== 'undefined') {
    hf(Performance.prototype, 'now', function() {
      log('perf-timing', 'performance.now', {}, 'medium');
    });
    hf(Performance.prototype, 'mark', function() {
      log('perf-timing', 'performance.mark', { name: arguments[0] }, 'medium');
    });
    hf(Performance.prototype, 'measure', function() {
      log('perf-timing', 'performance.measure', { name: arguments[0] }, 'medium');
    });
    hf(Performance.prototype, 'getEntriesByType', function() {
      log('perf-timing', 'getEntriesByType', { type: arguments[0] }, 'medium');
    });
    hf(Performance.prototype, 'getEntriesByName', function() {
      log('perf-timing', 'getEntriesByName', { name: arguments[0] }, 'medium');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 10: MEDIA DEVICES (CRITICAL)
  // ═══════════════════════════════════════════
  if (typeof navigator.mediaDevices !== 'undefined') {
    hf(navigator.mediaDevices, 'enumerateDevices', function() {
      log('media-devices', 'enumerateDevices', {}, 'critical');
    });
    hf(navigator.mediaDevices, 'getUserMedia', function() {
      log('media-devices', 'getUserMedia', { constraints: JSON.stringify(arguments[0]).slice(0, 100) }, 'critical');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 11: DOM PROBING (MEDIUM)
  //  REG-024: Filtered createElement (FP tags only)
  // ═══════════════════════════════════════════
  var fpTags = ['canvas', 'iframe', 'audio', 'video', 'object', 'embed', 'script', 'link', 'img'];
  hf(Document.prototype, 'createElement', function() {
    var tag = String(arguments[0] || '').toLowerCase();
    if (fpTags.indexOf(tag) !== -1) {
      log('dom-probe', 'createElement', { tag: tag }, 'medium');
    }
  });
  if (typeof MutationObserver !== 'undefined') {
    var origMO = MutationObserver;
    window.MutationObserver = function(cb) {
      log('dom-probe', 'MutationObserver', {}, 'medium');
      return new origMO(cb);
    };
    window.MutationObserver.prototype = origMO.prototype;
    window.MutationObserver.toString = function() { return 'function MutationObserver() { [native code] }'; };
  }
  if (typeof IntersectionObserver !== 'undefined') {
    var origIO = IntersectionObserver;
    window.IntersectionObserver = function(cb, opts) {
      log('dom-probe', 'IntersectionObserver', {}, 'medium');
      return new origIO(cb, opts);
    };
    window.IntersectionObserver.prototype = origIO.prototype;
    window.IntersectionObserver.toString = function() { return 'function IntersectionObserver() { [native code] }'; };
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 12: CLIPBOARD (CRITICAL)
  // ═══════════════════════════════════════════
  if (typeof navigator.clipboard !== 'undefined') {
    hf(navigator.clipboard, 'readText', function() { log('clipboard', 'readText', {}, 'critical'); });
    hf(navigator.clipboard, 'writeText', function() { log('clipboard', 'writeText', {}, 'critical'); });
    hf(navigator.clipboard, 'read', function() { log('clipboard', 'read', {}, 'critical'); });
    hf(navigator.clipboard, 'write', function() { log('clipboard', 'write', {}, 'critical'); });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 13: GEOLOCATION (CRITICAL)
  // ═══════════════════════════════════════════
  if (typeof navigator.geolocation !== 'undefined') {
    hf(navigator.geolocation, 'getCurrentPosition', function() { log('geolocation', 'getCurrentPosition', {}, 'critical'); });
    hf(navigator.geolocation, 'watchPosition', function() { log('geolocation', 'watchPosition', {}, 'critical'); });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 14: SERVICE WORKER (HIGH)
  // ═══════════════════════════════════════════
  if (typeof navigator.serviceWorker !== 'undefined') {
    hf(navigator.serviceWorker, 'register', function() {
      log('service-worker', 'register', { url: String(arguments[0]).slice(0, 200) }, 'high');
    });
    hf(navigator.serviceWorker, 'getRegistration', function() {
      log('service-worker', 'getRegistration', {}, 'high');
    });
    hf(navigator.serviceWorker, 'getRegistrations', function() {
      log('service-worker', 'getRegistrations', {}, 'high');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 15: HARDWARE (HIGH)
  // ═══════════════════════════════════════════
  if (typeof navigator.getGamepads === 'function') {
    hf(navigator, 'getGamepads', function() { log('hardware', 'getGamepads', {}, 'high'); });
  }
  if (typeof navigator.getBattery === 'function') {
    // REG-003: Battery API hook restored
    hf(navigator, 'getBattery', function() { log('battery', 'getBattery', {}, 'high'); });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 16: EXFILTRATION (CRITICAL)
  //  REG-005: sendBeacon, WebSocket, Image beacon
  // ═══════════════════════════════════════════
  if (typeof navigator.sendBeacon === 'function') {
    hf(navigator, 'sendBeacon', function() {
      log('exfiltration', 'sendBeacon', { url: String(arguments[0]).slice(0, 200) }, 'critical');
    });
  }
  if (typeof WebSocket !== 'undefined') {
    var origWS = WebSocket;
    window.WebSocket = function(url, protocols) {
      log('exfiltration', 'WebSocket', { url: String(url).slice(0, 200) }, 'critical');
      if (protocols) return new origWS(url, protocols);
      return new origWS(url);
    };
    window.WebSocket.prototype = origWS.prototype;
    window.WebSocket.CONNECTING = origWS.CONNECTING;
    window.WebSocket.OPEN = origWS.OPEN;
    window.WebSocket.CLOSING = origWS.CLOSING;
    window.WebSocket.CLOSED = origWS.CLOSED;
    window.WebSocket.toString = function() { return 'function WebSocket() { [native code] }'; };
  }
  // Image.src beacon detection
  var origImageSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
  if (origImageSrc && origImageSrc.set) {
    var origImgSet = origImageSrc.set;
    Object.defineProperty(HTMLImageElement.prototype, 'src', {
      get: origImageSrc.get,
      set: function(val) {
        if (val && typeof val === 'string' && (val.indexOf('?') !== -1 || val.indexOf('&') !== -1)) {
          log('exfiltration', 'Image.src', { url: val.slice(0, 200) }, 'medium');
        }
        return origImgSet.call(this, val);
      },
      enumerable: true,
      configurable: true
    });
    hookCount++;
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 17: WEBRTC (CRITICAL)
  // ═══════════════════════════════════════════
  if (typeof RTCPeerConnection !== 'undefined') {
    var origRTC = RTCPeerConnection;
    window.RTCPeerConnection = function(config) {
      log('webrtc', 'RTCPeerConnection', { iceServers: config ? JSON.stringify(config.iceServers || []).slice(0, 100) : '' }, 'critical');
      var pc = new origRTC(config);
      var origCreateOffer = pc.createOffer.bind(pc);
      pc.createOffer = function(opts) { log('webrtc', 'createOffer', {}, 'critical'); return origCreateOffer(opts); };
      var origCreateDC = pc.createDataChannel.bind(pc);
      pc.createDataChannel = function(label, opts) { log('webrtc', 'createDataChannel', { label: label }, 'critical'); return origCreateDC(label, opts); };
      pc.addEventListener('icecandidate', function(e) {
        if (e.candidate) log('webrtc', 'icecandidate', { candidate: String(e.candidate.candidate).slice(0, 100) }, 'critical');
      });
      return pc;
    };
    window.RTCPeerConnection.prototype = origRTC.prototype;
    window.RTCPeerConnection.toString = function() { return 'function RTCPeerConnection() { [native code] }'; };
    hookCount++;
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 18: MATH FINGERPRINTING (MEDIUM)
  //  21 Math functions precision probing
  // ═══════════════════════════════════════════
  var mathFns = ['sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'atan2',
    'sqrt', 'exp', 'log', 'log2', 'log10', 'pow', 'abs',
    'sinh', 'cosh', 'tanh', 'asinh', 'acosh', 'atanh', 'cbrt'];
  mathFns.forEach(function(fn) {
    if (typeof Math[fn] === 'function') {
      hf(Math, fn, function() {
        log('math-fingerprint', 'Math.' + fn, { val: Math[fn].apply(Math, arguments) }, 'medium');
      });
    }
  });

  // ═══════════════════════════════════════════
  //  CATEGORY 19: PERMISSIONS (HIGH)
  // ═══════════════════════════════════════════
  if (navigator.permissions && typeof navigator.permissions.query === 'function') {
    hf(navigator.permissions, 'query', function() {
      log('permissions', 'permissions.query', { name: arguments[0] ? arguments[0].name : '' }, 'high');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 20: SPEECH (HIGH)
  // ═══════════════════════════════════════════
  if (typeof speechSynthesis !== 'undefined' && typeof speechSynthesis.getVoices === 'function') {
    hf(speechSynthesis, 'getVoices', function() {
      log('speech', 'getVoices', {}, 'high');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 21: CLIENT HINTS (CRITICAL)
  // ═══════════════════════════════════════════
  if (navigator.userAgentData) {
    if (typeof navigator.userAgentData.getHighEntropyValues === 'function') {
      hf(navigator.userAgentData, 'getHighEntropyValues', function() {
        log('client-hints', 'getHighEntropyValues', { hints: JSON.stringify(arguments[0]).slice(0, 100) }, 'critical');
      });
    }
    shg(navigator.userAgentData, null, 'brands', function(val) {
      log('client-hints', 'brands', { val: JSON.stringify(val).slice(0, 100) }, 'high');
    });
    shg(navigator.userAgentData, null, 'platform', function(val) {
      log('client-hints', 'platform', { val: val }, 'high');
    });
    shg(navigator.userAgentData, null, 'mobile', function(val) {
      log('client-hints', 'mobile', { val: val }, 'medium');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 22: INTL FINGERPRINTING (MEDIUM)
  // ═══════════════════════════════════════════
  if (typeof Intl !== 'undefined') {
    if (Intl.DateTimeFormat) {
      hf(Intl.DateTimeFormat.prototype, 'resolvedOptions', function() {
        log('intl-fingerprint', 'DateTimeFormat.resolvedOptions', {}, 'medium');
      });
    }
    if (Intl.NumberFormat) {
      hf(Intl.NumberFormat.prototype, 'resolvedOptions', function() {
        log('intl-fingerprint', 'NumberFormat.resolvedOptions', {}, 'medium');
      });
    }
    if (Intl.Collator) {
      hf(Intl.Collator.prototype, 'resolvedOptions', function() {
        log('intl-fingerprint', 'Collator.resolvedOptions', {}, 'medium');
      });
    }
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 23: CSS FINGERPRINTING (MEDIUM)
  //  REG-004: matchMedia hook restored
  // ═══════════════════════════════════════════
  if (typeof CSS !== 'undefined' && typeof CSS.supports === 'function') {
    hf(CSS, 'supports', function() {
      log('css-fingerprint', 'CSS.supports', { prop: arguments[0], val: arguments[1] }, 'medium');
    });
  }
  if (typeof window.matchMedia === 'function') {
    hf(window, 'matchMedia', function() {
      log('css-fingerprint', 'matchMedia', { query: String(arguments[0]).slice(0, 100) }, 'medium');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 24: PROPERTY ENUMERATION (HIGH)
  //  REG-025: Filter navigator/screen/prototype only
  // ═══════════════════════════════════════════
  var origKeys = Object.keys;
  Object.keys = function(obj) {
    if (obj === navigator || obj === screen || obj === Navigator.prototype || obj === Screen.prototype) {
      log('property-enum', 'Object.keys', { target: obj === navigator ? 'navigator' : obj === screen ? 'screen' : 'prototype' }, 'high');
    }
    return origKeys.call(Object, obj);
  };
  Object.keys.toString = function() { return 'function keys() { [native code] }'; };
  hookCount++;

  var origGetOPN = Object.getOwnPropertyNames;
  Object.getOwnPropertyNames = function(obj) {
    if (obj === navigator || obj === screen || obj === Navigator.prototype || obj === Screen.prototype) {
      log('property-enum', 'getOwnPropertyNames', { target: obj === navigator ? 'navigator' : obj === screen ? 'screen' : 'prototype' }, 'high');
    }
    return origGetOPN.call(Object, obj);
  };
  Object.getOwnPropertyNames.toString = function() { return 'function getOwnPropertyNames() { [native code] }'; };
  hookCount++;

  // ═══════════════════════════════════════════
  //  CATEGORY 25: OFFSCREEN CANVAS (HIGH)
  // ═══════════════════════════════════════════
  if (typeof OffscreenCanvas !== 'undefined') {
    hf(OffscreenCanvas.prototype, 'getContext', function() {
      log('offscreen-canvas', 'getContext', { type: arguments[0] }, 'high');
    });
    hf(OffscreenCanvas.prototype, 'convertToBlob', function() {
      log('offscreen-canvas', 'convertToBlob', {}, 'high');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 26: HONEYPOT TRAPS (CRITICAL)
  // ═══════════════════════════════════════════
  var honeyProps = [
    '_phantom', '__nightmare', 'callPhantom', '_selenium',
    '__selenium_evaluate', '__selenium_unwrapped',
    '__webdriver_evaluate', '__driver_evaluate',
    '__webdriver_unwrapped', '__driver_unwrapped',
    '__fxdriver_evaluate', '__fxdriver_unwrapped',
    'callSelenium', '_Selenium_IDE_Recorder',
    'domAutomation', 'domAutomationController',
    '__lastWatirAlert', '__lastWatirConfirm',
    '__lastWatirPrompt', '_WEBDRIVER_ELEM_CACHE',
    'ChromeDriverw', 'driver-evaluate'
  ];
  honeyProps.forEach(function(prop) {
    try {
      Object.defineProperty(window, prop, {
        get: function() {
          log('honeypot', prop, { trap: prop }, 'critical');
          return undefined;
        },
        set: function() {
          log('honeypot', prop + '.set', { trap: prop }, 'critical');
        },
        enumerable: false,
        configurable: true
      });
      hookCount++;
    } catch(e) {}
  });

  // ═══════════════════════════════════════════
  //  CATEGORY 27: CREDENTIAL (CRITICAL)
  // ═══════════════════════════════════════════
  if (navigator.credentials) {
    hf(navigator.credentials, 'get', function() { log('credential', 'credentials.get', {}, 'critical'); });
    hf(navigator.credentials, 'create', function() { log('credential', 'credentials.create', {}, 'critical'); });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 29: ENCODING (LOW)
  // ═══════════════════════════════════════════
  if (typeof TextEncoder !== 'undefined') {
    hf(TextEncoder.prototype, 'encode', function() {
      log('encoding', 'TextEncoder.encode', { len: arguments[0] ? arguments[0].length : 0 }, 'low');
    });
  }
  if (typeof TextDecoder !== 'undefined') {
    hf(TextDecoder.prototype, 'decode', function() {
      log('encoding', 'TextDecoder.decode', {}, 'low');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 30: WORKER (HIGH)
  // ═══════════════════════════════════════════
  if (typeof Worker !== 'undefined') {
    var origWorker = Worker;
    window.Worker = function(url, opts) {
      log('worker', 'Worker', { url: String(url).slice(0, 200) }, 'high');
      return new origWorker(url, opts);
    };
    window.Worker.prototype = origWorker.prototype;
    window.Worker.toString = function() { return 'function Worker() { [native code] }'; };
    hookCount++;
  }
  if (typeof SharedWorker !== 'undefined') {
    var origSW = SharedWorker;
    window.SharedWorker = function(url, opts) {
      log('worker', 'SharedWorker', { url: String(url).slice(0, 200) }, 'high');
      return new origSW(url, opts);
    };
    window.SharedWorker.prototype = origSW.prototype;
    window.SharedWorker.toString = function() { return 'function SharedWorker() { [native code] }'; };
    hookCount++;
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 31: WEBASSEMBLY (CRITICAL)
  // ═══════════════════════════════════════════
  if (typeof WebAssembly !== 'undefined') {
    hf(WebAssembly, 'compile', function() { log('webassembly', 'compile', {}, 'critical'); });
    hf(WebAssembly, 'instantiate', function() { log('webassembly', 'instantiate', {}, 'critical'); });
    hf(WebAssembly, 'validate', function() { log('webassembly', 'validate', {}, 'high'); });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 32: KEYBOARD LAYOUT (HIGH)
  // ═══════════════════════════════════════════
  if (navigator.keyboard && typeof navigator.keyboard.getLayoutMap === 'function') {
    hf(navigator.keyboard, 'getLayoutMap', function() {
      log('keyboard-layout', 'getLayoutMap', {}, 'high');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 33: SENSOR APIs (HIGH)
  // ═══════════════════════════════════════════
  ['Accelerometer', 'Gyroscope', 'Magnetometer', 'LinearAccelerationSensor', 'AbsoluteOrientationSensor', 'RelativeOrientationSensor'].forEach(function(sensorName) {
    if (typeof window[sensorName] !== 'undefined') {
      var origSensor = window[sensorName];
      window[sensorName] = function(opts) {
        log('sensor-apis', sensorName, {}, 'high');
        return new origSensor(opts);
      };
      window[sensorName].prototype = origSensor.prototype;
      window[sensorName].toString = function() { return 'function ' + sensorName + '() { [native code] }'; };
      hookCount++;
    }
  });

  // ═══════════════════════════════════════════
  //  CATEGORY 34: VISUALIZATION (MEDIUM)
  //  requestAnimationFrame timing analysis
  // ═══════════════════════════════════════════
  var rafCount = 0;
  var origRAF = window.requestAnimationFrame;
  if (origRAF) {
    window.requestAnimationFrame = function(cb) {
      rafCount++;
      if (rafCount <= 10 || rafCount % 100 === 0) {
        log('visualization', 'requestAnimationFrame', { count: rafCount }, 'medium');
      }
      return origRAF.call(window, cb);
    };
    window.requestAnimationFrame.toString = function() { return 'function requestAnimationFrame() { [native code] }'; };
    hookCount++;
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 35: BATTERY (HIGH)
  //  REG-003: Restored from v5.0.0
  // ═══════════════════════════════════════════
  // (Covered above in Category 15 via navigator.getBattery)

  // ═══════════════════════════════════════════
  //  CATEGORY 36: EVENT MONITORING (MEDIUM)
  //  REG-002: Restored from v5.0.0
  // ═══════════════════════════════════════════
  var monitoredEvents = ['visibilitychange', 'focus', 'blur', 'resize', 'devicemotion', 'deviceorientation', 'beforeunload', 'unload', 'pagehide', 'pageshow'];
  var origAEL = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, listener, opts) {
    if (monitoredEvents.indexOf(type) !== -1) {
      log('event-monitoring', 'addEventListener', { type: type }, 'medium');
    }
    return origAEL.call(this, type, listener, opts);
  };
  EventTarget.prototype.addEventListener.toString = function() { return 'function addEventListener() { [native code] }'; };
  hookCount++;

  // ═══════════════════════════════════════════
  //  CATEGORY 37: BLOB URL (HIGH)
  // ═══════════════════════════════════════════
  if (typeof URL.createObjectURL === 'function') {
    hf(URL, 'createObjectURL', function() {
      log('blob-url', 'createObjectURL', {}, 'high');
    });
    hf(URL, 'revokeObjectURL', function() {
      log('blob-url', 'revokeObjectURL', {}, 'low');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 38: SHARED ARRAY BUFFER (HIGH)
  // ═══════════════════════════════════════════
  if (typeof SharedArrayBuffer !== 'undefined') {
    var origSAB = SharedArrayBuffer;
    window.SharedArrayBuffer = function(len) {
      log('shared-array-buffer', 'SharedArrayBuffer', { length: len }, 'high');
      return new origSAB(len);
    };
    window.SharedArrayBuffer.prototype = origSAB.prototype;
    window.SharedArrayBuffer.toString = function() { return 'function SharedArrayBuffer() { [native code] }'; };
    hookCount++;
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 39: POSTMESSAGE EXFIL (MEDIUM)
  // ═══════════════════════════════════════════
  hf(window, 'postMessage', function() {
    var data = arguments[0];
    var target = arguments[1];
    log('postmessage-exfil', 'postMessage', { target: String(target).slice(0, 50), dataType: typeof data }, 'medium');
  });

  // ═══════════════════════════════════════════
  //  CATEGORY 40: PERFORMANCE-NOW (MEDIUM)
  //  High-frequency precision timer (distinct from perf-timing)
  // ═══════════════════════════════════════════
  // (Already covered in Category 9)

  // ═══════════════════════════════════════════
  //  CATEGORY 41: DEVICE INFO (MEDIUM)
  // ═══════════════════════════════════════════
  if (navigator.connection) {
    shg(navigator.connection, null, 'effectiveType', function(val) {
      log('device-info', 'effectiveType', { val: val }, 'medium');
    });
    shg(navigator.connection, null, 'downlink', function(val) {
      log('device-info', 'downlink', { val: val }, 'medium');
    });
    shg(navigator.connection, null, 'rtt', function(val) {
      log('device-info', 'rtt', { val: val }, 'medium');
    });
  }

  // ═══════════════════════════════════════════
  //  CATEGORY 42: CROSS-FRAME COMM (MEDIUM)
  // ═══════════════════════════════════════════
  window.addEventListener('message', function(e) {
    log('cross-frame-comm', 'onmessage', { origin: e.origin, dataType: typeof e.data }, 'medium');
  });
  hookCount++;

  // ═══════════════════════════════════════════
  //  PUSH TELEMETRY SYSTEM
  //  REG-015: 500ms push interval
  //  REG-021: Final flush before close
  // ═══════════════════════════════════════════
  var _lastPushIndex = 0;

  function pushEvents() {
    if (_SENTINEL_DATA.events.length <= _lastPushIndex) return;
    var batch = _SENTINEL_DATA.events.slice(_lastPushIndex);
    _lastPushIndex = _SENTINEL_DATA.events.length;
    try {
      if (typeof window.SENTINEL_PUSH === 'function') {
        window.SENTINEL_PUSH(JSON.stringify({
          type: 'events',
          count: batch.length,
          total: _SENTINEL_DATA.events.length,
          events: batch,
          hookPoints: hookCount,
          frame: _SENTINEL_DATA.frameType,
          ts: Date.now()
        }));
      }
    } catch(e) {}
  }

  // Immediate boot push at 50ms
  setTimeout(pushEvents, 50);

  // REG-015: 500ms interval push
  var pushTimer = setInterval(pushEvents, _SENTINEL_DATA.pushInterval);

  // REG-021: Final flush before close
  window.addEventListener('beforeunload', function() {
    pushEvents();
    clearInterval(pushTimer);
  });
  window.addEventListener('pagehide', function() {
    pushEvents();
  });

  // Stop after timeout
  setTimeout(function() {
    pushEvents();
    clearInterval(pushTimer);
  }, _SENTINEL_DATA.timeout + 2000);

  // Record hook stats
  _SENTINEL_DATA.hookPoints = hookCount;
  _SENTINEL_DATA.bootTime = Date.now() - _SENTINEL_DATA.startTime;

  // ═══════════════════════════════════════════
  //  CATEGORY 28: SYSTEM — BOOT-OK SIGNAL
  //  REG-023: Mandatory boot confirmation
  // ═══════════════════════════════════════════
  log('system', 'BOOT-OK', {
    hookPoints: hookCount,
    categories: _SENTINEL_DATA.categoriesMonitored,
    frame: _SENTINEL_DATA.frameType,
    version: _SENTINEL_DATA.version,
    bootMs: _SENTINEL_DATA.bootTime
  }, 'info');

  // Immediate push of BOOT-OK
  setTimeout(pushEvents, 100);

})();
`;
}

module.exports = { getInterceptorScript };
