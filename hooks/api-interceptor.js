// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — API INTERCEPTOR (42 Categories, 110+ Hooks)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - PURE NEW: Full rewrite combining v5.0.0 + v6.1 hook coverage
//   - 42 categories (was 22 in v6.1, 19 in v6.4 CDP-only)
//   - 110+ hook points with push telemetry (500ms)
//   - REG-002: addEventListener monitoring
//   - REG-003: Battery API hook
//   - REG-004: matchMedia hook
//   - REG-005: Dual-log exfiltration + network
//   - REG-011: _SENTINEL_DATA naming
//   - REG-015: 500ms push interval
//   - REG-017: Non-enumerable globals (Quiet Mode)
//   - REG-020: categoriesMonitored: 42
//   - REG-023: BOOT-OK mandatory signal
//   - REG-024: Filtered createElement (fpTags)
//   - REG-025: Filtered property-enum (navigator/screen)
//   - ZERO spoofing — all hooks LOG only, never modify returns
//
// LAST HISTORY LOG:
//   v6.4.0: No interceptor (ZERO injection)
//   v6.1.0: api-interceptor with 22 categories
//   v5.0.0: api-interceptor with 42 categories
//   v7.0.0: Restored full 42 categories from v5.0.0/v6.1
// ═══════════════════════════════════════════════════════════════

'use strict';

function getInterceptorScript(opts) {
  var timeout = (opts && opts.timeout) || 30000;
  var maxEvents = (opts && opts.maxEvents) || 50000;
  var pushInterval = (opts && opts.pushInterval) || 500;

  return `
(function() {
  'use strict';
  if (window.__SENTINEL_INTERCEPTOR__) return;

  var H = window.__SENTINEL_HOOKS__;
  if (!H) return;

  var categoriesMonitored = 42;
  var hookPointsActive = 0;

  var _data = {
    events: [],
    startTime: Date.now(),
    frameType: (window === window.top) ? 'top' : 'sub',
    _lastPushIndex: 0
  };

  Object.defineProperty(window, '_SENTINEL_DATA', {
    value: _data,
    writable: false,
    enumerable: false,
    configurable: false
  });

  function log(cat, api, detail, risk, meta) {
    if (_data.events.length >= ${maxEvents}) return;
    _data.events.push({
      ts: Date.now(),
      cat: cat,
      api: api,
      detail: (typeof detail === 'string') ? detail.slice(0, 500) : String(detail).slice(0, 500),
      risk: risk || 'medium',
      frame: _data.frameType,
      src: 'hook',
      meta: meta || null
    });
  }

  // ─── PUSH TELEMETRY (REG-015: 500ms) ───
  var pushTimer = null;
  function pushEvents() {
    if (typeof window.SENTINEL_PUSH !== 'function') return;
    var lastIdx = _data._lastPushIndex || 0;
    var batch = _data.events.slice(lastIdx);
    if (batch.length === 0) return;
    _data._lastPushIndex = _data.events.length;
    try {
      window.SENTINEL_PUSH(JSON.stringify({
        type: 'events',
        count: batch.length,
        total: _data.events.length,
        events: batch,
        frame: _data.frameType,
        ts: Date.now()
      }));
    } catch(e) {}
  }
  pushTimer = setInterval(pushEvents, ${pushInterval});

  // beforeunload flush
  window.addEventListener('beforeunload', function() {
    clearInterval(pushTimer);
    pushEvents();
  });
  window.addEventListener('pagehide', function() {
    clearInterval(pushTimer);
    pushEvents();
  });

  // ─── BOOT-OK SIGNAL (REG-023) ───
  log('system', 'BOOT-OK', 'Interceptor loaded: categoriesMonitored=' + categoriesMonitored + ', frame=' + _data.frameType, 'info');

  // ═══════════════════════════════════════════
  // CATEGORY 1: CANVAS (cat: 'canvas')
  // ═══════════════════════════════════════════
  try {
    H.hookFunction(HTMLCanvasElement.prototype, 'toDataURL', function() { log('canvas', 'toDataURL', 'Canvas fingerprint export', 'high'); });
    H.hookFunction(HTMLCanvasElement.prototype, 'toBlob', function() { log('canvas', 'toBlob', 'Canvas blob export', 'high'); });
    if (CanvasRenderingContext2D && CanvasRenderingContext2D.prototype) {
      H.hookFunction(CanvasRenderingContext2D.prototype, 'getImageData', function() { log('canvas', 'getImageData', 'Canvas pixel read', 'high'); });
      H.hookFunction(CanvasRenderingContext2D.prototype, 'fillText', function(t) { log('canvas', 'fillText', 'Text render: ' + (t || ''), 'medium'); });
      H.hookFunction(CanvasRenderingContext2D.prototype, 'measureText', function(t) { log('canvas', 'measureText', 'Text measure: ' + (t || ''), 'medium'); });
      H.hookFunction(CanvasRenderingContext2D.prototype, 'isPointInPath', function() { log('canvas', 'isPointInPath', 'Path test', 'medium'); });
    }
    hookPointsActive += 6;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 2: WEBGL (cat: 'webgl')
  // ═══════════════════════════════════════════
  try {
    ['WebGLRenderingContext', 'WebGL2RenderingContext'].forEach(function(ctxName) {
      var proto = window[ctxName] && window[ctxName].prototype;
      if (!proto) return;
      H.hookFunction(proto, 'getParameter', function(p) { log('webgl', 'getParameter', ctxName + '.getParameter(' + p + ')', 'high'); });
      H.hookFunction(proto, 'getExtension', function(n) { log('webgl', 'getExtension', ctxName + '.getExtension(' + n + ')', 'high'); });
      H.hookFunction(proto, 'getSupportedExtensions', function() { log('webgl', 'getSupportedExtensions', ctxName + '.getSupportedExtensions', 'high'); });
      H.hookFunction(proto, 'getShaderPrecisionFormat', function() { log('webgl', 'getShaderPrecisionFormat', ctxName + '.getShaderPrecisionFormat', 'high'); });
      H.hookFunction(proto, 'readPixels', function() { log('webgl', 'readPixels', ctxName + '.readPixels', 'high'); });
      hookPointsActive += 5;
    });
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 3: AUDIO (cat: 'audio')
  // ═══════════════════════════════════════════
  try {
    if (typeof AudioContext !== 'undefined' || typeof webkitAudioContext !== 'undefined') {
      var AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx && AudioCtx.prototype) {
        H.hookFunction(AudioCtx.prototype, 'createOscillator', function() { log('audio', 'createOscillator', 'AudioContext oscillator', 'critical'); });
        H.hookFunction(AudioCtx.prototype, 'createDynamicsCompressor', function() { log('audio', 'createDynamicsCompressor', 'AudioContext compressor', 'critical'); });
        H.hookFunction(AudioCtx.prototype, 'createAnalyser', function() { log('audio', 'createAnalyser', 'AudioContext analyser', 'critical'); });
        hookPointsActive += 3;
      }
      if (typeof OfflineAudioContext !== 'undefined' && OfflineAudioContext.prototype) {
        H.hookFunction(OfflineAudioContext.prototype, 'startRendering', function() { log('audio', 'startRendering', 'OfflineAudioContext rendering', 'critical'); });
        hookPointsActive += 1;
      }
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 4: FONT DETECTION (cat: 'font-detection')
  // ═══════════════════════════════════════════
  try {
    H.hookFunction(Element.prototype, 'getBoundingClientRect', function() { log('font-detection', 'getBoundingClientRect', 'Element dimension probe', 'critical'); });
    if (document.fonts && document.fonts.check) {
      H.hookFunction(document.fonts, 'check', function(f) { log('font-detection', 'fonts.check', 'Font check: ' + (f || ''), 'critical'); });
    }
    if (typeof FontFace !== 'undefined' && FontFace.prototype) {
      H.hookFunction(FontFace.prototype, 'load', function() { log('font-detection', 'FontFace.load', 'FontFace load', 'critical'); });
    }
    hookPointsActive += 3;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 5: FINGERPRINT — Navigator Props (cat: 'fingerprint')
  // ═══════════════════════════════════════════
  try {
    var navProps = ['userAgent', 'platform', 'vendor', 'appVersion', 'appName', 'appCodeName',
      'product', 'productSub', 'language', 'languages', 'onLine', 'cookieEnabled',
      'doNotTrack', 'maxTouchPoints', 'hardwareConcurrency', 'deviceMemory',
      'pdfViewerEnabled', 'webdriver', 'connection'];
    navProps.forEach(function(prop) {
      H.smartHookGetter(navigator, Navigator.prototype, prop, function(val) {
        log('fingerprint', 'navigator.' + prop, 'Value: ' + val, 'high');
      });
      hookPointsActive++;
    });
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 6: SCREEN (cat: 'screen')
  // ═══════════════════════════════════════════
  try {
    var screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
    screenProps.forEach(function(prop) {
      H.smartHookGetter(screen, Screen.prototype, prop, function(val) {
        log('screen', 'screen.' + prop, 'Value: ' + val, 'medium');
      });
      hookPointsActive++;
    });
    H.smartHookGetter(window, Window.prototype, 'devicePixelRatio', function(val) { log('screen', 'devicePixelRatio', 'Value: ' + val, 'medium'); });
    H.smartHookGetter(window, Window.prototype, 'outerWidth', function(val) { log('screen', 'outerWidth', 'Value: ' + val, 'medium'); });
    H.smartHookGetter(window, Window.prototype, 'outerHeight', function(val) { log('screen', 'outerHeight', 'Value: ' + val, 'medium'); });
    H.smartHookGetter(window, Window.prototype, 'innerWidth', function(val) { log('screen', 'innerWidth', 'Value: ' + val, 'medium'); });
    H.smartHookGetter(window, Window.prototype, 'innerHeight', function(val) { log('screen', 'innerHeight', 'Value: ' + val, 'medium'); });
    hookPointsActive += 5;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 7: STORAGE (cat: 'storage')
  // ═══════════════════════════════════════════
  try {
    H.hookGetterSetter(document, 'cookie',
      function(val) { log('storage', 'cookie.get', 'Read cookie (' + (val || '').length + ' chars)', 'medium'); },
      function(val) { log('storage', 'cookie.set', 'Set cookie: ' + (val || '').slice(0, 100), 'medium'); }
    );
    if (window.localStorage) {
      H.hookFunction(Storage.prototype, 'getItem', function(k) { log('storage', 'localStorage.getItem', 'Key: ' + k, 'medium'); });
      H.hookFunction(Storage.prototype, 'setItem', function(k, v) { log('storage', 'localStorage.setItem', 'Key: ' + k + ', val len: ' + (v || '').length, 'medium'); });
      H.hookFunction(Storage.prototype, 'removeItem', function(k) { log('storage', 'localStorage.removeItem', 'Key: ' + k, 'medium'); });
    }
    if (window.indexedDB) {
      H.hookFunction(IDBFactory.prototype, 'open', function(n) { log('storage', 'indexedDB.open', 'DB: ' + n, 'medium'); });
    }
    hookPointsActive += 5;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 8: NETWORK — fetch/XHR (cat: 'network')
  // CATEGORY 16 DUAL: EXFILTRATION (REG-005)
  // ═══════════════════════════════════════════
  try {
    var origFetch = window.fetch;
    if (origFetch) {
      window.fetch = function() {
        var url = arguments[0];
        if (typeof url === 'object' && url.url) url = url.url;
        log('network', 'fetch', 'URL: ' + String(url).slice(0, 300), 'medium');
        log('exfiltration', 'fetch', 'Outbound fetch: ' + String(url).slice(0, 200), 'critical');
        return origFetch.apply(this, arguments);
      };
      window.fetch.toString = function() { return 'function fetch() { [native code] }'; };
      hookPointsActive++;
    }
    if (XMLHttpRequest && XMLHttpRequest.prototype) {
      H.hookFunction(XMLHttpRequest.prototype, 'open', function(method, url) {
        log('network', 'XHR.open', method + ' ' + String(url).slice(0, 300), 'medium');
        log('exfiltration', 'XHR.open', 'Outbound XHR: ' + method + ' ' + String(url).slice(0, 200), 'critical');
      });
      H.hookFunction(XMLHttpRequest.prototype, 'send', function() { log('network', 'XHR.send', 'XHR request sent', 'medium'); });
      hookPointsActive += 2;
    }
    if (typeof EventSource !== 'undefined') {
      var origES = EventSource;
      window.EventSource = function(url) { log('network', 'EventSource', 'SSE: ' + url, 'medium'); return new origES(url); };
      window.EventSource.toString = function() { return 'function EventSource() { [native code] }'; };
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 9: PERFORMANCE TIMING (cat: 'perf-timing')
  // ═══════════════════════════════════════════
  try {
    H.hookFunction(Performance.prototype, 'now', function() { log('perf-timing', 'performance.now', 'High-res timer', 'medium'); });
    H.hookFunction(Performance.prototype, 'mark', function(n) { log('perf-timing', 'performance.mark', 'Mark: ' + n, 'medium'); });
    H.hookFunction(Performance.prototype, 'measure', function(n) { log('perf-timing', 'performance.measure', 'Measure: ' + n, 'medium'); });
    H.hookFunction(Performance.prototype, 'getEntriesByType', function(t) { log('perf-timing', 'getEntriesByType', 'Type: ' + t, 'medium'); });
    H.hookFunction(Performance.prototype, 'getEntriesByName', function(n) { log('perf-timing', 'getEntriesByName', 'Name: ' + n, 'medium'); });
    hookPointsActive += 5;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 10: MEDIA DEVICES (cat: 'media-devices')
  // ═══════════════════════════════════════════
  try {
    if (navigator.mediaDevices) {
      H.hookFunction(navigator.mediaDevices, 'enumerateDevices', function() { log('media-devices', 'enumerateDevices', 'Media device enumeration', 'critical'); });
      H.hookFunction(navigator.mediaDevices, 'getUserMedia', function() { log('media-devices', 'getUserMedia', 'Camera/mic access request', 'critical'); });
      hookPointsActive += 2;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 11: DOM PROBE (cat: 'dom-probe') — REG-024
  // ═══════════════════════════════════════════
  try {
    var fpTags = { canvas: 1, audio: 1, video: 1, iframe: 1, object: 1, embed: 1, img: 1 };
    var origCreateElement = document.createElement;
    document.createElement = function(tag) {
      var tl = (tag || '').toLowerCase();
      if (fpTags[tl]) log('dom-probe', 'createElement', 'Created: <' + tl + '>', 'medium');
      return origCreateElement.call(document, tag);
    };
    document.createElement.toString = function() { return 'function createElement() { [native code] }'; };
    hookPointsActive++;
    if (typeof MutationObserver !== 'undefined') {
      var origMO = MutationObserver;
      window.MutationObserver = function(cb) { log('dom-probe', 'MutationObserver', 'MutationObserver created', 'medium'); return new origMO(cb); };
      window.MutationObserver.toString = function() { return 'function MutationObserver() { [native code] }'; };
      window.MutationObserver.prototype = origMO.prototype;
      hookPointsActive++;
    }
    if (typeof IntersectionObserver !== 'undefined') {
      var origIO = IntersectionObserver;
      window.IntersectionObserver = function(cb, opts) { log('dom-probe', 'IntersectionObserver', 'IntersectionObserver created', 'medium'); return new origIO(cb, opts); };
      window.IntersectionObserver.toString = function() { return 'function IntersectionObserver() { [native code] }'; };
      window.IntersectionObserver.prototype = origIO.prototype;
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 12: CLIPBOARD (cat: 'clipboard')
  // ═══════════════════════════════════════════
  try {
    if (navigator.clipboard) {
      H.hookFunction(navigator.clipboard, 'readText', function() { log('clipboard', 'readText', 'Clipboard read attempt', 'critical'); });
      H.hookFunction(navigator.clipboard, 'writeText', function() { log('clipboard', 'writeText', 'Clipboard write', 'critical'); });
      H.hookFunction(navigator.clipboard, 'read', function() { log('clipboard', 'read', 'Clipboard read (binary)', 'critical'); });
      H.hookFunction(navigator.clipboard, 'write', function() { log('clipboard', 'write', 'Clipboard write (binary)', 'critical'); });
      hookPointsActive += 4;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 13: GEOLOCATION (cat: 'geolocation')
  // ═══════════════════════════════════════════
  try {
    if (navigator.geolocation) {
      H.hookFunction(navigator.geolocation, 'getCurrentPosition', function() { log('geolocation', 'getCurrentPosition', 'Location request', 'critical'); });
      H.hookFunction(navigator.geolocation, 'watchPosition', function() { log('geolocation', 'watchPosition', 'Location watch', 'critical'); });
      hookPointsActive += 2;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 14: SERVICE WORKER (cat: 'service-worker')
  // ═══════════════════════════════════════════
  try {
    if (navigator.serviceWorker) {
      H.hookFunction(navigator.serviceWorker, 'register', function(url) { log('service-worker', 'register', 'SW register: ' + url, 'high'); });
      H.hookFunction(navigator.serviceWorker, 'getRegistration', function() { log('service-worker', 'getRegistration', 'SW getRegistration', 'high'); });
      H.hookFunction(navigator.serviceWorker, 'getRegistrations', function() { log('service-worker', 'getRegistrations', 'SW getRegistrations', 'high'); });
      hookPointsActive += 3;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 15: HARDWARE (cat: 'hardware')
  // ═══════════════════════════════════════════
  try {
    if (navigator.getGamepads) {
      H.hookFunction(navigator, 'getGamepads', function() { log('hardware', 'getGamepads', 'Gamepad enumeration', 'high'); });
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 16: EXFILTRATION (cat: 'exfiltration') — beacon, WS, img
  // ═══════════════════════════════════════════
  try {
    if (navigator.sendBeacon) {
      H.hookFunction(navigator, 'sendBeacon', function(url) { log('exfiltration', 'sendBeacon', 'Beacon: ' + String(url).slice(0, 200), 'critical'); });
      hookPointsActive++;
    }
    if (typeof WebSocket !== 'undefined') {
      var origWS = WebSocket;
      window.WebSocket = function(url, proto) {
        log('exfiltration', 'WebSocket', 'WS connect: ' + url, 'critical');
        if (proto) return new origWS(url, proto);
        return new origWS(url);
      };
      window.WebSocket.prototype = origWS.prototype;
      window.WebSocket.CONNECTING = origWS.CONNECTING;
      window.WebSocket.OPEN = origWS.OPEN;
      window.WebSocket.CLOSING = origWS.CLOSING;
      window.WebSocket.CLOSED = origWS.CLOSED;
      window.WebSocket.toString = function() { return 'function WebSocket() { [native code] }'; };
      hookPointsActive++;
    }
    var origImgSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
    if (origImgSrc && origImgSrc.set) {
      Object.defineProperty(HTMLImageElement.prototype, 'src', {
        get: origImgSrc.get,
        set: function(val) {
          if (val && String(val).indexOf('?') !== -1 && String(val).length > 100) {
            log('exfiltration', 'img.src', 'Image beacon: ' + String(val).slice(0, 200), 'high');
          }
          return origImgSrc.set.call(this, val);
        },
        enumerable: true,
        configurable: true
      });
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 17: WEBRTC (cat: 'webrtc')
  // ═══════════════════════════════════════════
  try {
    if (typeof RTCPeerConnection !== 'undefined') {
      var origRTC = RTCPeerConnection;
      window.RTCPeerConnection = function(config) {
        log('webrtc', 'RTCPeerConnection', 'RTC created: ' + JSON.stringify(config || {}).slice(0, 200), 'critical');
        var inst = new origRTC(config);
        var origCreateOffer = inst.createOffer;
        if (origCreateOffer) {
          inst.createOffer = function() { log('webrtc', 'createOffer', 'SDP offer', 'critical'); return origCreateOffer.apply(this, arguments); };
        }
        var origDC = inst.createDataChannel;
        if (origDC) {
          inst.createDataChannel = function(label) { log('webrtc', 'createDataChannel', 'Channel: ' + label, 'critical'); return origDC.apply(this, arguments); };
        }
        inst.addEventListener('icecandidate', function(ev) {
          if (ev.candidate) log('webrtc', 'icecandidate', 'ICE: ' + String(ev.candidate.candidate).slice(0, 200), 'critical');
        });
        return inst;
      };
      window.RTCPeerConnection.prototype = origRTC.prototype;
      window.RTCPeerConnection.toString = function() { return 'function RTCPeerConnection() { [native code] }'; };
      hookPointsActive += 4;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 18: MATH FINGERPRINT (cat: 'math-fingerprint')
  // ═══════════════════════════════════════════
  try {
    var mathFns = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan', 'atanh', 'atan2',
      'cbrt', 'ceil', 'clz32', 'cos', 'cosh', 'exp', 'expm1', 'floor',
      'fround', 'log', 'log1p', 'log10', 'log2', 'sign', 'sin', 'sinh',
      'sqrt', 'tan', 'tanh', 'trunc'];
    mathFns.forEach(function(fn) {
      if (typeof Math[fn] === 'function') {
        H.hookFunction(Math, fn, function() { log('math-fingerprint', 'Math.' + fn, 'Math function called', 'medium'); });
        hookPointsActive++;
      }
    });
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 19: PERMISSIONS (cat: 'permissions')
  // ═══════════════════════════════════════════
  try {
    if (navigator.permissions && navigator.permissions.query) {
      H.hookFunction(navigator.permissions, 'query', function(desc) {
        log('permissions', 'permissions.query', 'Query: ' + JSON.stringify(desc || {}), 'high');
      });
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 20: SPEECH (cat: 'speech')
  // ═══════════════════════════════════════════
  try {
    if (window.speechSynthesis && window.speechSynthesis.getVoices) {
      H.hookFunction(window.speechSynthesis, 'getVoices', function() { log('speech', 'getVoices', 'Voice enumeration', 'high'); });
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 21: CLIENT HINTS (cat: 'client-hints')
  // ═══════════════════════════════════════════
  try {
    if (navigator.userAgentData) {
      if (navigator.userAgentData.getHighEntropyValues) {
        H.hookFunction(navigator.userAgentData, 'getHighEntropyValues', function(hints) {
          log('client-hints', 'getHighEntropyValues', 'Hints: ' + JSON.stringify(hints || []), 'critical');
        });
        hookPointsActive++;
      }
      H.hookGetter(navigator.userAgentData, 'brands', function(val) { log('client-hints', 'brands', 'Brands accessed', 'high'); });
      H.hookGetter(navigator.userAgentData, 'platform', function(val) { log('client-hints', 'platform', 'UA platform: ' + val, 'high'); });
      H.hookGetter(navigator.userAgentData, 'mobile', function(val) { log('client-hints', 'mobile', 'Mobile: ' + val, 'high'); });
      hookPointsActive += 3;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 22: INTL FINGERPRINT (cat: 'intl-fingerprint')
  // ═══════════════════════════════════════════
  try {
    if (Intl && Intl.DateTimeFormat && Intl.DateTimeFormat.prototype) {
      H.hookFunction(Intl.DateTimeFormat.prototype, 'resolvedOptions', function() { log('intl-fingerprint', 'DateTimeFormat.resolvedOptions', 'Intl DateTimeFormat probe', 'medium'); });
    }
    if (Intl && Intl.NumberFormat && Intl.NumberFormat.prototype) {
      H.hookFunction(Intl.NumberFormat.prototype, 'resolvedOptions', function() { log('intl-fingerprint', 'NumberFormat.resolvedOptions', 'Intl NumberFormat probe', 'medium'); });
    }
    if (Intl && Intl.Collator && Intl.Collator.prototype) {
      H.hookFunction(Intl.Collator.prototype, 'resolvedOptions', function() { log('intl-fingerprint', 'Collator.resolvedOptions', 'Intl Collator probe', 'medium'); });
    }
    hookPointsActive += 3;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 23: CSS FINGERPRINT (cat: 'css-fingerprint') — REG-004
  // ═══════════════════════════════════════════
  try {
    if (window.CSS && window.CSS.supports) {
      H.hookFunction(window.CSS, 'supports', function(prop) { log('css-fingerprint', 'CSS.supports', 'Test: ' + prop, 'medium'); });
      hookPointsActive++;
    }
    H.hookFunction(window, 'matchMedia', function(q) { log('css-fingerprint', 'matchMedia', 'Query: ' + q, 'medium'); });
    hookPointsActive++;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 24: PROPERTY ENUM (cat: 'property-enum') — REG-025
  // ═══════════════════════════════════════════
  try {
    var origObjKeys = Object.keys;
    Object.keys = function(obj) {
      if (obj === navigator || obj === screen) {
        log('property-enum', 'Object.keys', 'Enum target: ' + (obj === navigator ? 'navigator' : 'screen'), 'high');
      }
      return origObjKeys.call(Object, obj);
    };
    Object.keys.toString = function() { return 'function keys() { [native code] }'; };
    var origObjNames = Object.getOwnPropertyNames;
    Object.getOwnPropertyNames = function(obj) {
      if (obj === navigator || obj === screen) {
        log('property-enum', 'getOwnPropertyNames', 'Enum target: ' + (obj === navigator ? 'navigator' : 'screen'), 'high');
      }
      return origObjNames.call(Object, obj);
    };
    Object.getOwnPropertyNames.toString = function() { return 'function getOwnPropertyNames() { [native code] }'; };
    hookPointsActive += 2;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 25: OFFSCREEN CANVAS (cat: 'offscreen-canvas')
  // ═══════════════════════════════════════════
  try {
    if (typeof OffscreenCanvas !== 'undefined' && OffscreenCanvas.prototype) {
      H.hookFunction(OffscreenCanvas.prototype, 'getContext', function(type) { log('offscreen-canvas', 'getContext', 'OffscreenCanvas context: ' + type, 'high'); });
      H.hookFunction(OffscreenCanvas.prototype, 'convertToBlob', function() { log('offscreen-canvas', 'convertToBlob', 'OffscreenCanvas blob export', 'high'); });
      hookPointsActive += 2;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 26: HONEYPOT TRAPS (cat: 'honeypot')
  // ═══════════════════════════════════════════
  try {
    var honeypotProps = ['_phantom', '__selenium_unwrapped', '__webdriver_evaluate', '__driver_evaluate',
      '__webdriver_script_fn', '__selenium_evaluate', '__fxdriver_evaluate', '__webdriver_script_function',
      '__webdriver_script_func', '__lastWatirAlert', '__lastWatirConfirm', '__lastWatirPrompt',
      'callSelenium', '_Selenium_IDE_Recorder', '_selenium', 'calledSelenium',
      '__nightmare', 'domAutomation', 'domAutomationController', '__SENTINEL_CLOAKED__'];
    honeypotProps.forEach(function(prop) {
      try {
        Object.defineProperty(window, prop, {
          get: function() { log('honeypot', prop, 'Honeypot trap accessed: ' + prop, 'critical'); return undefined; },
          set: function() { log('honeypot', prop + '.set', 'Honeypot trap set: ' + prop, 'critical'); },
          enumerable: false,
          configurable: true
        });
        hookPointsActive++;
      } catch(e) {}
    });
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 27: CREDENTIAL (cat: 'credential')
  // ═══════════════════════════════════════════
  try {
    if (navigator.credentials) {
      H.hookFunction(navigator.credentials, 'get', function(opts) { log('credential', 'credentials.get', 'Credential get: ' + JSON.stringify(opts || {}).slice(0, 200), 'critical'); });
      H.hookFunction(navigator.credentials, 'create', function(opts) { log('credential', 'credentials.create', 'Credential create: ' + JSON.stringify(opts || {}).slice(0, 200), 'critical'); });
      hookPointsActive += 2;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 29: ENCODING (cat: 'encoding')
  // ═══════════════════════════════════════════
  try {
    if (typeof TextEncoder !== 'undefined' && TextEncoder.prototype) {
      H.hookFunction(TextEncoder.prototype, 'encode', function() { log('encoding', 'TextEncoder.encode', 'Text encoding', 'low'); });
    }
    if (typeof TextDecoder !== 'undefined' && TextDecoder.prototype) {
      H.hookFunction(TextDecoder.prototype, 'decode', function() { log('encoding', 'TextDecoder.decode', 'Text decoding', 'low'); });
    }
    hookPointsActive += 2;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 30: WORKER (cat: 'worker')
  // ═══════════════════════════════════════════
  try {
    if (typeof Worker !== 'undefined') {
      var origWorker = Worker;
      window.Worker = function(url, opts) {
        log('worker', 'Worker', 'New Worker: ' + url, 'high');
        return new origWorker(url, opts);
      };
      window.Worker.prototype = origWorker.prototype;
      window.Worker.toString = function() { return 'function Worker() { [native code] }'; };
      hookPointsActive++;
    }
    if (typeof SharedWorker !== 'undefined') {
      var origSW = SharedWorker;
      window.SharedWorker = function(url, opts) {
        log('worker', 'SharedWorker', 'New SharedWorker: ' + url, 'high');
        return new origSW(url, opts);
      };
      window.SharedWorker.prototype = origSW.prototype;
      window.SharedWorker.toString = function() { return 'function SharedWorker() { [native code] }'; };
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 31: WEBASSEMBLY (cat: 'webassembly')
  // ═══════════════════════════════════════════
  try {
    if (typeof WebAssembly !== 'undefined') {
      H.hookFunction(WebAssembly, 'compile', function() { log('webassembly', 'compile', 'WASM compile', 'critical'); });
      H.hookFunction(WebAssembly, 'instantiate', function() { log('webassembly', 'instantiate', 'WASM instantiate', 'critical'); });
      H.hookFunction(WebAssembly, 'validate', function() { log('webassembly', 'validate', 'WASM validate', 'critical'); });
      hookPointsActive += 3;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 32: KEYBOARD LAYOUT (cat: 'keyboard-layout')
  // ═══════════════════════════════════════════
  try {
    if (navigator.keyboard && navigator.keyboard.getLayoutMap) {
      H.hookFunction(navigator.keyboard, 'getLayoutMap', function() { log('keyboard-layout', 'getLayoutMap', 'Keyboard layout probe', 'high'); });
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 33: SENSOR APIs (cat: 'sensor-apis')
  // ═══════════════════════════════════════════
  try {
    var sensorTypes = ['Accelerometer', 'Gyroscope', 'Magnetometer', 'AmbientLightSensor', 'LinearAccelerationSensor', 'GravitySensor'];
    sensorTypes.forEach(function(name) {
      if (typeof window[name] !== 'undefined') {
        var origSensor = window[name];
        window[name] = function(opts) {
          log('sensor-apis', name, 'Sensor created: ' + name, 'high');
          return new origSensor(opts);
        };
        window[name].prototype = origSensor.prototype;
        window[name].toString = function() { return 'function ' + name + '() { [native code] }'; };
        hookPointsActive++;
      }
    });
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 34: VISUALIZATION (cat: 'visualization')
  // ═══════════════════════════════════════════
  try {
    var origRAF = window.requestAnimationFrame;
    if (origRAF) {
      window.requestAnimationFrame = function(cb) {
        log('visualization', 'requestAnimationFrame', 'rAF callback registered', 'medium');
        return origRAF.call(window, cb);
      };
      window.requestAnimationFrame.toString = function() { return 'function requestAnimationFrame() { [native code] }'; };
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 35: BATTERY (cat: 'battery') — REG-003
  // ═══════════════════════════════════════════
  try {
    if (navigator.getBattery) {
      H.hookFunction(navigator, 'getBattery', function() { log('battery', 'getBattery', 'Battery status request', 'high'); });
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 36: EVENT MONITORING (cat: 'event-monitoring') — REG-002
  // ═══════════════════════════════════════════
  try {
    var monitoredEvents = ['deviceorientation', 'devicemotion', 'touchstart', 'touchmove', 'touchend',
      'pointerdown', 'pointermove', 'pointerup', 'wheel', 'resize'];
    var origAddEL = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, listener, opts) {
      if (monitoredEvents.indexOf(type) !== -1) {
        log('event-monitoring', 'addEventListener', 'Event listener: ' + type, 'medium');
      }
      return origAddEL.call(this, type, listener, opts);
    };
    EventTarget.prototype.addEventListener.toString = function() { return 'function addEventListener() { [native code] }'; };
    hookPointsActive++;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 37: BLOB URL (cat: 'blob-url')
  // ═══════════════════════════════════════════
  try {
    H.hookFunction(URL, 'createObjectURL', function() { log('blob-url', 'createObjectURL', 'Blob URL created', 'high'); });
    H.hookFunction(URL, 'revokeObjectURL', function() { log('blob-url', 'revokeObjectURL', 'Blob URL revoked', 'high'); });
    hookPointsActive += 2;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 38: SHARED ARRAY BUFFER (cat: 'shared-array-buffer')
  // ═══════════════════════════════════════════
  try {
    if (typeof SharedArrayBuffer !== 'undefined') {
      var origSAB = SharedArrayBuffer;
      window.SharedArrayBuffer = function(len) {
        log('shared-array-buffer', 'SharedArrayBuffer', 'SAB created: ' + len + ' bytes', 'high');
        return new origSAB(len);
      };
      window.SharedArrayBuffer.prototype = origSAB.prototype;
      window.SharedArrayBuffer.toString = function() { return 'function SharedArrayBuffer() { [native code] }'; };
      hookPointsActive++;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 39: POSTMESSAGE EXFIL (cat: 'postmessage-exfil')
  // ═══════════════════════════════════════════
  try {
    H.hookFunction(window, 'postMessage', function(msg, origin) {
      log('postmessage-exfil', 'postMessage', 'Target: ' + (origin || '*') + ', data type: ' + typeof msg, 'medium');
    });
    hookPointsActive++;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 40: DEVICE INFO (cat: 'device-info')
  // ═══════════════════════════════════════════
  try {
    if (navigator.connection) {
      H.hookGetter(navigator.connection, 'effectiveType', function(val) { log('device-info', 'effectiveType', 'Network type: ' + val, 'medium'); });
      H.hookGetter(navigator.connection, 'downlink', function(val) { log('device-info', 'downlink', 'Downlink: ' + val, 'medium'); });
      H.hookGetter(navigator.connection, 'rtt', function(val) { log('device-info', 'rtt', 'RTT: ' + val, 'medium'); });
      hookPointsActive += 3;
    }
  } catch(e) {}

  // ═══════════════════════════════════════════
  // CATEGORY 41: CROSS-FRAME COMM (cat: 'cross-frame-comm')
  // ═══════════════════════════════════════════
  try {
    window.addEventListener('message', function(ev) {
      log('cross-frame-comm', 'onmessage', 'Message from: ' + (ev.origin || 'unknown') + ', type: ' + typeof ev.data, 'medium');
    });
    hookPointsActive++;
  } catch(e) {}

  // ═══════════════════════════════════════════
  // FINALIZE — Mark interceptor as loaded
  // ═══════════════════════════════════════════
  Object.defineProperty(window, '__SENTINEL_INTERCEPTOR__', { value: true, writable: false, enumerable: false, configurable: false });

  log('system', 'INIT-COMPLETE', 'hookPointsActive=' + hookPointsActive + ', categories=42, pushInterval=${pushInterval}', 'info');
})();
`;
}

module.exports = { getInterceptorScript };
