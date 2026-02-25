// ═══════════════════════════════════════════════════════════════════
//  SENTINEL v6.0.0 — UNIFIED API INTERCEPTOR
// ═══════════════════════════════════════════════════════════════════
// CHANGE LOG v6.0.0 (2026-02-25):
//   FROM v5.0.0:
//   - FIX: v5.1.0-Final had WRONG api-interceptor.js (v3 version, 586 lines,
//          exported getInterceptorScript). v6 restores the CORRECT v5.0.0 version
//          (887 lines, exports generateInterceptorScript, 42 categories, 110+ hooks).
//   - CHANGED: Version strings updated to v6.0.0
//   - KEPT: ALL 42 sections, ALL 110+ hook points
//   - KEPT: smartHookGetter (C-INT-01), hookGetterSetter (C-INT-02)
//   - KEPT: Filtered createElement (C-INT-04), event monitoring (C-INT-05)
//   - KEPT: Dual-log network+exfiltration (C-INT-06), battery (C-INT-07)
//   - KEPT: matchMedia with value capture (C-INT-08), BOOT_OK (C-INT-09)
//   - KEPT: Push telemetry 500ms interval (C-INT-10), direction field (C-INT-11)
//   - KEPT: Guard variable (C-INT-13), non-enumerable globals (C-INT-15)
//
// LAST HISTORY LOG:
//   v5.0.0: 42 categories, 110+ hooks, smartHookGetter, 887 lines
//   v5.1.0-Final: REGRESSION — wrong file (v3, 586 lines, getInterceptorScript)
//   v6.0.0: Restored correct v5.0.0 interceptor, version bump only
//
// CONTRACT: C-INT-01 through C-INT-15
// 42 categories, 110+ hook points
// ═══════════════════════════════════════════════════════════════════

function generateInterceptorScript() {
  return `(function() {
    'use strict';

    // ─── [C-INT-13] Guard variable with RANDOM name ───
    var guardName = '__s_' + Math.random().toString(36).substring(2, 10);
    if (window[guardName]) return;
    Object.defineProperty(window, guardName, { value: true, writable: false, enumerable: false, configurable: false });

    // ─── Globals (non-enumerable) [C-INT-15] ───
    var events = [];
    var eventCounter = 0;
    var categoriesMonitored = 42;
    var pushThreshold = 20;
    var VALUE_CAP = 500;
    var DETAIL_CAP = 500;

    Object.defineProperty(window, '__SENTINEL_DATA__', {
      value: {
        events: events,
        version: 'sentinel-v6.1.0',
        categoriesMonitored: categoriesMonitored,
        startTime: Date.now(),
        injectionFlags: { shield: !!window.__SENTINEL_SHIELD__, stealth: true, interceptor: true }
      },
      writable: false, enumerable: false, configurable: false
    });

    // ─── Utility functions ───
    var realGetDesc = Object.getOwnPropertyDescriptor;
    var realDefProp = Object.defineProperty;
    var realToString = Function.prototype.toString;
    var origFetch = window.fetch;
    var origXHROpen = XMLHttpRequest.prototype.open;
    var origXHRSend = XMLHttpRequest.prototype.send;
    var origObjKeys = Object.keys;
    var origObjGetOwnPropNames = Object.getOwnPropertyNames;

    function safeStr(v) {
      if (v === undefined) return 'undefined';
      if (v === null) return 'null';
      try {
        var s = typeof v === 'object' ? JSON.stringify(v) : String(v);
        return s.length > VALUE_CAP ? s.substring(0, VALUE_CAP) + '...[truncated]' : s;
      } catch(e) { return '[unserializable]'; }
    }

    function getStack() {
      try {
        var e = new Error();
        var stack = e.stack || '';
        var lines = stack.split('\\n').slice(2, 5);
        var cleaned = [];
        for (var i = 0; i < lines.length; i++) {
          var l = lines[i].trim();
          if (l.indexOf('sentinel') === -1 && l.indexOf('addInitScript') === -1) {
            cleaned.push(l);
          }
        }
        return cleaned.join(' | ') || 'unknown';
      } catch(e) { return 'unknown'; }
    }

    // ─── [C-INT-11] Core log function with direction field ───
    function log(cat, api, detail, opts) {
      opts = opts || {};
      var evt = {
        ts: Date.now(),
        cat: cat,
        api: api,
        risk: opts.risk || 'medium',
        val: safeStr(opts.val),
        detail: (detail || '').substring(0, DETAIL_CAP),
        src: opts.src || getStack(),
        dir: opts.dir || 'call',
        fid: opts.fid || 'main'
      };
      events.push(evt);
      eventCounter++;

      // [C-INT-10] Push telemetry
      if (eventCounter % pushThreshold === 0 && typeof window.SENTINEL_PUSH === 'function') {
        try {
          window.SENTINEL_PUSH(JSON.stringify({ type: 'EVENTS', data: events.splice(0, events.length) }));
        } catch(e) {}
      }
    }

    // ─── Shield integration (optional graceful fallback) ───
    var shield = window.__SENTINEL_SHIELD__ || null;

    function hookFn(target, prop, cat, risk, opts) {
      opts = opts || {};
      try {
        var original = target[prop];
        if (typeof original !== 'function') return false;
        var origStr;
        try { origStr = realToString.call(original); } catch(e) { origStr = 'function ' + prop + '() { [native code] }'; }
        var hooked = function() {
          var val;
          try { val = original.apply(this, arguments); } catch(e) { val = e.message; throw e; }
          var argStr = '';
          for (var i = 0; i < arguments.length && i < 3; i++) {
            if (i > 0) argStr += ', ';
            argStr += safeStr(arguments[i]);
          }
          log(cat, prop, (opts.why || prop) + '(' + argStr + ')', {
            risk: risk, val: val, dir: opts.returnCapture ? 'response' : 'call'
          });
          return val;
        };
        if (shield) {
          shield.hookFunction(target, prop, function(ctx, args) {
            var argStr = '';
            for (var i = 0; i < args.length && i < 3; i++) {
              if (i > 0) argStr += ', ';
              argStr += safeStr(args[i]);
            }
            log(cat, prop, (opts.why || prop) + '(' + argStr + ')', { risk: risk, dir: 'call' });
          });
        } else {
          target[prop] = hooked;
        }
        return true;
      } catch(e) { return false; }
    }

    function hookGetter(target, prop, cat, risk, opts) {
      opts = opts || {};
      try {
        if (shield) {
          return shield.hookGetter(target, prop, function(ctx, p, val) {
            log(cat, p, (opts.why || p) + ' → ' + safeStr(val), { risk: risk, val: val, dir: 'response' });
          });
        }
        var desc = realGetDesc.call(Object, target, prop);
        if (!desc || !desc.get) return false;
        var origGet = desc.get;
        realDefProp(target, prop, {
          get: function() {
            var val = origGet.call(this);
            log(cat, prop, (opts.why || prop) + ' → ' + safeStr(val), { risk: risk, val: val, dir: 'response' });
            return val;
          },
          set: desc.set, enumerable: desc.enumerable, configurable: desc.configurable
        });
        return true;
      } catch(e) { return false; }
    }

    // ─── [C-INT-01] smartHookGetter — prevents prototype shadow bug (v4.4.0 fatal) ───
    function smartHookGetter(protoTarget, instanceTarget, prop, cat, risk, opts) {
      var instanceDesc = realGetDesc.call(Object, instanceTarget, prop);
      var protoDesc = realGetDesc.call(Object, protoTarget, prop);
      if (instanceDesc && instanceDesc.get) {
        return hookGetter(instanceTarget, prop, cat, risk, opts);
      } else if (protoDesc && protoDesc.get) {
        return hookGetter(protoTarget, prop, cat, risk, opts);
      }
      return false;
    }

    // ─── [C-INT-02] hookGetterSetter for cookie r/w ───
    function hookGetterSetter(target, prop, cat, risk, getWhy, setWhy) {
      try {
        if (shield) {
          return shield.hookGetterSetter(target, prop,
            function(ctx, p, val) { log(cat, p + ' [read]', getWhy + ' → ' + safeStr(val), { risk: risk, val: val, dir: 'response' }); },
            function(ctx, p, val) { log(cat, p + ' [write]', setWhy + ': ' + safeStr(val), { risk: 'high', val: val, dir: 'call' }); }
          );
        }
        var desc = realGetDesc.call(Object, target, prop);
        if (!desc) return false;
        var origGet = desc.get;
        var origSet = desc.set;
        realDefProp(target, prop, {
          get: function() {
            var val = origGet ? origGet.call(this) : undefined;
            log(cat, prop + ' [read]', getWhy + ' → ' + safeStr(val), { risk: risk, val: val, dir: 'response' });
            return val;
          },
          set: function(v) {
            log(cat, prop + ' [write]', setWhy + ': ' + safeStr(v), { risk: 'high', val: v, dir: 'call' });
            if (origSet) origSet.call(this, v);
          },
          enumerable: desc.enumerable, configurable: desc.configurable
        });
        return true;
      } catch(e) { return false; }
    }


    // ════════════════════════════════════════════════════
    //  SECTION 1: CANVAS FINGERPRINTING (#1 canvas) — HIGH
    // ════════════════════════════════════════════════════
    hookFn(HTMLCanvasElement.prototype, 'toDataURL', 'canvas', 'high', { why: 'Canvas fingerprint extraction' });
    hookFn(HTMLCanvasElement.prototype, 'toBlob', 'canvas', 'high', { why: 'Canvas blob extraction' });
    try { hookFn(HTMLCanvasElement.prototype, 'getContext', 'canvas', 'medium', { why: 'Canvas context creation' }); } catch(e) {}
    try {
      hookFn(CanvasRenderingContext2D.prototype, 'fillText', 'canvas', 'high', { why: 'Canvas text rendering' });
      hookFn(CanvasRenderingContext2D.prototype, 'strokeText', 'canvas', 'high', { why: 'Canvas stroke text' });
      hookFn(CanvasRenderingContext2D.prototype, 'getImageData', 'canvas', 'high', { why: 'Canvas pixel readback' });
      hookFn(CanvasRenderingContext2D.prototype, 'isPointInPath', 'canvas', 'high', { why: 'Canvas point-in-path test' });
      hookFn(CanvasRenderingContext2D.prototype, 'measureText', 'canvas', 'medium', { why: 'Canvas text measurement' });
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 2: WEBGL FINGERPRINTING (#2 webgl) — HIGH
    // ════════════════════════════════════════════════════
    var webglProtos = [];
    try { webglProtos.push(WebGLRenderingContext.prototype); } catch(e) {}
    try { webglProtos.push(WebGL2RenderingContext.prototype); } catch(e) {}
    for (var wi = 0; wi < webglProtos.length; wi++) {
      var wgl = webglProtos[wi];
      hookFn(wgl, 'getParameter', 'webgl', 'high', { why: 'WebGL parameter read', returnCapture: true });
      hookFn(wgl, 'getExtension', 'webgl', 'high', { why: 'WebGL extension query' });
      hookFn(wgl, 'getSupportedExtensions', 'webgl', 'high', { why: 'WebGL supported extensions list' });
      hookFn(wgl, 'readPixels', 'webgl', 'high', { why: 'WebGL pixel readback' });
      hookFn(wgl, 'getShaderPrecisionFormat', 'webgl', 'high', { why: 'WebGL shader precision' });
      hookFn(wgl, 'createBuffer', 'webgl', 'low', { why: 'WebGL buffer creation' });
    }


    // ════════════════════════════════════════════════════
    //  SECTION 3: AUDIO FINGERPRINTING (#3 audio) — CRITICAL
    // ════════════════════════════════════════════════════
    try {
      hookFn(OfflineAudioContext.prototype, 'startRendering', 'audio', 'critical', { why: 'Audio fingerprint rendering' });
      hookFn(BaseAudioContext.prototype, 'createOscillator', 'audio', 'critical', { why: 'Audio oscillator creation' });
      hookFn(BaseAudioContext.prototype, 'createDynamicsCompressor', 'audio', 'critical', { why: 'Audio compressor creation' });
      hookFn(BaseAudioContext.prototype, 'createAnalyser', 'audio', 'high', { why: 'Audio analyser creation' });
      hookFn(BaseAudioContext.prototype, 'createGain', 'audio', 'medium', { why: 'Audio gain node' });
      hookGetter(AudioContext.prototype, 'baseLatency', 'audio', 'high', { why: 'Audio latency fingerprint' });
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 4: FONT DETECTION (#4 font-detection) — CRITICAL
    // ════════════════════════════════════════════════════
    try {
      var origGetBCR = Element.prototype.getBoundingClientRect;
      Element.prototype.getBoundingClientRect = function() {
        var result = origGetBCR.call(this);
        var tag = (this.tagName || '').toLowerCase();
        if (tag === 'span' || tag === 'div') {
          var style = this.style || {};
          if (style.fontFamily || this.getAttribute && this.getAttribute('style')) {
            log('font-detection', 'getBoundingClientRect', 'Font width/height probe: ' + (style.fontFamily || ''), { risk: 'critical', val: result.width + 'x' + result.height, dir: 'response' });
          }
        }
        return result;
      };
    } catch(e) {}
    try { hookFn(document, 'fonts', 'font-detection', 'critical', { why: 'Document.fonts access' }); } catch(e) {}
    try {
      if (document.fonts && document.fonts.check) {
        hookFn(document.fonts, 'check', 'font-detection', 'critical', { why: 'Font availability check' });
      }
    } catch(e) {}
    try { hookFn(FontFace.prototype, 'load', 'font-detection', 'high', { why: 'FontFace load' }); } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 5: NAVIGATOR FINGERPRINTING (#5 fingerprint) — HIGH
    //  [C-INT-01] smartHookGetter for ALL 19 navigator props
    // ════════════════════════════════════════════════════
    var navProps = [
      'userAgent', 'vendor', 'platform', 'language', 'languages',
      'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints',
      'plugins', 'mimeTypes', 'cookieEnabled', 'doNotTrack',
      'appName', 'appVersion', 'product', 'productSub',
      'vendorSub', 'oscpu', 'buildID'
    ];
    for (var ni = 0; ni < navProps.length; ni++) {
      smartHookGetter(Navigator.prototype, navigator, navProps[ni], 'fingerprint', 'high', { why: 'navigator.' + navProps[ni] + ' fingerprint read' });
    }


    // ════════════════════════════════════════════════════
    //  SECTION 6: SCREEN PROPERTIES (#6 screen) — MEDIUM
    // ════════════════════════════════════════════════════
    var screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
    for (var si = 0; si < screenProps.length; si++) {
      smartHookGetter(Screen.prototype, screen, screenProps[si], 'screen', 'medium', { why: 'screen.' + screenProps[si] + ' probe' });
    }
    hookGetter(window, 'devicePixelRatio', 'screen', 'medium', { why: 'window.devicePixelRatio probe' });
    hookGetter(window, 'outerWidth', 'screen', 'medium', { why: 'window.outerWidth probe' });
    hookGetter(window, 'outerHeight', 'screen', 'medium', { why: 'window.outerHeight probe' });
    hookGetter(window, 'innerWidth', 'screen', 'low', { why: 'window.innerWidth probe' });
    hookGetter(window, 'innerHeight', 'screen', 'low', { why: 'window.innerHeight probe' });


    // ════════════════════════════════════════════════════
    //  SECTION 7: STORAGE (#7 storage) — MEDIUM
    //  [C-INT-02] hookGetterSetter for cookie read + write
    // ════════════════════════════════════════════════════
    hookGetterSetter(Document.prototype, 'cookie', 'storage', 'medium',
      'document.cookie read — tracking data access',
      'document.cookie write — tracking cookie creation'
    );
    try { hookGetter(window, 'localStorage', 'storage', 'medium', { why: 'localStorage access' }); } catch(e) {}
    try { hookGetter(window, 'sessionStorage', 'storage', 'medium', { why: 'sessionStorage access' }); } catch(e) {}
    try { hookGetter(window, 'indexedDB', 'storage', 'medium', { why: 'IndexedDB access' }); } catch(e) {}
    try { hookFn(window, 'openDatabase', 'storage', 'medium', { why: 'WebSQL openDatabase' }); } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 8: NETWORK (#8 network) — MEDIUM
    //  [C-INT-06] Dual-log: both 'network' AND 'exfiltration'
    // ════════════════════════════════════════════════════
    window.fetch = function() {
      var url = arguments[0];
      if (typeof url === 'object' && url.url) url = url.url;
      var method = (arguments[1] && arguments[1].method) || 'GET';
      var body = (arguments[1] && arguments[1].body) ? safeStr(arguments[1].body) : '';
      log('network', 'fetch', method + ' ' + safeStr(url), { risk: 'medium', dir: 'call' });
      if (method === 'POST' || body) {
        log('exfiltration', 'fetch', 'POST data: ' + body + ' → ' + safeStr(url), { risk: 'critical', dir: 'call' });
      }
      return origFetch.apply(this, arguments);
    };

    XMLHttpRequest.prototype.open = function(method, url) {
      this.__sentinel_method = method;
      this.__sentinel_url = url;
      log('network', 'XMLHttpRequest.open', method + ' ' + safeStr(url), { risk: 'medium', dir: 'call' });
      return origXHROpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function(body) {
      if (body) {
        log('exfiltration', 'XMLHttpRequest.send', 'XHR data: ' + safeStr(body) + ' → ' + safeStr(this.__sentinel_url), { risk: 'critical', dir: 'call' });
      }
      return origXHRSend.apply(this, arguments);
    };

    try {
      var origES = window.EventSource;
      if (origES) {
        window.EventSource = function(url, opts) {
          log('network', 'EventSource', 'SSE connection: ' + safeStr(url), { risk: 'medium', dir: 'call' });
          return new origES(url, opts);
        };
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 9: PERFORMANCE TIMING (#9 perf-timing) — MEDIUM
    // ════════════════════════════════════════════════════
    hookFn(Performance.prototype, 'now', 'perf-timing', 'medium', { why: 'High-precision timer', returnCapture: true });
    try { hookFn(Performance.prototype, 'mark', 'perf-timing', 'medium', { why: 'Performance mark' }); } catch(e) {}
    try { hookFn(Performance.prototype, 'measure', 'perf-timing', 'medium', { why: 'Performance measure' }); } catch(e) {}
    try { hookFn(Performance.prototype, 'getEntriesByType', 'perf-timing', 'medium', { why: 'Performance entries query' }); } catch(e) {}
    try { hookFn(Performance.prototype, 'getEntriesByName', 'perf-timing', 'medium', { why: 'Performance entries by name' }); } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 10: MEDIA DEVICES (#10 media-devices) — CRITICAL
    // ════════════════════════════════════════════════════
    try { hookFn(MediaDevices.prototype, 'enumerateDevices', 'media-devices', 'critical', { why: 'Device enumeration fingerprint' }); } catch(e) {}
    try { hookFn(MediaDevices.prototype, 'getUserMedia', 'media-devices', 'critical', { why: 'Camera/mic access request' }); } catch(e) {}
    try { hookFn(MediaDevices.prototype, 'getDisplayMedia', 'media-devices', 'critical', { why: 'Screen capture request' }); } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 11: DOM PROBING (#11 dom-probe) — MEDIUM
    //  [C-INT-04] Filtered createElement — FP tags only
    // ════════════════════════════════════════════════════
    var origCreateElement = document.createElement;
    var fpTags = ['canvas','iframe','audio','video','object','embed','script','link','img'];
    document.createElement = function(tag) {
      var result = origCreateElement.apply(this, arguments);
      var lTag = (tag || '').toLowerCase();
      if (fpTags.indexOf(lTag) >= 0) {
        log('dom-probe', 'createElement', 'tag: ' + lTag, { risk: 'medium', dir: 'call' });
      }
      return result;
    };
    try { hookFn(window, 'MutationObserver', 'dom-probe', 'medium', { why: 'DOM mutation observer creation' }); } catch(e) {}
    try { hookFn(window, 'IntersectionObserver', 'dom-probe', 'medium', { why: 'Intersection observer creation' }); } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 12: CLIPBOARD (#12 clipboard) — CRITICAL
    // ════════════════════════════════════════════════════
    try {
      if (navigator.clipboard) {
        hookFn(navigator.clipboard, 'readText', 'clipboard', 'critical', { why: 'Clipboard read' });
        hookFn(navigator.clipboard, 'writeText', 'clipboard', 'critical', { why: 'Clipboard write' });
        hookFn(navigator.clipboard, 'read', 'clipboard', 'critical', { why: 'Clipboard read binary' });
        hookFn(navigator.clipboard, 'write', 'clipboard', 'critical', { why: 'Clipboard write binary' });
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 13: GEOLOCATION (#13 geolocation) — CRITICAL
    // ════════════════════════════════════════════════════
    try {
      hookFn(Geolocation.prototype, 'getCurrentPosition', 'geolocation', 'critical', { why: 'Location access' });
      hookFn(Geolocation.prototype, 'watchPosition', 'geolocation', 'critical', { why: 'Location tracking' });
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 14: SERVICE WORKER (#14 service-worker) — HIGH
    // ════════════════════════════════════════════════════
    try {
      hookFn(ServiceWorkerContainer.prototype, 'register', 'service-worker', 'high', { why: 'SW registration' });
      hookFn(ServiceWorkerContainer.prototype, 'getRegistration', 'service-worker', 'high', { why: 'SW get registration' });
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 15: HARDWARE (#15 hardware) — HIGH
    // ════════════════════════════════════════════════════
    try { hookFn(Navigator.prototype, 'getGamepads', 'hardware', 'high', { why: 'Gamepad enumeration' }); } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 16: EXFILTRATION (#16 exfiltration) — CRITICAL
    // ════════════════════════════════════════════════════
    try { hookFn(Navigator.prototype, 'sendBeacon', 'exfiltration', 'critical', { why: 'Beacon data exfiltration' }); } catch(e) {}
    var origWS = window.WebSocket;
    try {
      window.WebSocket = function(url, protocols) {
        log('exfiltration', 'WebSocket', 'WS connection: ' + safeStr(url), { risk: 'critical', dir: 'call' });
        if (protocols) return new origWS(url, protocols);
        return new origWS(url);
      };
      window.WebSocket.prototype = origWS.prototype;
      window.WebSocket.CONNECTING = origWS.CONNECTING;
      window.WebSocket.OPEN = origWS.OPEN;
      window.WebSocket.CLOSING = origWS.CLOSING;
      window.WebSocket.CLOSED = origWS.CLOSED;
    } catch(e) {}
    try {
      var origImgSrc = realGetDesc.call(Object, HTMLImageElement.prototype, 'src');
      if (origImgSrc && origImgSrc.set) {
        var origImgSet = origImgSrc.set;
        realDefProp(HTMLImageElement.prototype, 'src', {
          set: function(v) {
            if (v && typeof v === 'string' && (v.indexOf('http') === 0 || v.indexOf('//') === 0)) {
              log('exfiltration', 'Image.src', 'Image beacon: ' + safeStr(v), { risk: 'high', dir: 'call' });
            }
            return origImgSet.call(this, v);
          },
          get: origImgSrc.get, enumerable: true, configurable: true
        });
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 17: WEBRTC (#17 webrtc) — CRITICAL
    // ════════════════════════════════════════════════════
    var origRTC = window.RTCPeerConnection;
    try {
      window.RTCPeerConnection = function(config) {
        log('webrtc', 'RTCPeerConnection', 'ICE config: ' + safeStr(config), { risk: 'critical', dir: 'call' });
        var pc = new origRTC(config);
        var origCreateDC = pc.createDataChannel;
        pc.createDataChannel = function() {
          log('webrtc', 'createDataChannel', 'Data channel created', { risk: 'critical', dir: 'call' });
          return origCreateDC.apply(this, arguments);
        };
        pc.addEventListener('icecandidate', function(e) {
          if (e && e.candidate) {
            log('webrtc', 'onicecandidate', 'ICE candidate: ' + safeStr(e.candidate.candidate), { risk: 'critical', dir: 'response' });
          }
        });
        return pc;
      };
      window.RTCPeerConnection.prototype = origRTC.prototype;
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 18: MATH FINGERPRINTING (#18 math-fingerprint) — MEDIUM
    // ════════════════════════════════════════════════════
    var mathFns = ['acos','acosh','asin','asinh','atan','atanh','atan2','cos','cosh','exp','expm1','log','log1p','log2','log10','sin','sinh','sqrt','tan','tanh','cbrt'];
    for (var mi = 0; mi < mathFns.length; mi++) {
      (function(fnName) {
        var orig = Math[fnName];
        if (typeof orig !== 'function') return;
        Math[fnName] = function() {
          var result = orig.apply(Math, arguments);
          log('math-fingerprint', 'Math.' + fnName, 'Math.' + fnName + '(' + safeStr(arguments[0]) + ') → ' + result, { risk: 'medium', val: result, dir: 'response' });
          return result;
        };
      })(mathFns[mi]);
    }


    // ════════════════════════════════════════════════════
    //  SECTION 19: PERMISSIONS (#19 permissions) — HIGH
    //  Hook in interceptor ONLY (NOT stealth!) — v4.6.2 lesson
    // ════════════════════════════════════════════════════
    try {
      if (navigator.permissions && navigator.permissions.query) {
        hookFn(navigator.permissions, 'query', 'permissions', 'high', { why: 'Permission state probe' });
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 20: SPEECH (#20 speech) — HIGH
    // ════════════════════════════════════════════════════
    try {
      if (window.speechSynthesis) {
        hookFn(window.speechSynthesis, 'getVoices', 'speech', 'high', { why: 'Voice enumeration fingerprint' });
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 21: CLIENT HINTS (#21 client-hints) — CRITICAL
    // ════════════════════════════════════════════════════
    try {
      if (navigator.userAgentData) {
        hookFn(navigator.userAgentData, 'getHighEntropyValues', 'client-hints', 'critical', { why: 'High-entropy client hints' });
        hookGetter(navigator.userAgentData, 'brands', 'client-hints', 'high', { why: 'UA brands read' });
        hookGetter(navigator.userAgentData, 'platform', 'client-hints', 'high', { why: 'UA platform read' });
        hookGetter(navigator.userAgentData, 'mobile', 'client-hints', 'medium', { why: 'UA mobile check' });
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 22: INTL FINGERPRINTING (#22 intl-fingerprint) — MEDIUM
    // ════════════════════════════════════════════════════
    var intlTypes = ['DateTimeFormat','NumberFormat','Collator','ListFormat','RelativeTimeFormat','PluralRules'];
    for (var ii = 0; ii < intlTypes.length; ii++) {
      (function(typeName) {
        try {
          if (Intl[typeName] && Intl[typeName].prototype.resolvedOptions) {
            hookFn(Intl[typeName].prototype, 'resolvedOptions', 'intl-fingerprint', 'medium', { why: 'Intl.' + typeName + '.resolvedOptions' });
          }
        } catch(e) {}
      })(intlTypes[ii]);
    }


    // ════════════════════════════════════════════════════
    //  SECTION 23: CSS FINGERPRINTING (#23 css-fingerprint) — MEDIUM
    //  [C-INT-08] matchMedia hook with value capture
    // ════════════════════════════════════════════════════
    try {
      if (CSS && CSS.supports) {
        hookFn(CSS, 'supports', 'css-fingerprint', 'medium', { why: 'CSS.supports feature detection' });
      }
    } catch(e) {}
    try {
      var origMatchMedia = window.matchMedia;
      window.matchMedia = function(query) {
        log('css-fingerprint', 'matchMedia', 'Media query: ' + safeStr(query), { risk: 'medium', dir: 'call' });
        var result = origMatchMedia.call(window, query);
        log('css-fingerprint', 'matchMedia', 'matchMedia(' + safeStr(query) + ') → matches:' + result.matches, { risk: 'medium', val: result.matches, dir: 'response' });
        return result;
      };
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 24: PROPERTY ENUMERATION (#24 property-enum) — HIGH
    //  [C-INT-03] Filtered: ONLY navigator/screen/prototype
    // ════════════════════════════════════════════════════
    Object.keys = function(obj) {
      var result = origObjKeys.call(Object, obj);
      if (obj === navigator || obj === screen || obj === Navigator.prototype || obj === Screen.prototype || obj === window) {
        log('property-enum', 'Object.keys', 'Object.keys on ' + (obj === navigator ? 'navigator' : obj === screen ? 'screen' : obj === window ? 'window' : 'prototype'), { risk: 'high', val: result.length + ' keys', dir: 'response' });
      }
      return result;
    };
    Object.getOwnPropertyNames = function(obj) {
      var result = origObjGetOwnPropNames.call(Object, obj);
      if (obj === navigator || obj === screen || obj === Navigator.prototype || obj === Screen.prototype || obj === window) {
        log('property-enum', 'Object.getOwnPropertyNames', 'getOwnPropertyNames on ' + (obj === navigator ? 'navigator' : obj === screen ? 'screen' : obj === window ? 'window' : 'prototype'), { risk: 'high', val: result.length + ' props', dir: 'response' });
      }
      return result;
    };


    // ════════════════════════════════════════════════════
    //  SECTION 25: OFFSCREEN CANVAS (#25 offscreen-canvas) — HIGH
    // ════════════════════════════════════════════════════
    try {
      if (typeof OffscreenCanvas !== 'undefined') {
        hookFn(OffscreenCanvas.prototype, 'getContext', 'offscreen-canvas', 'high', { why: 'OffscreenCanvas context' });
        hookFn(OffscreenCanvas.prototype, 'transferToImageBitmap', 'offscreen-canvas', 'high', { why: 'OffscreenCanvas bitmap transfer' });
        hookFn(OffscreenCanvas.prototype, 'convertToBlob', 'offscreen-canvas', 'high', { why: 'OffscreenCanvas blob export' });
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 26: HONEYPOT (#26 honeypot) — CRITICAL
    // ════════════════════════════════════════════════════
    var traps = [
      { name: '__fpjs_d_m', desc: 'FingerprintJS trap' },
      { name: '_Selenium_IDE_Recorder', desc: 'Selenium trap' },
      { name: '__selenium_evaluate', desc: 'Selenium evaluate trap' },
      { name: 'callPhantom', desc: 'PhantomJS trap' },
      { name: '_phantom', desc: 'Phantom trap' },
      { name: '__nightmare', desc: 'Nightmare trap' }
    ];
    for (var ti = 0; ti < traps.length; ti++) {
      (function(trap) {
        try {
          realDefProp(window, trap.name, {
            get: function() {
              log('honeypot', trap.name, trap.desc + ' accessed', { risk: 'critical', dir: 'call' });
              return undefined;
            },
            set: function() {},
            enumerable: false, configurable: true
          });
        } catch(e) {}
      })(traps[ti]);
    }


    // ════════════════════════════════════════════════════
    //  SECTION 27: CREDENTIALS (#27 credential) — CRITICAL
    // ════════════════════════════════════════════════════
    try {
      if (navigator.credentials) {
        hookFn(navigator.credentials, 'get', 'credential', 'critical', { why: 'Credential access' });
        hookFn(navigator.credentials, 'create', 'credential', 'critical', { why: 'Credential creation' });
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 28: SYSTEM / BOOT (#28 system) — INFO
    //  [C-INT-09] BOOT_OK mandatory
    // ════════════════════════════════════════════════════
    log('system', 'BOOT_OK', 'Sentinel v6.0.0 interceptor active — ' + categoriesMonitored + ' categories', { risk: 'info', dir: 'call' });


    // ════════════════════════════════════════════════════
    //  SECTION 29: ENCODING (#29 encoding) — LOW
    // ════════════════════════════════════════════════════
    try { hookFn(TextEncoder.prototype, 'encode', 'encoding', 'low', { why: 'TextEncoder probe' }); } catch(e) {}
    try { hookFn(TextDecoder.prototype, 'decode', 'encoding', 'low', { why: 'TextDecoder probe' }); } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 30: WORKER (#30 worker) — HIGH
    // ════════════════════════════════════════════════════
    var origWorker = window.Worker;
    try {
      window.Worker = function(url, opts) {
        log('worker', 'Worker', 'New Worker: ' + safeStr(url), { risk: 'high', dir: 'call' });
        return new origWorker(url, opts);
      };
      window.Worker.prototype = origWorker.prototype;
    } catch(e) {}
    var origSharedWorker = window.SharedWorker;
    try {
      if (origSharedWorker) {
        window.SharedWorker = function(url, opts) {
          log('worker', 'SharedWorker', 'New SharedWorker: ' + safeStr(url), { risk: 'high', dir: 'call' });
          return new origSharedWorker(url, opts);
        };
        window.SharedWorker.prototype = origSharedWorker.prototype;
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 31: WEBASSEMBLY (#31 webassembly) — CRITICAL
    // ════════════════════════════════════════════════════
    try {
      if (typeof WebAssembly !== 'undefined') {
        hookFn(WebAssembly, 'instantiate', 'webassembly', 'critical', { why: 'WASM instantiation' });
        hookFn(WebAssembly, 'compile', 'webassembly', 'critical', { why: 'WASM compilation' });
        hookFn(WebAssembly, 'instantiateStreaming', 'webassembly', 'critical', { why: 'WASM streaming instantiation' });
        hookFn(WebAssembly, 'validate', 'webassembly', 'high', { why: 'WASM validation' });
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 32: KEYBOARD LAYOUT (#32 keyboard-layout) — HIGH
    // ════════════════════════════════════════════════════
    try {
      if (navigator.keyboard && navigator.keyboard.getLayoutMap) {
        hookFn(navigator.keyboard, 'getLayoutMap', 'keyboard-layout', 'high', { why: 'Keyboard layout fingerprint' });
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 33: SENSOR APIS (#33 sensor-apis) — HIGH
    // ════════════════════════════════════════════════════
    var sensorClasses = ['Accelerometer','Gyroscope','LinearAccelerationSensor','AbsoluteOrientationSensor','RelativeOrientationSensor','AmbientLightSensor','Magnetometer','GravitySensor'];
    for (var sci = 0; sci < sensorClasses.length; sci++) {
      (function(cls) {
        try {
          if (window[cls]) {
            var origCls = window[cls];
            window[cls] = function(opts) {
              log('sensor-apis', cls, cls + ' instantiated', { risk: 'high', dir: 'call' });
              return new origCls(opts);
            };
            window[cls].prototype = origCls.prototype;
          }
        } catch(e) {}
      })(sensorClasses[sci]);
    }


    // ════════════════════════════════════════════════════
    //  SECTION 34: VISUALIZATION (#34 visualization) — MEDIUM
    // ════════════════════════════════════════════════════
    var origRAF = window.requestAnimationFrame;
    var rafCount = 0;
    if (origRAF) {
      window.requestAnimationFrame = function(cb) {
        rafCount++;
        if (rafCount <= 5 || rafCount % 50 === 0) {
          log('visualization', 'requestAnimationFrame', 'rAF call #' + rafCount, { risk: 'medium', dir: 'call' });
        }
        return origRAF.call(window, cb);
      };
    }


    // ════════════════════════════════════════════════════
    //  SECTION 35: BATTERY (#35 battery) — HIGH
    //  [C-INT-07] navigator.getBattery() — restored from v3
    // ════════════════════════════════════════════════════
    try {
      if (navigator.getBattery) {
        var origGetBattery = navigator.getBattery;
        navigator.getBattery = function() {
          log('battery', 'getBattery', 'Battery API access', { risk: 'high', dir: 'call' });
          return origGetBattery.call(navigator).then(function(battery) {
            log('battery', 'getBattery', 'Battery: charging=' + battery.charging + ', level=' + battery.level, { risk: 'high', val: battery.level, dir: 'response' });
            return battery;
          });
        };
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 36: EVENT MONITORING (#36 event-monitoring) — MEDIUM
    //  [C-INT-05] focus, blur, visibility, resize, sensors
    //  Restored from v4.6.3 — was deleted in v4.6.2!
    // ════════════════════════════════════════════════════
    var monitoredEvents = ['focus','blur','visibilitychange','resize','devicemotion','deviceorientation'];
    var origAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, listener, opts) {
      if (monitoredEvents.indexOf(type) >= 0) {
        log('event-monitoring', 'addEventListener', 'Listener added: ' + type, { risk: 'medium', dir: 'call' });
      }
      return origAddEventListener.call(this, type, listener, opts);
    };


    // ════════════════════════════════════════════════════
    //  SECTION 37: BLOB URL (#37 blob-url) — HIGH
    // ════════════════════════════════════════════════════
    try {
      var origCreateObjectURL = URL.createObjectURL;
      URL.createObjectURL = function(blob) {
        log('blob-url', 'URL.createObjectURL', 'Blob URL created, type: ' + (blob && blob.type || 'unknown'), { risk: 'high', dir: 'call' });
        return origCreateObjectURL.call(URL, blob);
      };
    } catch(e) {}
    try {
      var origBlob = window.Blob;
      window.Blob = function(parts, opts) {
        var type = (opts && opts.type) || 'unknown';
        if (type.indexOf('javascript') >= 0 || type.indexOf('wasm') >= 0) {
          log('blob-url', 'Blob', 'Dynamic code blob: type=' + type, { risk: 'high', dir: 'call' });
        }
        return new origBlob(parts, opts);
      };
      window.Blob.prototype = origBlob.prototype;
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 38: SHARED ARRAY BUFFER (#38 shared-array-buffer) — HIGH
    // ════════════════════════════════════════════════════
    try {
      if (typeof SharedArrayBuffer !== 'undefined') {
        var origSAB = SharedArrayBuffer;
        window.SharedArrayBuffer = function(len) {
          log('shared-array-buffer', 'SharedArrayBuffer', 'SAB created: ' + len + ' bytes (timing attack vector)', { risk: 'high', dir: 'call' });
          return new origSAB(len);
        };
        window.SharedArrayBuffer.prototype = origSAB.prototype;
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 39: POSTMESSAGE EXFIL (#39 postmessage-exfil) — MEDIUM
    // ════════════════════════════════════════════════════
    var origPostMessage = window.postMessage;
    window.postMessage = function(data, origin) {
      log('postmessage-exfil', 'postMessage', 'Cross-frame message → ' + safeStr(origin), { risk: 'medium', val: safeStr(data), dir: 'call' });
      return origPostMessage.apply(window, arguments);
    };
    origAddEventListener.call(window, 'message', function(e) {
      log('postmessage-exfil', 'onmessage', 'Message received from: ' + (e.origin || 'unknown'), { risk: 'medium', val: safeStr(e.data), dir: 'response' });
    });


    // ════════════════════════════════════════════════════
    //  SECTION 40: PERFORMANCE NOW (granular) (#40 performance-now) — MEDIUM
    //  Extended from perf-timing — tracks precision abuse
    // ════════════════════════════════════════════════════
    // Already hooked in section 9; this section adds cross-reference for timing attacks
    // High-frequency performance.now calls are flagged by correlation engine


    // ════════════════════════════════════════════════════
    //  SECTION 41: DEVICE INFO (#41 device-info) — MEDIUM
    // ════════════════════════════════════════════════════
    try {
      if (navigator.connection) {
        hookGetter(navigator.connection, 'effectiveType', 'device-info', 'medium', { why: 'Network connection type' });
        hookGetter(navigator.connection, 'downlink', 'device-info', 'medium', { why: 'Network downlink speed' });
        hookGetter(navigator.connection, 'rtt', 'device-info', 'medium', { why: 'Network RTT' });
        hookGetter(navigator.connection, 'saveData', 'device-info', 'medium', { why: 'Data saver mode' });
      }
    } catch(e) {}


    // ════════════════════════════════════════════════════
    //  SECTION 42: CROSS-FRAME COMM (#42 cross-frame-comm) — MEDIUM
    // ════════════════════════════════════════════════════
    // Cross-frame communication is captured via postMessage hooks in section 39
    // and iframe monitoring via frameattached/framenavigated in index.js


    // ════════════════════════════════════════════════════
    //  PUSH TELEMETRY SETUP
    //  [C-INT-10] Push every 500ms + immediate boot push
    // ════════════════════════════════════════════════════
    setInterval(function() {
      if (events.length > 0 && typeof window.SENTINEL_PUSH === 'function') {
        try {
          window.SENTINEL_PUSH(JSON.stringify({ type: 'EVENTS', data: events.splice(0, events.length) }));
        } catch(e) {}
      }
    }, 500);

    // Immediate boot push after 50ms
    setTimeout(function() {
      if (events.length > 0 && typeof window.SENTINEL_PUSH === 'function') {
        try {
          window.SENTINEL_PUSH(JSON.stringify({ type: 'EVENTS', data: events.splice(0, events.length) }));
        } catch(e) {}
      }
    }, 50);

    // SENTINEL_FLUSH handler for final collection
    Object.defineProperty(window, '__SENTINEL_FLUSH__', {
      value: function() {
        if (events.length > 0 && typeof window.SENTINEL_PUSH === 'function') {
          try {
            window.SENTINEL_PUSH(JSON.stringify({ type: 'FINAL_FLUSH', data: events.splice(0, events.length) }));
          } catch(e) {}
        }
        return window.__SENTINEL_DATA__;
      },
      writable: false, enumerable: false, configurable: false
    });

  })();`;
}

module.exports = { generateInterceptorScript };
