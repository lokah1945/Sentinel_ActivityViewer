/**
 * Sentinel v4.3 — API Interceptor
 * 200+ API hooks across 37 categories
 * ES5-compatible browser code (injected into page context)
 *
 * KEY SAFETY:
 * - Non-destructive event collection (push, not spread/reassign)
 * - BOOT_OK protocol for injection verification
 * - __SENTINEL_FLUSH__ for event retrieval
 * - No ...args, no [...spread], no arrow functions in browser code
 */

function getInterceptorScript(options) {
  options = options || {};
  var stealthEnabled = !!options.stealthEnabled;

  return `
(function() {
  'use strict';

  // ── Guard: prevent double-injection ──
  if (window.__SENTINEL_ACTIVE__) return;
  window.__SENTINEL_ACTIVE__ = true;

  // ── Event Buffer (non-destructive push only) ──
  var _events = [];
  var _startTime = Date.now();
  var _dedupMap = {};
  var _dedupCount = 0;
  var _maxEvents = 50000;

  function getTs() {
    return Date.now() - _startTime;
  }

  function dedupKey(api, cat, detail) {
    return api + '|' + cat + '|' + (detail || '').slice(0, 50);
  }

  function record(api, cat, risk, detail, value, extra) {
    if (_events.length >= _maxEvents) return;

    var key = dedupKey(api, cat, detail);
    var now = getTs();

    // Dedup: same api+cat+detail within 200ms
    if (_dedupMap[key] && (now - _dedupMap[key]) < 200) {
      _dedupCount++;
      return;
    }
    _dedupMap[key] = now;

    var evt = {
      ts: now,
      api: api,
      cat: cat || 'system',
      risk: risk || 'info',
      detail: detail || '',
      origin: (typeof location !== 'undefined') ? location.origin : '',
      frameId: (typeof window !== 'undefined' && window.frameElement) ? 'child' : 'main'
    };
    if (value !== undefined && value !== null) {
      try { evt.value = String(value).slice(0, 500); } catch(e) { evt.value = '[unreadable]'; }
    }
    if (extra) {
      var ekeys = Object.keys(extra);
      for (var i = 0; i < ekeys.length; i++) {
        evt[ekeys[i]] = extra[ekeys[i]];
      }
    }

    // Non-destructive push
    _events.push(evt);
  }

  // ── BOOT_OK: Signal successful injection ──
  record('BOOT_OK', 'system', 'info', location.href);

  // ── Flush mechanism for Node.js to retrieve events ──
  window.__SENTINEL_FLUSH__ = function() {
    var result = {
      events: _events.slice(0),
      dedupStats: { totalReceived: _events.length + _dedupCount, deduplicated: _dedupCount, kept: _events.length }
    };
    return JSON.stringify(result);
  };

  // ── Helper: safe hook ──
  function hookMethod(obj, prop, cat, risk, hookFn) {
    if (!obj || typeof obj[prop] !== 'function') return;
    var orig = obj[prop];
    try {
      obj[prop] = function() {
        var args = [];
        for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
        var detail = '';
        if (hookFn) {
          try { detail = hookFn(args, this); } catch(e) {}
        }
        record(prop, cat, risk, detail);
        return orig.apply(this, args);
      };
      // Preserve toString
      if (window.__sentinelShield__) {
        window.__sentinelShield__.hookFunction(obj, prop, obj[prop], orig);
      }
    } catch(e) {}
  }

  function hookGetter(obj, prop, cat, risk, label) {
    if (!obj) return;
    var descriptor = Object.getOwnPropertyDescriptor(obj, prop);
    if (!descriptor && obj.__proto__) {
      descriptor = Object.getOwnPropertyDescriptor(obj.__proto__, prop);
    }
    if (!descriptor) return;

    var origGet = descriptor.get || (function() { return descriptor.value; });
    try {
      Object.defineProperty(obj, prop, {
        get: function() {
          var val;
          try { val = origGet.call(this); } catch(e) { val = undefined; }
          record(label || prop, cat, risk, '', val);
          return val;
        },
        set: descriptor.set,
        enumerable: descriptor.enumerable,
        configurable: true
      });
    } catch(e) {}
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 1: CANVAS (canvas)
  // ══════════════════════════════════════════════════════

  // toDataURL
  hookMethod(HTMLCanvasElement.prototype, 'toDataURL', 'canvas', 'high', function(args) {
    return 'type=' + (args[0] || 'image/png');
  });

  // toBlob
  hookMethod(HTMLCanvasElement.prototype, 'toBlob', 'canvas', 'high', function(args) {
    return 'type=' + (args[1] || 'image/png');
  });

  // getContext
  hookMethod(HTMLCanvasElement.prototype, 'getContext', 'canvas', 'medium', function(args) {
    return 'contextType=' + args[0];
  });

  // getImageData
  if (typeof CanvasRenderingContext2D !== 'undefined') {
    hookMethod(CanvasRenderingContext2D.prototype, 'getImageData', 'canvas', 'high', function(args) {
      return args[0] + ',' + args[1] + ',' + args[2] + ',' + args[3];
    });

    hookMethod(CanvasRenderingContext2D.prototype, 'fillText', 'canvas', 'medium', function(args) {
      return 'text=' + String(args[0]).slice(0, 50);
    });

    hookMethod(CanvasRenderingContext2D.prototype, 'strokeText', 'canvas', 'medium', function(args) {
      return 'text=' + String(args[0]).slice(0, 50);
    });

    hookMethod(CanvasRenderingContext2D.prototype, 'measureText', 'font-detection', 'high', function(args) {
      return 'text=' + String(args[0]).slice(0, 30);
    });

    hookMethod(CanvasRenderingContext2D.prototype, 'isPointInPath', 'canvas', 'medium');
    hookMethod(CanvasRenderingContext2D.prototype, 'isPointInStroke', 'canvas', 'medium');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 2: WEBGL (webgl)
  // ══════════════════════════════════════════════════════

  var webglProtos = [];
  if (typeof WebGLRenderingContext !== 'undefined') webglProtos.push(WebGLRenderingContext.prototype);
  if (typeof WebGL2RenderingContext !== 'undefined') webglProtos.push(WebGL2RenderingContext.prototype);

  for (var wp = 0; wp < webglProtos.length; wp++) {
    var wProto = webglProtos[wp];

    hookMethod(wProto, 'getParameter', 'webgl', 'high', function(args) {
      return 'param=0x' + (args[0] || 0).toString(16);
    });

    hookMethod(wProto, 'getExtension', 'webgl', 'medium', function(args) {
      return 'ext=' + args[0];
    });

    hookMethod(wProto, 'getSupportedExtensions', 'webgl', 'medium');
    hookMethod(wProto, 'getShaderPrecisionFormat', 'webgl', 'high', function(args) {
      return 'shader=' + args[0] + ',precision=' + args[1];
    });

    hookMethod(wProto, 'readPixels', 'webgl', 'high');
    hookMethod(wProto, 'createBuffer', 'webgl', 'low');
    hookMethod(wProto, 'createProgram', 'webgl', 'low');
    hookMethod(wProto, 'createShader', 'webgl', 'low');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 3: AUDIO (audio)
  // ══════════════════════════════════════════════════════

  if (typeof OfflineAudioContext !== 'undefined') {
    hookMethod(OfflineAudioContext.prototype, 'startRendering', 'audio', 'critical');
    hookMethod(OfflineAudioContext.prototype, 'createOscillator', 'audio', 'high');
    hookMethod(OfflineAudioContext.prototype, 'createDynamicsCompressor', 'audio', 'high');
    hookMethod(OfflineAudioContext.prototype, 'createAnalyser', 'audio', 'high');
    hookMethod(OfflineAudioContext.prototype, 'createGain', 'audio', 'medium');
    hookMethod(OfflineAudioContext.prototype, 'createBiquadFilter', 'audio', 'medium');
  }

  if (typeof AudioContext !== 'undefined') {
    hookMethod(AudioContext.prototype, 'createOscillator', 'audio', 'high');
    hookMethod(AudioContext.prototype, 'createDynamicsCompressor', 'audio', 'high');
    hookMethod(AudioContext.prototype, 'createAnalyser', 'audio', 'high');
    hookMethod(AudioContext.prototype, 'createGain', 'audio', 'medium');
  }

  if (typeof OscillatorNode !== 'undefined') {
    hookMethod(OscillatorNode.prototype, 'connect', 'audio', 'high');
    hookMethod(OscillatorNode.prototype, 'start', 'audio', 'medium');
  }

  if (typeof AnalyserNode !== 'undefined') {
    hookMethod(AnalyserNode.prototype, 'getFloatFrequencyData', 'audio', 'high');
    hookMethod(AnalyserNode.prototype, 'getByteFrequencyData', 'audio', 'high');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 4: FONT DETECTION (font-detection)
  // ══════════════════════════════════════════════════════

  if (typeof document !== 'undefined' && document.fonts) {
    hookMethod(document.fonts, 'check', 'font-detection', 'high', function(args) {
      return 'font=' + String(args[0]).slice(0, 50);
    });
    hookMethod(document.fonts, 'load', 'font-detection', 'high', function(args) {
      return 'font=' + String(args[0]).slice(0, 50);
    });
  }

  if (typeof FontFace !== 'undefined') {
    var _origFontFace = FontFace;
    try {
      window.FontFace = function(family, source, descriptors) {
        record('FontFace', 'font-detection', 'high', 'family=' + family);
        return new _origFontFace(family, source, descriptors);
      };
      window.FontFace.prototype = _origFontFace.prototype;
    } catch(e) {}
  }

  // getBoundingClientRect for font width measurement
  if (typeof Element !== 'undefined') {
    hookMethod(Element.prototype, 'getBoundingClientRect', 'font-detection', 'medium');
    hookMethod(Element.prototype, 'getClientRects', 'font-detection', 'medium');
    hookMethod(Element.prototype, 'offsetWidth', 'font-detection', 'low');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 5: SCREEN (screen)
  // ══════════════════════════════════════════════════════

  if (typeof screen !== 'undefined') {
    var screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth', 'orientation'];
    for (var sp = 0; sp < screenProps.length; sp++) {
      hookGetter(screen, screenProps[sp], 'screen', 'medium', 'screen.' + screenProps[sp]);
    }
  }

  hookGetter(window, 'devicePixelRatio', 'screen', 'medium', 'window.devicePixelRatio');
  hookGetter(window, 'innerWidth', 'screen', 'low', 'window.innerWidth');
  hookGetter(window, 'innerHeight', 'screen', 'low', 'window.innerHeight');
  hookGetter(window, 'outerWidth', 'screen', 'low', 'window.outerWidth');
  hookGetter(window, 'outerHeight', 'screen', 'low', 'window.outerHeight');

  if (typeof matchMedia !== 'undefined') {
    hookMethod(window, 'matchMedia', 'css-fingerprint', 'medium', function(args) {
      return 'query=' + String(args[0]).slice(0, 80);
    });
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 6: STORAGE (storage)
  // ══════════════════════════════════════════════════════

  if (typeof localStorage !== 'undefined') {
    hookMethod(localStorage, 'getItem', 'storage', 'low', function(args) { return 'key=' + args[0]; });
    hookMethod(localStorage, 'setItem', 'storage', 'medium', function(args) { return 'key=' + args[0]; });
    hookMethod(localStorage, 'removeItem', 'storage', 'low', function(args) { return 'key=' + args[0]; });
  }

  if (typeof sessionStorage !== 'undefined') {
    hookMethod(sessionStorage, 'getItem', 'storage', 'low', function(args) { return 'key=' + args[0]; });
    hookMethod(sessionStorage, 'setItem', 'storage', 'medium', function(args) { return 'key=' + args[0]; });
  }

  // IndexedDB
  if (typeof indexedDB !== 'undefined') {
    hookMethod(indexedDB, 'open', 'storage', 'medium', function(args) { return 'db=' + args[0]; });
    hookMethod(indexedDB, 'deleteDatabase', 'storage', 'high', function(args) { return 'db=' + args[0]; });
  }

  // Cookies
  try {
    var _cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
                      Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
    if (_cookieDesc) {
      var _origCookieGet = _cookieDesc.get;
      var _origCookieSet = _cookieDesc.set;
      Object.defineProperty(document, 'cookie', {
        get: function() {
          record('document.cookie.get', 'storage', 'low', '');
          return _origCookieGet.call(document);
        },
        set: function(val) {
          record('document.cookie.set', 'storage', 'medium', 'cookie=' + String(val).slice(0, 50));
          return _origCookieSet.call(document, val);
        },
        configurable: true
      });
    }
  } catch(e) {}

  // ══════════════════════════════════════════════════════
  // CATEGORY 7: NETWORK / EXFILTRATION (network, exfiltration)
  // ══════════════════════════════════════════════════════

  // XMLHttpRequest
  if (typeof XMLHttpRequest !== 'undefined') {
    hookMethod(XMLHttpRequest.prototype, 'open', 'network', 'medium', function(args) {
      return args[0] + ' ' + String(args[1]).slice(0, 100);
    });
    hookMethod(XMLHttpRequest.prototype, 'send', 'network', 'high', function(args) {
      if (args[0]) record('XHR.send.data', 'exfiltration', 'high', 'bodySize=' + String(args[0]).length);
      return '';
    });
  }

  // fetch
  if (typeof fetch !== 'undefined') {
    var _origFetch = fetch;
    window.fetch = function() {
      var args = [];
      for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
      var url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url ? args[0].url : 'unknown');
      record('fetch', 'network', 'medium', 'url=' + String(url).slice(0, 100));
      if (args[1] && args[1].body) {
        record('fetch.body', 'exfiltration', 'high', 'method=' + (args[1].method || 'GET'));
      }
      return _origFetch.apply(window, args);
    };
    if (window.__sentinelShield__) {
      window.__sentinelShield__.hookFunction(window, 'fetch', window.fetch, _origFetch);
    }
  }

  // sendBeacon
  if (navigator.sendBeacon) {
    hookMethod(navigator, 'sendBeacon', 'exfiltration', 'critical', function(args) {
      return 'url=' + String(args[0]).slice(0, 100);
    });
  }

  // WebSocket
  if (typeof WebSocket !== 'undefined') {
    var _origWS = WebSocket;
    window.WebSocket = function(url, protocols) {
      record('WebSocket', 'exfiltration', 'high', 'url=' + String(url).slice(0, 100));
      if (protocols) {
        return new _origWS(url, protocols);
      }
      return new _origWS(url);
    };
    window.WebSocket.prototype = _origWS.prototype;
    window.WebSocket.CONNECTING = _origWS.CONNECTING;
    window.WebSocket.OPEN = _origWS.OPEN;
    window.WebSocket.CLOSING = _origWS.CLOSING;
    window.WebSocket.CLOSED = _origWS.CLOSED;
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 8: PERFORMANCE TIMING (perf-timing)
  // ══════════════════════════════════════════════════════

  if (typeof performance !== 'undefined') {
    hookMethod(performance, 'now', 'perf-timing', 'low');
    hookMethod(performance, 'mark', 'perf-timing', 'low', function(args) { return 'mark=' + args[0]; });
    hookMethod(performance, 'measure', 'perf-timing', 'medium', function(args) { return 'measure=' + args[0]; });
    hookMethod(performance, 'getEntries', 'perf-timing', 'medium');
    hookMethod(performance, 'getEntriesByType', 'perf-timing', 'medium', function(args) { return 'type=' + args[0]; });
    hookMethod(performance, 'getEntriesByName', 'perf-timing', 'medium', function(args) { return 'name=' + args[0]; });
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 9: MEDIA DEVICES (media-devices)
  // ══════════════════════════════════════════════════════

  if (navigator.mediaDevices) {
    hookMethod(navigator.mediaDevices, 'enumerateDevices', 'media-devices', 'critical');
    hookMethod(navigator.mediaDevices, 'getUserMedia', 'media-devices', 'critical', function(args) {
      return JSON.stringify(args[0]).slice(0, 100);
    });
    hookMethod(navigator.mediaDevices, 'getDisplayMedia', 'media-devices', 'critical');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 10: DOM PROBING (dom-probe)
  // ══════════════════════════════════════════════════════

  if (typeof MutationObserver !== 'undefined') {
    var _origMO = MutationObserver;
    window.MutationObserver = function(callback) {
      record('MutationObserver', 'dom-probe', 'medium', 'created');
      return new _origMO(callback);
    };
    window.MutationObserver.prototype = _origMO.prototype;
  }

  if (typeof IntersectionObserver !== 'undefined') {
    var _origIO = IntersectionObserver;
    window.IntersectionObserver = function(callback, options) {
      record('IntersectionObserver', 'dom-probe', 'medium', 'created');
      return new _origIO(callback, options);
    };
    window.IntersectionObserver.prototype = _origIO.prototype;
  }

  hookMethod(document, 'createElement', 'dom-probe', 'low', function(args) { return 'tag=' + args[0]; });
  hookMethod(document, 'createElementNS', 'dom-probe', 'low', function(args) { return 'ns=' + args[0] + ',tag=' + args[1]; });

  // ══════════════════════════════════════════════════════
  // CATEGORY 11: CLIPBOARD (clipboard)
  // ══════════════════════════════════════════════════════

  if (navigator.clipboard) {
    hookMethod(navigator.clipboard, 'readText', 'clipboard', 'critical');
    hookMethod(navigator.clipboard, 'writeText', 'clipboard', 'critical');
    hookMethod(navigator.clipboard, 'read', 'clipboard', 'critical');
    hookMethod(navigator.clipboard, 'write', 'clipboard', 'critical');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 12: GEOLOCATION (geolocation)
  // ══════════════════════════════════════════════════════

  if (navigator.geolocation) {
    hookMethod(navigator.geolocation, 'getCurrentPosition', 'geolocation', 'critical');
    hookMethod(navigator.geolocation, 'watchPosition', 'geolocation', 'critical');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 13: SERVICE WORKER (service-worker)
  // ══════════════════════════════════════════════════════

  if (navigator.serviceWorker) {
    hookMethod(navigator.serviceWorker, 'register', 'service-worker', 'high', function(args) {
      return 'url=' + String(args[0]).slice(0, 100);
    });
    hookMethod(navigator.serviceWorker, 'getRegistration', 'service-worker', 'medium');
    hookMethod(navigator.serviceWorker, 'getRegistrations', 'service-worker', 'medium');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 14: HARDWARE (hardware)
  // ══════════════════════════════════════════════════════

  hookGetter(navigator, 'hardwareConcurrency', 'hardware', 'high', 'navigator.hardwareConcurrency');
  hookGetter(navigator, 'deviceMemory', 'hardware', 'high', 'navigator.deviceMemory');
  hookGetter(navigator, 'platform', 'hardware', 'medium', 'navigator.platform');
  hookGetter(navigator, 'maxTouchPoints', 'hardware', 'medium', 'navigator.maxTouchPoints');
  hookGetter(navigator, 'vendor', 'hardware', 'low', 'navigator.vendor');
  hookGetter(navigator, 'userAgent', 'hardware', 'low', 'navigator.userAgent');
  hookGetter(navigator, 'appVersion', 'hardware', 'low', 'navigator.appVersion');
  hookGetter(navigator, 'product', 'hardware', 'low', 'navigator.product');
  hookGetter(navigator, 'productSub', 'hardware', 'low', 'navigator.productSub');
  hookGetter(navigator, 'vendorSub', 'hardware', 'low', 'navigator.vendorSub');

  // ══════════════════════════════════════════════════════
  // CATEGORY 15: WEBRTC (webrtc)
  // ══════════════════════════════════════════════════════

  if (typeof RTCPeerConnection !== 'undefined') {
    var _origRTC = RTCPeerConnection;
    window.RTCPeerConnection = function(config) {
      record('RTCPeerConnection', 'webrtc', 'critical', 'config=' + JSON.stringify(config || {}).slice(0, 100));
      var pc = new _origRTC(config);

      // Hook createDataChannel
      var _origCreateDC = pc.createDataChannel;
      if (_origCreateDC) {
        pc.createDataChannel = function() {
          var args = [];
          for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
          record('RTCPeerConnection.createDataChannel', 'webrtc', 'high', 'label=' + args[0]);
          return _origCreateDC.apply(pc, args);
        };
      }

      // Hook createOffer
      var _origCreateOffer = pc.createOffer;
      if (_origCreateOffer) {
        pc.createOffer = function() {
          var args = [];
          for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
          record('RTCPeerConnection.createOffer', 'webrtc', 'high', '');
          return _origCreateOffer.apply(pc, args);
        };
      }

      // Monitor ICE candidates
      var _origOnIce = null;
      Object.defineProperty(pc, 'onicecandidate', {
        get: function() { return _origOnIce; },
        set: function(fn) {
          _origOnIce = function(event) {
            if (event && event.candidate) {
              record('RTCPeerConnection.onicecandidate', 'webrtc', 'critical',
                'candidate=' + String(event.candidate.candidate).slice(0, 100));
            }
            if (fn) fn(event);
          };
        },
        configurable: true
      });

      return pc;
    };
    window.RTCPeerConnection.prototype = _origRTC.prototype;
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 16: MATH FINGERPRINT (math-fingerprint)
  // ══════════════════════════════════════════════════════

  var mathMethods = ['acos', 'acosh', 'asin', 'asinh', 'atan', 'atanh', 'atan2',
    'cos', 'cosh', 'sin', 'sinh', 'tan', 'tanh', 'exp', 'expm1',
    'log', 'log1p', 'log2', 'log10', 'sqrt', 'cbrt', 'hypot',
    'fround', 'clz32', 'trunc', 'sign'];

  for (var mm = 0; mm < mathMethods.length; mm++) {
    (function(method) {
      if (typeof Math[method] === 'function') {
        hookMethod(Math, method, 'math-fingerprint', 'medium', function(args) {
          return method + '(' + args.slice(0, 2).join(',') + ')';
        });
      }
    })(mathMethods[mm]);
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 17: PERMISSIONS (permissions)
  // ══════════════════════════════════════════════════════

  if (navigator.permissions) {
    hookMethod(navigator.permissions, 'query', 'permissions', 'high', function(args) {
      return 'name=' + (args[0] && args[0].name ? args[0].name : 'unknown');
    });
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 18: SPEECH (speech)
  // ══════════════════════════════════════════════════════

  if (typeof speechSynthesis !== 'undefined') {
    hookMethod(speechSynthesis, 'getVoices', 'speech', 'high');
    hookMethod(speechSynthesis, 'speak', 'speech', 'medium');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 19: CLIENT HINTS (client-hints)
  // ══════════════════════════════════════════════════════

  if (navigator.userAgentData) {
    hookMethod(navigator.userAgentData, 'getHighEntropyValues', 'client-hints', 'critical', function(args) {
      return 'hints=' + (args[0] || []).join(',');
    });
    hookGetter(navigator.userAgentData, 'brands', 'client-hints', 'medium', 'navigator.userAgentData.brands');
    hookGetter(navigator.userAgentData, 'mobile', 'client-hints', 'medium', 'navigator.userAgentData.mobile');
    hookGetter(navigator.userAgentData, 'platform', 'client-hints', 'medium', 'navigator.userAgentData.platform');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 20: INTL FINGERPRINT (intl-fingerprint)
  // ══════════════════════════════════════════════════════

  if (typeof Intl !== 'undefined') {
    if (Intl.DateTimeFormat) {
      hookMethod(Intl.DateTimeFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium');
    }
    if (Intl.NumberFormat) {
      hookMethod(Intl.NumberFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium');
    }
    if (Intl.Collator) {
      hookMethod(Intl.Collator.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium');
    }
    if (Intl.ListFormat) {
      hookMethod(Intl.ListFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'high');
    }
    if (Intl.RelativeTimeFormat) {
      hookMethod(Intl.RelativeTimeFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'high');
    }
    if (Intl.PluralRules) {
      hookMethod(Intl.PluralRules.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium');
    }
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 21: CSS FINGERPRINT (css-fingerprint)
  // ══════════════════════════════════════════════════════

  if (typeof CSS !== 'undefined' && CSS.supports) {
    hookMethod(CSS, 'supports', 'css-fingerprint', 'medium', function(args) {
      return args.join(' ').slice(0, 80);
    });
  }

  if (typeof getComputedStyle !== 'undefined') {
    hookMethod(window, 'getComputedStyle', 'css-fingerprint', 'low');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 22: PROPERTY ENUMERATION (property-enum)
  // ══════════════════════════════════════════════════════

  var _origObjKeys = Object.keys;
  Object.keys = function(obj) {
    if (obj === navigator || obj === screen || obj === window ||
        (typeof Navigator !== 'undefined' && obj === Navigator.prototype) ||
        (typeof Screen !== 'undefined' && obj === Screen.prototype)) {
      record('Object.keys', 'property-enum', 'high', 'target=' + (obj === navigator ? 'navigator' : obj === screen ? 'screen' : 'window'));
    }
    return _origObjKeys.call(Object, obj);
  };

  var _origGetOwnPropNames = Object.getOwnPropertyNames;
  Object.getOwnPropertyNames = function(obj) {
    if (obj === navigator || obj === screen || obj === window ||
        (typeof Navigator !== 'undefined' && obj === Navigator.prototype) ||
        (typeof Screen !== 'undefined' && obj === Screen.prototype)) {
      record('Object.getOwnPropertyNames', 'property-enum', 'high', 'target=' + (obj === navigator ? 'navigator' : obj === screen ? 'screen' : 'window'));
    }
    return _origGetOwnPropNames.call(Object, obj);
  };

  // ══════════════════════════════════════════════════════
  // CATEGORY 23: OFFSCREEN CANVAS (offscreen-canvas)
  // ══════════════════════════════════════════════════════

  if (typeof OffscreenCanvas !== 'undefined') {
    var _origOC = OffscreenCanvas;
    window.OffscreenCanvas = function(w, h) {
      record('OffscreenCanvas', 'offscreen-canvas', 'high', 'size=' + w + 'x' + h);
      return new _origOC(w, h);
    };
    window.OffscreenCanvas.prototype = _origOC.prototype;
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 24: HONEYPOT (honeypot)
  // ══════════════════════════════════════════════════════

  var honeypotProps = [
    { obj: navigator, name: '__fingerprint', label: 'navigator.__fingerprint' },
    { obj: navigator, name: 'buildID', label: 'navigator.buildID' },
    { obj: window, name: '__nightmare', label: 'window.__nightmare' },
    { obj: window, name: '_phantom', label: 'window._phantom' },
    { obj: window, name: '__selenium_unwrapped', label: 'window.__selenium_unwrapped' },
    { obj: window, name: 'callPhantom', label: 'window.callPhantom' },
    { obj: window, name: '_Recaptcha', label: 'window._Recaptcha' },
    { obj: document, name: '__webdriver_evaluate', label: 'document.__webdriver_evaluate' },
    { obj: document, name: '__driver_evaluate', label: 'document.__driver_evaluate' }
  ];

  for (var hp = 0; hp < honeypotProps.length; hp++) {
    (function(trap) {
      try {
        Object.defineProperty(trap.obj, trap.name, {
          get: function() {
            record(trap.label, 'honeypot', 'critical', 'Honeypot property accessed!');
            return undefined;
          },
          set: function() {
            record(trap.label + '.set', 'honeypot', 'critical', 'Honeypot property written!');
          },
          configurable: true,
          enumerable: false
        });
      } catch(e) {}
    })(honeypotProps[hp]);
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 25: CREDENTIAL (credential)
  // ══════════════════════════════════════════════════════

  if (navigator.credentials) {
    hookMethod(navigator.credentials, 'get', 'credential', 'critical', function(args) {
      return JSON.stringify(args[0] || {}).slice(0, 100);
    });
    hookMethod(navigator.credentials, 'create', 'credential', 'critical', function(args) {
      return JSON.stringify(args[0] || {}).slice(0, 100);
    });
    hookMethod(navigator.credentials, 'store', 'credential', 'high');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 26: ENCODING (encoding)
  // ══════════════════════════════════════════════════════

  if (typeof TextEncoder !== 'undefined') {
    hookMethod(TextEncoder.prototype, 'encode', 'encoding', 'low');
    hookMethod(TextEncoder.prototype, 'encodeInto', 'encoding', 'low');
  }

  if (typeof TextDecoder !== 'undefined') {
    hookMethod(TextDecoder.prototype, 'decode', 'encoding', 'low');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 27: WEBASSEMBLY (webassembly)
  // ══════════════════════════════════════════════════════

  if (typeof WebAssembly !== 'undefined') {
    if (WebAssembly.compile) {
      hookMethod(WebAssembly, 'compile', 'webassembly', 'critical');
    }
    if (WebAssembly.instantiate) {
      hookMethod(WebAssembly, 'instantiate', 'webassembly', 'critical');
    }
    if (WebAssembly.validate) {
      hookMethod(WebAssembly, 'validate', 'webassembly', 'high');
    }
    if (WebAssembly.compileStreaming) {
      hookMethod(WebAssembly, 'compileStreaming', 'webassembly', 'critical');
    }
    if (WebAssembly.instantiateStreaming) {
      hookMethod(WebAssembly, 'instantiateStreaming', 'webassembly', 'critical');
    }
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 28: KEYBOARD LAYOUT (keyboard-layout)
  // ══════════════════════════════════════════════════════

  if (navigator.keyboard) {
    hookMethod(navigator.keyboard, 'getLayoutMap', 'keyboard-layout', 'high');
    hookMethod(navigator.keyboard, 'lock', 'keyboard-layout', 'high');
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 29: SENSOR APIS (sensor-apis)
  // ══════════════════════════════════════════════════════

  var sensorTypes = ['Accelerometer', 'Gyroscope', 'Magnetometer',
    'AbsoluteOrientationSensor', 'RelativeOrientationSensor',
    'AmbientLightSensor', 'LinearAccelerationSensor', 'GravitySensor'];

  for (var st = 0; st < sensorTypes.length; st++) {
    (function(sensorName) {
      if (typeof window[sensorName] !== 'undefined') {
        var _origSensor = window[sensorName];
        window[sensorName] = function(options) {
          record(sensorName, 'sensor-apis', 'high', 'frequency=' + (options && options.frequency ? options.frequency : 'default'));
          return new _origSensor(options);
        };
        window[sensorName].prototype = _origSensor.prototype;
      }
    })(sensorTypes[st]);
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 30: VISUALIZATION / GPU (visualization)
  // ══════════════════════════════════════════════════════

  hookMethod(window, 'requestAnimationFrame', 'visualization', 'low');

  // ══════════════════════════════════════════════════════
  // CATEGORY 31: DEVICE INFO (device-info)
  // ══════════════════════════════════════════════════════

  hookGetter(navigator, 'connection', 'device-info', 'medium', 'navigator.connection');

  if (navigator.getBattery) {
    hookMethod(navigator, 'getBattery', 'device-info', 'high');
  }

  hookGetter(navigator, 'doNotTrack', 'device-info', 'medium', 'navigator.doNotTrack');
  hookGetter(navigator, 'cookieEnabled', 'device-info', 'low', 'navigator.cookieEnabled');
  hookGetter(navigator, 'onLine', 'device-info', 'low', 'navigator.onLine');
  hookGetter(navigator, 'pdfViewerEnabled', 'device-info', 'low', 'navigator.pdfViewerEnabled');

  // ══════════════════════════════════════════════════════
  // CATEGORY 32: WORKER (worker)
  // ══════════════════════════════════════════════════════

  if (typeof Worker !== 'undefined') {
    var _origWorker = Worker;
    window.Worker = function(url, options) {
      record('Worker', 'worker', 'high', 'url=' + String(url).slice(0, 100));
      if (options) {
        return new _origWorker(url, options);
      }
      return new _origWorker(url);
    };
    window.Worker.prototype = _origWorker.prototype;
  }

  if (typeof SharedWorker !== 'undefined') {
    var _origSW = SharedWorker;
    window.SharedWorker = function(url, options) {
      record('SharedWorker', 'worker', 'high', 'url=' + String(url).slice(0, 100));
      if (options) {
        return new _origSW(url, options);
      }
      return new _origSW(url);
    };
    window.SharedWorker.prototype = _origSW.prototype;
  }

  // ══════════════════════════════════════════════════════
  // CATEGORY 33: FINGERPRINT (general fingerprint)
  // ══════════════════════════════════════════════════════

  hookGetter(navigator, 'languages', 'fingerprint', 'medium', 'navigator.languages');
  hookGetter(navigator, 'language', 'fingerprint', 'low', 'navigator.language');
  hookGetter(navigator, 'plugins', 'fingerprint', 'medium', 'navigator.plugins');
  hookGetter(navigator, 'mimeTypes', 'fingerprint', 'medium', 'navigator.mimeTypes');

  // Date/timezone fingerprinting
  var _origGetTZOffset = Date.prototype.getTimezoneOffset;
  Date.prototype.getTimezoneOffset = function() {
    record('Date.getTimezoneOffset', 'fingerprint', 'medium', '');
    return _origGetTZOffset.call(this);
  };

  // ══════════════════════════════════════════════════════
  // CATEGORY 34-37: BATTERY, BLUETOOTH, EventSource, Image tracking
  // ══════════════════════════════════════════════════════

  // Image-based tracking pixel detection
  if (typeof Image !== 'undefined') {
    var _origImage = Image;
    window.Image = function(w, h) {
      var img = new _origImage(w, h);
      var _origSrcDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
      if (_origSrcDesc && _origSrcDesc.set) {
        var _origSrcSet = _origSrcDesc.set;
        try {
          Object.defineProperty(img, 'src', {
            get: function() { return _origSrcDesc.get.call(img); },
            set: function(val) {
              var url = String(val).slice(0, 100);
              if (url.indexOf('?') !== -1 || url.indexOf('pixel') !== -1 || url.indexOf('track') !== -1 || url.indexOf('beacon') !== -1) {
                record('Image.src.tracking', 'exfiltration', 'high', 'url=' + url);
              }
              return _origSrcSet.call(img, val);
            },
            configurable: true
          });
        } catch(e) {}
      }
      return img;
    };
    window.Image.prototype = _origImage.prototype;
  }

  // EventSource
  if (typeof EventSource !== 'undefined') {
    var _origES = EventSource;
    window.EventSource = function(url, options) {
      record('EventSource', 'network', 'high', 'url=' + String(url).slice(0, 100));
      if (options) {
        return new _origES(url, options);
      }
      return new _origES(url);
    };
    window.EventSource.prototype = _origES.prototype;
  }

  // Bluetooth
  if (navigator.bluetooth) {
    hookMethod(navigator.bluetooth, 'requestDevice', 'device-info', 'critical');
    hookMethod(navigator.bluetooth, 'getAvailability', 'device-info', 'high');
  }

  // ══════════════════════════════════════════════════════
  // SYSTEM: Mark injection complete
  // ══════════════════════════════════════════════════════

  record('SENTINEL_INTERCEPTOR_READY', 'system', 'info', 'All hooks installed — 37 categories active');

})();
`;
}

module.exports = { getInterceptorScript };
