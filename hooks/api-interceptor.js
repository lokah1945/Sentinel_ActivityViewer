// Sentinel v4.4.2 — API Interceptor (Layer 3)
// 200+ hooks across 37 categories with smartHookGetter
// NO spoofing — pure monitoring/logging only

function getApiInterceptorScript() {
  return `
(function() {
  'use strict';
  if (window.__SENTINEL_ACTIVE) return;
  window.__SENTINEL_ACTIVE = true;

  // === DATA STORE ===
  var events = [];
  var seqCounter = 0;
  var startTime = performance.now();
  var DEDUP_WINDOW_MS = 100;
  var lastEventMap = {};
  var STACK_SAMPLE_INTERVAL = 10;
  var callCounters = {};

  // Original references (saved before any hooks)
  var realGetDesc = Object.getOwnPropertyDescriptor;
  var realDefProp = Object.defineProperty;
  var realToString = Function.prototype.toString;

  // Frame identification
  var frameId = 'f_' + Math.random().toString(36).substr(2, 8);
  var frameUrl = '';
  var frameOrigin = '';
  var isTop = false;
  try { frameUrl = window.location.href; } catch(e) {}
  try { frameOrigin = window.location.origin; } catch(e) {}
  try { isTop = (window === window.top); } catch(e) {}

  // === FNV-1a HASH (full-length, no truncation) ===
  function fnvHash(str) {
    var h = 0x811c9dc5;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h * 0x01000193) >>> 0;
    }
    return h.toString(16);
  }

  // === VALUE CAPTURE (tiered — no truncation for hash) ===
  function captureValue(val) {
    if (val === undefined || val === null) return { display: String(val), hash: '', size: 0 };
    var s = '';
    try { s = typeof val === 'object' ? JSON.stringify(val) : String(val); } catch(e) { s = String(val); }
    var size = s.length;
    if (size <= 200) return { display: s, hash: fnvHash(s), size: size };
    return { display: s.substring(0, 200) + '...', hash: fnvHash(s), size: size };
  }

  // === STACK TRACE CAPTURE ===
  function captureStack() {
    try {
      var stack = new Error().stack || '';
      var lines = stack.split('\\n').slice(2, 12); // top 10 frames, skip Error + captureStack
      var cleaned = [];
      for (var i = 0; i < lines.length; i++) {
        var ln = lines[i].trim();
        if (ln.toLowerCase().indexOf('sentinel') === -1 &&
            ln.toLowerCase().indexOf('puppeteer') === -1 &&
            ln.toLowerCase().indexOf('playwright') === -1) {
          cleaned.push(ln);
        }
      }
      return cleaned.join(' | ');
    } catch(e) { return ''; }
  }

  // === DEDUP ===
  function isDuplicate(cat, api) {
    var key = cat + ':' + api;
    var now = performance.now();
    if (lastEventMap[key] && (now - lastEventMap[key]) < DEDUP_WINDOW_MS) return true;
    lastEventMap[key] = now;
    return false;
  }

  // === CORE LOG FUNCTION with 1H5W ===
  function log(cat, api, detail, risk, opts) {
    risk = risk || 'low';
    opts = opts || {};
    if (isDuplicate(cat, api) && !opts.force) return;

    var callKey = cat + ':' + api;
    callCounters[callKey] = (callCounters[callKey] || 0) + 1;
    var shouldSampleStack = (callCounters[callKey] % STACK_SAMPLE_INTERVAL === 1);

    var evt = {
      seqId: seqCounter++,
      ts: Math.round(performance.now() - startTime),
      cat: cat,
      api: api,
      detail: detail || '',
      risk: risk,
      frame: isTop ? 'top' : 'iframe',
      frameId: frameId,
      frameUrl: frameUrl,
      origin: frameOrigin,
      who: opts.who || (shouldSampleStack ? captureStack() : ''),
      what: api + (opts.args ? '(' + opts.args + ')' : ''),
      why: opts.why || '',
      how: opts.how || 'direct-call'
    };

    if (opts.value !== undefined) {
      var captured = captureValue(opts.value);
      evt.value = captured.display;
      evt.valueHash = captured.hash;
      evt.valueSize = captured.size;
    }

    events.push(evt);

    // Push telemetry if available (real-time data to Node.js)
    if (typeof window.__SENTINEL_PUSH === 'function') {
      try { window.__SENTINEL_PUSH(JSON.stringify(evt)); } catch(e) {}
    }
  }

  // === SHIELD-AWARE HOOK HELPERS ===
  var shield = window.__SENTINEL_SHIELD || null;

  function hookFn(target, method, cat, risk, opts) {
    opts = opts || {};
    try {
      var orig = target[method];
      if (typeof orig !== 'function') return;
      if (shield && shield.hookFunction) {
        shield.hookFunction(target, method, function(original, args) {
          var val;
          try { val = original.apply(this, args); } catch(e) { throw e; }
          log(cat, method, opts.detail || '', risk, {
            value: opts.captureReturn ? val : undefined,
            args: opts.captureArgs ? Array.prototype.slice.call(args, 0, 3).join(',') : '',
            why: opts.why || 'API call monitoring',
            how: 'prototype-call'
          });
          return val;
        });
      } else {
        // Fallback: direct wrap
        target[method] = function() {
          var val;
          try { val = orig.apply(this, arguments); } catch(e) { throw e; }
          log(cat, method, opts.detail || '', risk, {
            value: opts.captureReturn ? val : undefined,
            why: opts.why || 'API call monitoring',
            how: 'direct-wrap'
          });
          return val;
        };
      }
    } catch(e) {}
  }

  function hookGetter(target, prop, cat, risk, opts) {
    opts = opts || {};
    try {
      if (shield && shield.hookGetter) {
        shield.hookGetter(target, prop, function(origGetter) {
          var val = origGetter.call(this);
          log(cat, prop, opts.detail || '', risk, {
            value: val,
            why: opts.why || 'Property read monitoring',
            how: 'getter-access'
          });
          return val;
        });
      } else {
        var desc = realGetDesc.call(Object, target, prop);
        if (!desc || !desc.get) return;
        var origGet = desc.get;
        realDefProp(target, prop, {
          get: function() {
            var val = origGet.call(this);
            log(cat, prop, opts.detail || '', risk, {
              value: val,
              why: opts.why || 'Property read monitoring',
              how: 'getter-access'
            });
            return val;
          },
          set: desc.set,
          configurable: true,
          enumerable: desc.enumerable
        });
      }
    } catch(e) {}
  }

  function hookGetterSetter(target, prop, cat, risk, opts) {
    opts = opts || {};
    try {
      var getHook = function(origGetter) {
        var val = origGetter.call(this);
        log(cat, prop + '.get', opts.detailGet || '', risk, {
          value: val,
          why: opts.whyGet || 'Read monitoring',
          how: 'getter-access'
        });
        return val;
      };
      var setHook = function(origSetter, v) {
        log(cat, prop + '.set', opts.detailSet || '', risk, {
          value: v,
          why: opts.whySet || 'Write monitoring',
          how: 'setter-access'
        });
        return origSetter.call(this, v);
      };
      if (shield && shield.hookGetterSetter) {
        shield.hookGetterSetter(target, prop, getHook, setHook);
      } else {
        var desc = realGetDesc.call(Object, target, prop);
        if (!desc) return;
        var origGet = desc.get;
        var origSet = desc.set;
        var newDesc = { configurable: true, enumerable: desc.enumerable };
        if (origGet) {
          newDesc.get = function() { return getHook.call(this, origGet); };
        }
        if (origSet) {
          newDesc.set = function(v) { return setHook.call(this, origSet, v); };
        } else if (origGet) {
          newDesc.set = desc.set;
        }
        realDefProp(target, prop, newDesc);
      }
    } catch(e) {}
  }

  // === smartHookGetter — auto-detect instance vs prototype ===
  function smartHookGetter(protoTarget, instanceTarget, prop, cat, risk, opts) {
    try {
      var instanceDesc = realGetDesc.call(Object, instanceTarget, prop);
      var protoDesc = realGetDesc.call(Object, protoTarget, prop);
      if (instanceDesc && instanceDesc.get) {
        hookGetter(instanceTarget, prop, cat, risk, opts);
      } else if (protoDesc && protoDesc.get) {
        hookGetter(protoTarget, prop, cat, risk, opts);
      }
    } catch(e) {}
  }

  // ================================================================
  // CATEGORY 29: SYSTEM — BOOT_OK (coverage proof)
  // ================================================================
  log('system', 'BOOT_OK', '', 'info', {
    force: true,
    value: JSON.stringify({ frameId: frameId, url: frameUrl, origin: frameOrigin, isTop: isTop }),
    why: 'Coverage proof: interceptor successfully loaded in this context',
    how: 'auto-emit'
  });

  // ================================================================
  // CATEGORY 1: CANVAS
  // ================================================================
  try {
    hookFn(HTMLCanvasElement.prototype, 'toDataURL', 'canvas', 'high', {
      captureReturn: true, why: 'Canvas fingerprint generation', detail: 'toDataURL'
    });
    hookFn(HTMLCanvasElement.prototype, 'getContext', 'canvas', 'medium', {
      captureArgs: true, why: 'Canvas context creation for fingerprinting'
    });
    hookFn(CanvasRenderingContext2D.prototype, 'fillText', 'canvas', 'medium', {
      captureArgs: true, why: 'Canvas text rendering for fingerprint'
    });
    hookFn(CanvasRenderingContext2D.prototype, 'strokeText', 'canvas', 'medium', {
      captureArgs: true, why: 'Canvas stroke text for fingerprint'
    });
    hookFn(CanvasRenderingContext2D.prototype, 'getImageData', 'canvas', 'high', {
      why: 'Canvas pixel data extraction'
    });
    hookFn(CanvasRenderingContext2D.prototype, 'measureText', 'canvas', 'medium', {
      captureArgs: true, why: 'Text measurement for font fingerprinting'
    });
    if (typeof CanvasRenderingContext2D.prototype.isPointInPath === 'function') {
      hookFn(CanvasRenderingContext2D.prototype, 'isPointInPath', 'canvas', 'high', {
        why: 'isPointInPath used by FingerprintJS'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 2: WEBGL
  // ================================================================
  try {
    var webglProtos = [];
    if (typeof WebGLRenderingContext !== 'undefined') webglProtos.push(WebGLRenderingContext.prototype);
    if (typeof WebGL2RenderingContext !== 'undefined') webglProtos.push(WebGL2RenderingContext.prototype);
    for (var wi = 0; wi < webglProtos.length; wi++) {
      hookFn(webglProtos[wi], 'getParameter', 'webgl', 'high', {
        captureReturn: true, captureArgs: true, why: 'WebGL parameter probing (VENDOR/RENDERER)'
      });
      hookFn(webglProtos[wi], 'getExtension', 'webgl', 'medium', {
        captureArgs: true, why: 'WebGL extension enumeration'
      });
      hookFn(webglProtos[wi], 'getSupportedExtensions', 'webgl', 'medium', {
        captureReturn: true, why: 'WebGL supported extensions list'
      });
      hookFn(webglProtos[wi], 'getShaderPrecisionFormat', 'webgl', 'high', {
        captureReturn: true, why: 'Shader precision format fingerprint'
      });
      hookFn(webglProtos[wi], 'readPixels', 'webgl', 'high', {
        why: 'WebGL pixel readback for fingerprint'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 3: AUDIO
  // ================================================================
  try {
    if (typeof OfflineAudioContext !== 'undefined') {
      var origOAC = OfflineAudioContext;
      OfflineAudioContext = function() {
        log('audio', 'OfflineAudioContext', '', 'high', {
          why: 'Audio fingerprint via OfflineAudioContext', how: 'constructor'
        });
        return new (Function.prototype.bind.apply(origOAC, [null].concat(Array.prototype.slice.call(arguments))))();
      };
      OfflineAudioContext.prototype = origOAC.prototype;
    }
    if (typeof AudioContext !== 'undefined') {
      hookFn(AudioContext.prototype, 'createOscillator', 'audio', 'high', {
        why: 'Oscillator creation for audio fingerprint'
      });
      hookFn(AudioContext.prototype, 'createDynamicsCompressor', 'audio', 'high', {
        why: 'Compressor for audio fingerprint'
      });
      hookFn(AudioContext.prototype, 'createAnalyser', 'audio', 'medium', {
        why: 'Analyser node for audio fingerprint'
      });
    }
    if (typeof BaseAudioContext !== 'undefined') {
      hookGetter(BaseAudioContext.prototype, 'sampleRate', 'audio', 'medium', {
        why: 'Audio sample rate fingerprint'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 4: FONT DETECTION
  // ================================================================
  try {
    hookFn(CanvasRenderingContext2D.prototype, 'measureText', 'font-detection', 'high', {
      captureArgs: true, captureReturn: true, why: 'Font width measurement for font enumeration'
    });
    hookFn(Element.prototype, 'getBoundingClientRect', 'font-detection', 'medium', {
      captureReturn: true, why: 'Element bounding rect for font detection'
    });
    hookGetter(HTMLElement.prototype, 'offsetWidth', 'font-detection', 'medium', {
      why: 'Element offset width for font detection'
    });
    hookGetter(HTMLElement.prototype, 'offsetHeight', 'font-detection', 'medium', {
      why: 'Element offset height for font detection'
    });
    if (typeof FontFace !== 'undefined') {
      var origFontFace = FontFace;
      window.FontFace = function(family, source, descriptors) {
        log('font-detection', 'FontFace', family, 'medium', {
          value: family, why: 'FontFace construction for font enumeration', how: 'constructor'
        });
        return new origFontFace(family, source, descriptors);
      };
      window.FontFace.prototype = origFontFace.prototype;
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 5: FINGERPRINT (navigator props)
  // ================================================================
  try {
    var navProps = [
      'userAgent', 'vendor', 'platform', 'language', 'languages',
      'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints',
      'cookieEnabled', 'doNotTrack', 'appVersion', 'product',
      'productSub', 'vendorSub', 'oscpu', 'pdfViewerEnabled'
    ];
    for (var ni = 0; ni < navProps.length; ni++) {
      smartHookGetter(Navigator.prototype, navigator, navProps[ni], 'fingerprint', 'medium', {
        why: 'Navigator property probing for fingerprint'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 6: SCREEN
  // ================================================================
  try {
    var screenProps = [
      'width', 'height', 'availWidth', 'availHeight', 'colorDepth',
      'pixelDepth'
    ];
    for (var si = 0; si < screenProps.length; si++) {
      smartHookGetter(Screen.prototype, screen, screenProps[si], 'screen', 'medium', {
        why: 'Screen property probing for fingerprint'
      });
    }
    hookGetter(window, 'devicePixelRatio', 'screen', 'medium', {
      why: 'Device pixel ratio fingerprint'
    });
    hookGetter(window, 'innerWidth', 'screen', 'low', { why: 'Window inner width' });
    hookGetter(window, 'innerHeight', 'screen', 'low', { why: 'Window inner height' });
    hookGetter(window, 'outerWidth', 'screen', 'low', { why: 'Window outer width' });
    hookGetter(window, 'outerHeight', 'screen', 'low', { why: 'Window outer height' });
  } catch(e) {}

  // ================================================================
  // CATEGORY 7: STORAGE
  // ================================================================
  try {
    hookFn(Storage.prototype, 'getItem', 'storage', 'medium', {
      captureArgs: true, why: 'Storage read (tracking data access)'
    });
    hookFn(Storage.prototype, 'setItem', 'storage', 'medium', {
      captureArgs: true, why: 'Storage write (tracking data creation)'
    });
    hookFn(Storage.prototype, 'removeItem', 'storage', 'low', {
      captureArgs: true, why: 'Storage remove'
    });
    // Cookie getter+setter
    hookGetterSetter(Document.prototype, 'cookie', 'storage', 'high', {
      detailGet: 'cookie.get',
      detailSet: 'cookie.set',
      whyGet: 'document.cookie read — tracking data access',
      whySet: 'document.cookie write — tracking cookie creation'
    });
    // IndexedDB
    if (typeof indexedDB !== 'undefined') {
      hookFn(IDBFactory.prototype, 'open', 'storage', 'medium', {
        captureArgs: true, why: 'IndexedDB open — persistent storage access'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 8: NETWORK
  // ================================================================
  try {
    hookFn(XMLHttpRequest.prototype, 'open', 'network', 'medium', {
      captureArgs: true, why: 'XHR open — network request monitoring'
    });
    hookFn(XMLHttpRequest.prototype, 'send', 'network', 'medium', {
      why: 'XHR send — outbound data monitoring'
    });
    var origFetch = window.fetch;
    window.fetch = function() {
      var url = '';
      try {
        var arg0 = arguments[0];
        url = typeof arg0 === 'string' ? arg0 : (arg0 && arg0.url ? arg0.url : String(arg0));
      } catch(e) {}
      var method = 'GET';
      var hasBody = false;
      try {
        if (arguments[1]) {
          method = arguments[1].method || 'GET';
          hasBody = !!arguments[1].body;
        }
      } catch(e) {}
      log('exfiltration', 'fetch', '', 'high', {
        value: 'url:' + url + ',method:' + method + ',hasBody:' + hasBody,
        why: 'Fetch request — potential data exfiltration',
        how: 'fetch-call'
      });
      return origFetch.apply(this, arguments);
    };
  } catch(e) {}

  // ================================================================
  // CATEGORY 9: PERFORMANCE TIMING
  // ================================================================
  try {
    hookFn(Performance.prototype, 'now', 'perf-timing', 'low', {
      captureReturn: true, why: 'High-resolution timing (timing fingerprint)'
    });
    hookFn(Performance.prototype, 'getEntriesByType', 'perf-timing', 'medium', {
      captureArgs: true, why: 'Performance entries probing'
    });
    hookFn(Performance.prototype, 'mark', 'perf-timing', 'low', {
      captureArgs: true, why: 'Performance mark'
    });
    hookFn(Performance.prototype, 'measure', 'perf-timing', 'low', {
      captureArgs: true, why: 'Performance measure'
    });
  } catch(e) {}

  // ================================================================
  // CATEGORY 10: MEDIA DEVICES
  // ================================================================
  try {
    if (typeof MediaDevices !== 'undefined' && MediaDevices.prototype.enumerateDevices) {
      hookFn(MediaDevices.prototype, 'enumerateDevices', 'media-devices', 'critical', {
        captureReturn: true, why: 'Media device enumeration — hardware fingerprint'
      });
    }
    if (typeof MediaDevices !== 'undefined' && MediaDevices.prototype.getUserMedia) {
      hookFn(MediaDevices.prototype, 'getUserMedia', 'media-devices', 'critical', {
        why: 'getUserMedia — camera/mic access attempt'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 11: DOM PROBE (filtered — only fingerprint-relevant tags)
  // ================================================================
  try {
    var origCreateElement = document.createElement;
    var fpTags = ['canvas','iframe','audio','video','object','embed','script','link','img'];
    document.createElement = function(tag) {
      var el = origCreateElement.apply(this, arguments);
      var lTag = (tag || '').toLowerCase();
      if (fpTags.indexOf(lTag) >= 0) {
        log('dom-probe', 'createElement', 'tag:' + lTag, 'low', {
          value: lTag, why: 'Fingerprint-relevant DOM element creation'
        });
      }
      return el;
    };
    // MutationObserver
    var origMO = MutationObserver;
    window.MutationObserver = function(cb) {
      log('dom-probe', 'MutationObserver', '', 'medium', {
        why: 'DOM mutation monitoring (fingerprint detection vector)'
      });
      return new origMO(cb);
    };
    window.MutationObserver.prototype = origMO.prototype;
    // IntersectionObserver
    if (typeof IntersectionObserver !== 'undefined') {
      var origIO = IntersectionObserver;
      window.IntersectionObserver = function(cb, opts) {
        log('dom-probe', 'IntersectionObserver', '', 'medium', {
          why: 'Intersection observer (visibility-based fingerprint detection)'
        });
        return new origIO(cb, opts);
      };
      window.IntersectionObserver.prototype = origIO.prototype;
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 12: CLIPBOARD
  // ================================================================
  try {
    if (navigator.clipboard) {
      ['readText','read','writeText','write'].forEach(function(m) {
        if (typeof navigator.clipboard[m] === 'function') {
          hookFn(navigator.clipboard, m, 'clipboard', 'critical', {
            why: 'Clipboard ' + m + ' — data exfiltration/injection vector'
          });
        }
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 13: GEOLOCATION
  // ================================================================
  try {
    if (navigator.geolocation) {
      hookFn(Geolocation.prototype, 'getCurrentPosition', 'geolocation', 'critical', {
        why: 'Geolocation request — precise location fingerprint'
      });
      hookFn(Geolocation.prototype, 'watchPosition', 'geolocation', 'critical', {
        why: 'Geolocation watch — continuous location tracking'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 14: SERVICE WORKER
  // ================================================================
  try {
    if (navigator.serviceWorker) {
      hookFn(navigator.serviceWorker, 'register', 'service-worker', 'high', {
        captureArgs: true, why: 'Service worker registration — persistent script install'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 15: HARDWARE
  // ================================================================
  try {
    smartHookGetter(Navigator.prototype, navigator, 'hardwareConcurrency', 'hardware', 'high', {
      why: 'CPU core count fingerprint'
    });
    smartHookGetter(Navigator.prototype, navigator, 'deviceMemory', 'hardware', 'high', {
      why: 'Device RAM estimate fingerprint'
    });
    smartHookGetter(Navigator.prototype, navigator, 'platform', 'hardware', 'medium', {
      why: 'Platform string fingerprint'
    });
  } catch(e) {}

  // ================================================================
  // CATEGORY 16: EXFILTRATION (sendBeacon, WebSocket, tracking pixels)
  // ================================================================
  try {
    hookFn(Navigator.prototype, 'sendBeacon', 'exfiltration', 'critical', {
      captureArgs: true, why: 'sendBeacon — fire-and-forget data exfiltration'
    });
    var origWS = window.WebSocket;
    window.WebSocket = function(url, protocols) {
      log('exfiltration', 'WebSocket', '', 'high', {
        value: 'url:' + url, why: 'WebSocket connection — potential covert channel'
      });
      if (protocols) return new origWS(url, protocols);
      return new origWS(url);
    };
    window.WebSocket.prototype = origWS.prototype;
    window.WebSocket.CONNECTING = origWS.CONNECTING;
    window.WebSocket.OPEN = origWS.OPEN;
    window.WebSocket.CLOSING = origWS.CLOSING;
    window.WebSocket.CLOSED = origWS.CLOSED;
  } catch(e) {}

  // ================================================================
  // CATEGORY 17: WEBRTC
  // ================================================================
  try {
    if (typeof RTCPeerConnection !== 'undefined') {
      var origRTC = RTCPeerConnection;
      window.RTCPeerConnection = function(config) {
        log('webrtc', 'RTCPeerConnection', '', 'critical', {
          value: JSON.stringify(config || {}),
          why: 'RTCPeerConnection — IP leak via ICE candidates'
        });
        var pc = new origRTC(config);
        var origAddEvent = pc.addEventListener;
        if (origAddEvent) {
          pc.addEventListener = function(type, cb) {
            if (type === 'icecandidate') {
              log('webrtc', 'onicecandidate', '', 'critical', {
                why: 'ICE candidate listener — IP harvesting'
              });
            }
            return origAddEvent.apply(this, arguments);
          };
        }
        return pc;
      };
      window.RTCPeerConnection.prototype = origRTC.prototype;
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 18: MATH FINGERPRINT
  // ================================================================
  try {
    var mathFns = ['acos','acosh','asin','asinh','atan','atanh','atan2',
      'cos','cosh','exp','expm1','log','log1p','log2','log10',
      'sin','sinh','sqrt','tan','tanh','cbrt','sign','trunc'];
    for (var mi = 0; mi < mathFns.length; mi++) {
      (function(fn) {
        if (typeof Math[fn] === 'function') {
          hookFn(Math, fn, 'math-fingerprint', 'low', {
            captureReturn: true, why: 'Math.' + fn + ' — precision difference fingerprint'
          });
        }
      })(mathFns[mi]);
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 19: PERMISSIONS
  // ================================================================
  try {
    if (navigator.permissions && typeof navigator.permissions.query === 'function') {
      hookFn(navigator.permissions, 'query', 'permissions', 'high', {
        captureArgs: true, why: 'Permissions query — browser capability probing'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 20: SPEECH
  // ================================================================
  try {
    if (typeof speechSynthesis !== 'undefined') {
      hookFn(speechSynthesis, 'getVoices', 'speech', 'high', {
        captureReturn: true, why: 'Speech voices — OS/language fingerprint via TTS'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 21: CLIENT HINTS
  // ================================================================
  try {
    if (navigator.userAgentData) {
      if (typeof navigator.userAgentData.getHighEntropyValues === 'function') {
        hookFn(navigator.userAgentData, 'getHighEntropyValues', 'client-hints', 'critical', {
          captureArgs: true, captureReturn: true, why: 'High-entropy Client Hints — full OS/CPU/model'
        });
      }
      hookGetter(navigator.userAgentData, 'brands', 'client-hints', 'medium', {
        why: 'Client Hints brands'
      });
      hookGetter(navigator.userAgentData, 'platform', 'client-hints', 'medium', {
        why: 'Client Hints platform'
      });
      hookGetter(navigator.userAgentData, 'mobile', 'client-hints', 'low', {
        why: 'Client Hints mobile flag'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 22: INTL FINGERPRINT
  // ================================================================
  try {
    var intlTypes = ['DateTimeFormat','NumberFormat','ListFormat','PluralRules',
      'RelativeTimeFormat','Collator'];
    for (var ii = 0; ii < intlTypes.length; ii++) {
      (function(typeName) {
        if (Intl[typeName] && Intl[typeName].prototype.resolvedOptions) {
          hookFn(Intl[typeName].prototype, 'resolvedOptions', 'intl-fingerprint', 'medium', {
            captureReturn: true, why: 'Intl.' + typeName + '.resolvedOptions — locale fingerprint'
          });
        }
      })(intlTypes[ii]);
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 23: CSS FINGERPRINT (matchMedia + CSS.supports)
  // ================================================================
  try {
    var origMatchMedia = window.matchMedia;
    window.matchMedia = function(query) {
      log('css-fingerprint', 'matchMedia', query, 'medium', {
        value: query, why: 'matchMedia query — CSS feature fingerprint'
      });
      return origMatchMedia.call(this, query);
    };
    if (typeof CSS !== 'undefined' && CSS.supports) {
      hookFn(CSS, 'supports', 'css-fingerprint', 'medium', {
        captureArgs: true, captureReturn: true, why: 'CSS.supports — browser capability fingerprint'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 24: PROPERTY ENUM (filtered — nav/screen only)
  // ================================================================
  try {
    var origObjKeys = Object.keys;
    Object.keys = function(obj) {
      var result = origObjKeys.call(Object, obj);
      if (obj === navigator || obj === screen ||
          obj === Navigator.prototype || obj === Screen.prototype) {
        log('property-enum', 'Object.keys', '', 'high', {
          value: result.join(','), why: 'Property enumeration on nav/screen — lie detection'
        });
      }
      return result;
    };
    var origObjNames = Object.getOwnPropertyNames;
    Object.getOwnPropertyNames = function(obj) {
      var result = origObjNames.call(Object, obj);
      if (obj === navigator || obj === screen ||
          obj === Navigator.prototype || obj === Screen.prototype) {
        log('property-enum', 'Object.getOwnPropertyNames', '', 'high', {
          value: result.length + ' props', why: 'Property name enumeration — prototype lie detection'
        });
      }
      return result;
    };
  } catch(e) {}

  // ================================================================
  // CATEGORY 25: OFFSCREEN CANVAS
  // ================================================================
  try {
    if (typeof OffscreenCanvas !== 'undefined') {
      var origOSC = OffscreenCanvas;
      window.OffscreenCanvas = function(w, h) {
        log('offscreen-canvas', 'OffscreenCanvas', w + 'x' + h, 'high', {
          why: 'OffscreenCanvas — worker-based canvas fingerprinting'
        });
        return new origOSC(w, h);
      };
      window.OffscreenCanvas.prototype = origOSC.prototype;
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 26: HONEYPOT (trap properties)
  // ================================================================
  try {
    var traps = ['__fpjs_d_m', 'selenium', 'callSelenium', '__fxdriver_evaluate',
      '__selenium_unwrapped', '_Selenium_IDE_Recorder', 'callPhantom',
      '__phantomas', '_phantom', 'phantom', '__nightmare', '__webdriver_evaluate'];
    for (var ti = 0; ti < traps.length; ti++) {
      (function(trapName) {
        try {
          realDefProp(window, trapName, {
            get: function() {
              log('honeypot', trapName, '', 'critical', {
                force: true, why: 'Honeypot access — confirms active bot/fingerprint probing'
              });
              return undefined;
            },
            set: function() {},
            configurable: true,
            enumerable: false
          });
        } catch(e) {}
      })(traps[ti]);
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 27: CREDENTIAL
  // ================================================================
  try {
    if (navigator.credentials) {
      if (typeof navigator.credentials.get === 'function') {
        hookFn(navigator.credentials, 'get', 'credential', 'critical', {
          captureArgs: true, why: 'Credential API get — WebAuthn/passkey fingerprint'
        });
      }
      if (typeof navigator.credentials.create === 'function') {
        hookFn(navigator.credentials, 'create', 'credential', 'critical', {
          captureArgs: true, why: 'Credential API create — WebAuthn fingerprint'
        });
      }
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 28: ENCODING
  // ================================================================
  try {
    hookFn(TextEncoder.prototype, 'encode', 'encoding', 'low', {
      why: 'TextEncoder — encoding probing'
    });
    if (typeof TextDecoder !== 'undefined') {
      hookFn(TextDecoder.prototype, 'decode', 'encoding', 'low', {
        why: 'TextDecoder — encoding probing'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 30: WORKER
  // ================================================================
  try {
    if (typeof Worker !== 'undefined') {
      var origWorker = Worker;
      window.Worker = function(url, opts) {
        log('worker', 'Worker', '', 'high', {
          value: String(url), why: 'Web Worker creation — off-thread processing detection'
        });
        return new origWorker(url, opts);
      };
      window.Worker.prototype = origWorker.prototype;
    }
    if (typeof SharedWorker !== 'undefined') {
      var origSW = SharedWorker;
      window.SharedWorker = function(url, opts) {
        log('worker', 'SharedWorker', '', 'high', {
          value: String(url), why: 'Shared Worker creation'
        });
        return new origSW(url, opts);
      };
      window.SharedWorker.prototype = origSW.prototype;
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 31: WEBASSEMBLY
  // ================================================================
  try {
    if (typeof WebAssembly !== 'undefined') {
      var wasmMethods = ['compile','compileStreaming','instantiate','instantiateStreaming','validate'];
      for (var wmi = 0; wmi < wasmMethods.length; wmi++) {
        (function(m) {
          if (typeof WebAssembly[m] === 'function') {
            hookFn(WebAssembly, m, 'webassembly', 'critical', {
              why: 'WebAssembly.' + m + ' — WASM fingerprinting'
            });
          }
        })(wasmMethods[wmi]);
      }
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 32: KEYBOARD LAYOUT
  // ================================================================
  try {
    if (navigator.keyboard && typeof navigator.keyboard.getLayoutMap === 'function') {
      hookFn(navigator.keyboard, 'getLayoutMap', 'keyboard-layout', 'high', {
        captureReturn: true, why: 'Keyboard layout map — locale/hardware fingerprint'
      });
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 33: SENSOR APIs
  // ================================================================
  try {
    var sensorCtors = ['Accelerometer','Gyroscope','Magnetometer',
      'AmbientLightSensor','GravitySensor','LinearAccelerationSensor',
      'AbsoluteOrientationSensor','RelativeOrientationSensor'];
    for (var sci = 0; sci < sensorCtors.length; sci++) {
      (function(name) {
        if (typeof window[name] !== 'undefined') {
          var origCtor = window[name];
          window[name] = function(opts) {
            log('sensor-apis', name, '', 'high', {
              why: name + ' sensor — hardware fingerprint'
            });
            return new origCtor(opts);
          };
          window[name].prototype = origCtor.prototype;
        }
      })(sensorCtors[sci]);
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 34: VISUALIZATION (rAF timing)
  // ================================================================
  try {
    var origRAF = window.requestAnimationFrame;
    window.requestAnimationFrame = function(cb) {
      log('visualization', 'requestAnimationFrame', '', 'low', {
        why: 'rAF — GPU/frame timing fingerprint'
      });
      return origRAF.call(window, cb);
    };
  } catch(e) {}

  // ================================================================
  // CATEGORY 35: DEVICE INFO (connection, battery)
  // ================================================================
  try {
    if (navigator.getBattery) {
      hookFn(navigator, 'getBattery', 'device-info', 'high', {
        captureReturn: true, why: 'Battery API — device fingerprint'
      });
    }
    if (navigator.connection) {
      var connProps = ['effectiveType','rtt','downlink','saveData','type'];
      for (var ci = 0; ci < connProps.length; ci++) {
        try {
          hookGetter(navigator.connection, connProps[ci], 'device-info', 'medium', {
            why: 'Network connection property — network fingerprint'
          });
        } catch(e) {}
      }
    }
  } catch(e) {}

  // ================================================================
  // CATEGORY 36: BATTERY (dedicated)
  // ================================================================
  // Covered by device-info above

  // ================================================================
  // CATEGORY 37: BLUETOOTH
  // ================================================================
  try {
    if (navigator.bluetooth) {
      if (typeof navigator.bluetooth.requestDevice === 'function') {
        hookFn(navigator.bluetooth, 'requestDevice', 'bluetooth', 'critical', {
          why: 'Bluetooth device request — hardware fingerprint'
        });
      }
      if (typeof navigator.bluetooth.getAvailability === 'function') {
        hookFn(navigator.bluetooth, 'getAvailability', 'bluetooth', 'medium', {
          why: 'Bluetooth availability check'
        });
      }
    }
  } catch(e) {}

  // ================================================================
  // GETIMEZONEOFFSET (fingerprint category)
  // ================================================================
  try {
    hookFn(Date.prototype, 'getTimezoneOffset', 'fingerprint', 'medium', {
      captureReturn: true, why: 'Timezone offset — locale fingerprint'
    });
  } catch(e) {}

  // === DATA EXPORT ===
  window.__SENTINEL_DATA = { events: events, frameId: frameId, startTime: startTime };
  window.__SENTINEL_FLUSH = function() {
    return JSON.stringify({ events: events, frameId: frameId });
  };

})();
`;
}

module.exports = { getApiInterceptorScript };
