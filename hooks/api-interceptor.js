/**
 * Sentinel v4.1 — Forensic API Interceptor (Layer 3 + Layer 4)
 * 
 * CRITICAL FIXES from v4.0:
 * - Each hook is wrapped in try/catch so one failure doesn't kill the whole script
 * - No events.splice() — events stay in __SENTINEL_DATA__ for collection
 * - Push telemetry sends COPIES, not spliced originals
 * - Shield dependency is optional (graceful fallback to direct hooking)
 * - Getter hooks use stored reference to real Object.getOwnPropertyDescriptor
 * 
 * Architecture:
 * - Layer 3: Enhanced 19 original categories with value capture + 1H5W
 * - Layer 4: 12 new vectors (speech, client-hints, intl, css, etc.)
 * - Layer 5: Exfiltration monitoring (fetch/xhr/beacon/ws/img)
 */

function getInterceptorScript(config = {}) {
  const timeout = config.timeout || 30000;
  const stackSampleRate = config.stackSampleRate || 10;

  return `
  (function() {
    'use strict';

    // ═══════════════════════════════════════════
    //  SENTINEL v4.1 — FORENSIC MALING CATCHER
    // ═══════════════════════════════════════════

    // Prevent double-injection
    if (window.__SENTINEL_ACTIVE__) return;
    window.__SENTINEL_ACTIVE__ = true;

    // Store real natives before anything else runs
    const _realGetDesc = Object.getOwnPropertyDescriptor;
    const _realDefProp = Object.defineProperty;

    const _sentinel = {
      events: [],
      startTime: Date.now(),
      bootOk: false,
      frameId: Math.random().toString(36).substr(2, 8),
      config: {
        timeout: ${timeout},
        maxEvents: 100000,
        stackSampleRate: ${stackSampleRate}
      },
      counters: {}
    };

    // Shield is optional — set by anti-detection-shield.js if it ran first
    const _shield = window.__SENTINEL_SHIELD__ || null;

    // ═══ FORENSIC LOGGER (1H5W) ═══
    function log(category, api, detail, risk, options) {
      if (_sentinel.events.length >= _sentinel.config.maxEvents) return;

      const opts = options || {};
      const counter = _sentinel.counters[api] = (_sentinel.counters[api] || 0) + 1;

      // Stack sampling: capture WHO is calling
      var stack = null;
      if (counter % _sentinel.config.stackSampleRate === 1) {
        try {
          var err = new Error();
          stack = (err.stack || '').split('\\n').slice(2, 6).map(function(s){return s.trim();}).join(' | ');
        } catch(e) {}
      }

      var origin = 'unknown';
      try { origin = location.origin; } catch(e) {}

      var frameType = 'top';
      try { if (window !== window.top) frameType = 'iframe'; } catch(e) { frameType = 'cross-origin-iframe'; }

      var currentUrl = 'unknown';
      try { currentUrl = location.href; } catch(e) {}

      var event = {
        ts: Date.now() - _sentinel.startTime,
        cat: category,
        api: api,
        detail: null,
        value: null,
        risk: risk || 'low',
        origin: origin,
        frame: frameType,
        frameId: _sentinel.frameId,
        url: currentUrl,
        callCount: counter
      };

      // Safely serialize detail
      if (detail !== undefined && detail !== null) {
        try {
          if (typeof detail === 'object') {
            event.detail = JSON.stringify(detail).slice(0, 500);
          } else {
            event.detail = String(detail).slice(0, 500);
          }
        } catch(e) {
          event.detail = '[unserializable]';
        }
      }

      // Capture return value (WHAT)
      if (opts.returnValue !== undefined) {
        try {
          var rv = opts.returnValue;
          if (rv === null || rv === undefined) {
            event.value = String(rv);
          } else if (typeof rv === 'string') {
            event.value = rv.slice(0, 300);
          } else if (typeof rv === 'number' || typeof rv === 'boolean') {
            event.value = String(rv);
          } else if (Array.isArray(rv)) {
            event.value = JSON.stringify(rv.slice(0, 10)).slice(0, 300);
          } else if (typeof rv === 'object') {
            event.value = JSON.stringify(rv).slice(0, 300);
          } else {
            event.value = String(rv).slice(0, 200);
          }
        } catch(e) {
          event.value = '[capture-error]';
        }
      }

      if (stack) event.stack = stack;
      if (opts.why) event.why = opts.why;
      if (opts.how) event.how = opts.how;

      _sentinel.events.push(event);
    }

    // ═══ SAFE HOOK HELPERS ═══
    // Each hook is independently guarded — one crash doesn't kill the rest

    function hookFn(target, prop, category, risk, options) {
      try {
        var opts = options || {};
        var original = target[prop];
        if (!original || typeof original !== 'function') return;

        if (_shield && _shield.hookFunction) {
          _shield.hookFunction(target, prop, function(orig) {
            var args = Array.prototype.slice.call(arguments, 1);
            var detail = opts.detailFn ? opts.detailFn(args) : { args: args.length };
            var result = orig.apply(this, args);

            if (result && typeof result === 'object' && typeof result.then === 'function') {
              result.then(function(val) {
                log(category, prop, detail, risk, {
                  returnValue: opts.valueFn ? opts.valueFn(val) : val,
                  why: opts.why || '',
                  how: 'async-call'
                });
              }).catch(function(){});
              log(category, prop, detail, risk, { why: opts.why || '', how: 'async-initiated' });
              return result;
            }

            log(category, prop, detail, risk, {
              returnValue: opts.valueFn ? opts.valueFn(result) : result,
              why: opts.why || '',
              how: opts.how || 'direct-call'
            });
            return result;
          });
        } else {
          // Direct hook (no shield)
          target[prop] = function() {
            var args = Array.prototype.slice.call(arguments);
            var detail = opts.detailFn ? opts.detailFn(args) : { args: args.length };
            var result = original.apply(this, args);

            if (result && typeof result === 'object' && typeof result.then === 'function') {
              result.then(function(val) {
                log(category, prop, detail, risk, {
                  returnValue: opts.valueFn ? opts.valueFn(val) : val,
                  why: opts.why || '',
                  how: 'async-call'
                });
              }).catch(function(){});
              return result;
            }

            log(category, prop, detail, risk, {
              returnValue: opts.valueFn ? opts.valueFn(result) : result,
              why: opts.why || '',
              how: opts.how || 'direct-call'
            });
            return result;
          };
          // Basic toString protection even without shield
          try { target[prop].toString = function() { return original.toString(); }; } catch(e) {}
        }
      } catch(e) {
        // Silent failure for individual hook — don't crash pipeline
      }
    }

    function hookGetter(target, prop, category, risk, options) {
      try {
        var opts = options || {};

        if (_shield && _shield.hookGetter) {
          _shield.hookGetter(target, prop, function(originalGetter) {
            var value = originalGetter.call(this);
            log(category, prop, {}, risk, {
              returnValue: opts.valueFn ? opts.valueFn(value) : value,
              why: opts.why || '',
              how: 'getter-access'
            });
            return value;
          });
        } else {
          // Direct getter hook using stored real getOwnPropertyDescriptor
          var desc = _realGetDesc.call(Object, target, prop);
          if (!desc || !desc.get) return;
          var origGetter = desc.get;
          _realDefProp.call(Object, target, prop, {
            get: function() {
              var value = origGetter.call(this);
              log(category, prop, {}, risk, {
                returnValue: opts.valueFn ? opts.valueFn(value) : value,
                why: opts.why || ''
              });
              return value;
            },
            set: desc.set,
            enumerable: desc.enumerable,
            configurable: true
          });
        }
      } catch(e) {
        // Silent failure for individual hook
      }
    }

    // ═══ Hash helper ═══
    function hashStr(str) {
      var hash = 0;
      if (!str) return '0';
      str = String(str);
      for (var i = 0; i < Math.min(str.length, 1000); i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0;
      }
      return Math.abs(hash).toString(36);
    }

    // ═══════════════════════════════════════════
    //  LAYER 3: CORE HOOKS (19 categories)
    //  Each hook in its own try/catch
    // ═══════════════════════════════════════════

    // ═══ 1. CANVAS FINGERPRINTING ═══
    try {
      hookFn(HTMLCanvasElement.prototype, 'toDataURL', 'canvas', 'high', {
        detailFn: function(a) { return { type: a[0] || 'image/png', quality: a[1] }; },
        valueFn: function(v) { return v ? v.slice(0, 80) + '...[hash:' + hashStr(v) + ']' : null; },
        why: 'Canvas toDataURL generates unique pixel hash per GPU/driver'
      });
    } catch(e) {}

    try {
      hookFn(HTMLCanvasElement.prototype, 'toBlob', 'canvas', 'high', {
        detailFn: function(a) { return { type: a[1] || 'image/png' }; },
        why: 'Canvas toBlob exports pixel data for fingerprint hashing'
      });
    } catch(e) {}

    try {
      hookFn(CanvasRenderingContext2D.prototype, 'getImageData', 'canvas', 'high', {
        detailFn: function(a) { return { x: a[0], y: a[1], w: a[2], h: a[3] }; },
        valueFn: function(v) { return v ? { width: v.width, height: v.height, dataLen: v.data ? v.data.length : 0 } : null; },
        why: 'Raw pixel data extraction for canvas fingerprint'
      });
    } catch(e) {}

    try {
      hookFn(CanvasRenderingContext2D.prototype, 'fillText', 'canvas', 'medium', {
        detailFn: function(a) { return { text: String(a[0]).slice(0, 50), x: a[1], y: a[2] }; },
        why: 'Text rendering varies by font engine — canvas fingerprint component'
      });
    } catch(e) {}

    try {
      hookFn(CanvasRenderingContext2D.prototype, 'measureText', 'font-detection', 'high', {
        detailFn: function(a) { return { text: String(a[0]).slice(0, 30) }; },
        valueFn: function(v) { return v ? { width: v.width } : null; },
        why: 'Font metric measurement for installed font detection'
      });
    } catch(e) {}

    try {
      hookFn(CanvasRenderingContext2D.prototype, 'isPointInPath', 'canvas', 'medium', {
        detailFn: function(a) { return { x: a[0], y: a[1] }; },
        valueFn: function(v) { return v; },
        why: 'Path rendering test — FingerprintJS v5 signature'
      });
    } catch(e) {}

    try {
      hookFn(CanvasRenderingContext2D.prototype, 'isPointInStroke', 'canvas', 'medium', {
        detailFn: function(a) { return { x: a[0], y: a[1] }; },
        valueFn: function(v) { return v; },
        why: 'Stroke rendering test for GPU fingerprinting'
      });
    } catch(e) {}

    try {
      hookFn(HTMLCanvasElement.prototype, 'getContext', 'canvas', 'medium', {
        detailFn: function(a) { return { contextType: a[0], attrs: a[1] }; },
        valueFn: function(v) { return v ? (v.constructor ? v.constructor.name : 'context') : null; },
        why: 'Canvas context creation — precursor to fingerprinting'
      });
    } catch(e) {}

    // ═══ 2. WEBGL FINGERPRINTING ═══
    function hookWebGL(proto, name) {
      try {
        hookFn(proto, 'getParameter', 'webgl', 'high', {
          detailFn: function(a) { return { param: a[0], ctx: name }; },
          valueFn: function(v) {
            if (v === null || v === undefined) return String(v);
            if (typeof v === 'string' || typeof v === 'number') return v;
            if (v instanceof Float32Array || v instanceof Int32Array) return Array.from(v);
            return String(v).slice(0, 100);
          },
          why: 'WebGL parameter reads expose GPU vendor/renderer/capabilities'
        });
      } catch(e) {}

      try {
        hookFn(proto, 'getExtension', 'webgl', 'medium', {
          detailFn: function(a) { return { ext: a[0], ctx: name }; },
          valueFn: function(v) { return v ? 'supported' : 'null'; },
          why: 'WebGL extension enumeration for GPU capability fingerprint'
        });
      } catch(e) {}

      try {
        hookFn(proto, 'getSupportedExtensions', 'webgl', 'medium', {
          detailFn: function() { return { ctx: name }; },
          valueFn: function(v) { return v ? { count: v.length, list: v.slice(0, 5) } : null; },
          why: 'Full WebGL extension list — high entropy source'
        });
      } catch(e) {}

      try {
        if (proto.getShaderPrecisionFormat) {
          hookFn(proto, 'getShaderPrecisionFormat', 'webgl', 'high', {
            detailFn: function(a) { return { shaderType: a[0], precisionType: a[1], ctx: name }; },
            valueFn: function(v) { return v ? { rangeMin: v.rangeMin, rangeMax: v.rangeMax, precision: v.precision } : null; },
            why: 'Shader precision reveals GPU hardware specifics'
          });
        }
      } catch(e) {}

      try {
        hookFn(proto, 'getContextAttributes', 'webgl', 'low', {
          detailFn: function() { return { ctx: name }; },
          valueFn: function(v) { return v; },
          why: 'WebGL context attributes'
        });
      } catch(e) {}

      try {
        if (proto.readPixels) {
          hookFn(proto, 'readPixels', 'webgl', 'high', {
            detailFn: function(a) { return { x: a[0], y: a[1], w: a[2], h: a[3], ctx: name }; },
            why: 'WebGL pixel data extraction for GPU rendering fingerprint'
          });
        }
      } catch(e) {}
    }

    try { if (typeof WebGLRenderingContext !== 'undefined') hookWebGL(WebGLRenderingContext.prototype, 'webgl'); } catch(e) {}
    try { if (typeof WebGL2RenderingContext !== 'undefined') hookWebGL(WebGL2RenderingContext.prototype, 'webgl2'); } catch(e) {}

    // ═══ 3. AUDIO FINGERPRINTING ═══
    try {
      if (typeof AudioContext !== 'undefined') {
        hookFn(AudioContext.prototype, 'createOscillator', 'audio', 'high', { why: 'Oscillator creation for audio fingerprint' });
        hookFn(AudioContext.prototype, 'createDynamicsCompressor', 'audio', 'high', { why: 'Compressor for audio fingerprint' });
        if (AudioContext.prototype.createAnalyser) hookFn(AudioContext.prototype, 'createAnalyser', 'audio', 'medium', { why: 'Analyser for frequency data' });
        if (AudioContext.prototype.createGain) hookFn(AudioContext.prototype, 'createGain', 'audio', 'low', { why: 'Gain node — audio pipeline' });
        if (AudioContext.prototype.createScriptProcessor) hookFn(AudioContext.prototype, 'createScriptProcessor', 'audio', 'medium', { why: 'Script processor for raw audio' });

        // baseLatency getter
        try {
          var blDesc = _realGetDesc.call(Object, AudioContext.prototype, 'baseLatency');
          if (blDesc && blDesc.get) {
            hookGetter(AudioContext.prototype, 'baseLatency', 'audio', 'medium', { why: 'Audio base latency — FPjs v5 entropy source' });
          }
        } catch(e) {}

        // sampleRate getter
        try {
          var srTarget = null;
          if (_realGetDesc.call(Object, AudioContext.prototype, 'sampleRate')) {
            srTarget = AudioContext.prototype;
          } else if (typeof BaseAudioContext !== 'undefined' && _realGetDesc.call(Object, BaseAudioContext.prototype, 'sampleRate')) {
            srTarget = BaseAudioContext.prototype;
          }
          if (srTarget) {
            var srDesc = _realGetDesc.call(Object, srTarget, 'sampleRate');
            if (srDesc && srDesc.get) {
              hookGetter(srTarget, 'sampleRate', 'audio', 'medium', { why: 'Audio sample rate varies by hardware' });
            }
          }
        } catch(e) {}
      }
    } catch(e) {}

    try {
      if (typeof OfflineAudioContext !== 'undefined') {
        hookFn(OfflineAudioContext.prototype, 'startRendering', 'audio', 'critical', { why: 'Offline audio rendering — generates fingerprint hash' });
        if (OfflineAudioContext.prototype.createOscillator) hookFn(OfflineAudioContext.prototype, 'createOscillator', 'audio', 'high', { why: 'Offline oscillator' });
        if (OfflineAudioContext.prototype.createDynamicsCompressor) hookFn(OfflineAudioContext.prototype, 'createDynamicsCompressor', 'audio', 'high', { why: 'Offline compressor' });
      }
    } catch(e) {}

    // ═══ 4. FONT DETECTION ═══
    try {
      if (document.fonts && document.fonts.check) {
        var origFontCheck = document.fonts.check.bind(document.fonts);
        document.fonts.check = function(font, text) {
          var result = origFontCheck(font, text);
          log('font-detection', 'document.fonts.check', { font: font, text: text }, 'high', {
            returnValue: result, why: 'CSS Font Loading API — installed font enumeration'
          });
          return result;
        };
        try { document.fonts.check.toString = function() { return 'function check() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    try {
      hookFn(Element.prototype, 'getBoundingClientRect', 'font-detection', 'low', {
        detailFn: function() { return {}; },
        valueFn: function(v) { return v ? { w: Math.round(v.width*100)/100, h: Math.round(v.height*100)/100 } : null; },
        why: 'Element dimension measurement — mass calls = font probing'
      });
    } catch(e) {}

    // offsetWidth / offsetHeight (sampled)
    try {
      var owDesc = _realGetDesc.call(Object, HTMLElement.prototype, 'offsetWidth');
      if (owDesc && owDesc.get) {
        var owCount = 0;
        var origOW = owDesc.get;
        _realDefProp.call(Object, HTMLElement.prototype, 'offsetWidth', {
          get: function() {
            owCount++;
            var val = origOW.call(this);
            if (owCount <= 3 || owCount % 100 === 0) {
              log('font-detection', 'offsetWidth', { callCount: owCount }, owCount > 200 ? 'high' : 'low', {
                returnValue: val, why: 'Element width — bulk calls = font probe'
              });
            }
            return val;
          },
          set: owDesc.set,
          enumerable: owDesc.enumerable,
          configurable: true
        });
      }
    } catch(e) {}

    try {
      var ohDesc = _realGetDesc.call(Object, HTMLElement.prototype, 'offsetHeight');
      if (ohDesc && ohDesc.get) {
        var ohCount = 0;
        var origOH = ohDesc.get;
        _realDefProp.call(Object, HTMLElement.prototype, 'offsetHeight', {
          get: function() {
            ohCount++;
            var val = origOH.call(this);
            if (ohCount <= 3 || ohCount % 100 === 0) {
              log('font-detection', 'offsetHeight', { callCount: ohCount }, ohCount > 200 ? 'high' : 'low', {
                returnValue: val, why: 'Element height — bulk calls = font probe'
              });
            }
            return val;
          },
          set: ohDesc.set,
          enumerable: ohDesc.enumerable,
          configurable: true
        });
      }
    } catch(e) {}

    // ═══ 5. NAVIGATOR PROPERTIES ═══
    try {
      var navProps = [
        { prop: 'userAgent', risk: 'medium', why: 'Browser identity string' },
        { prop: 'platform', risk: 'medium', why: 'OS platform identifier' },
        { prop: 'language', risk: 'medium', why: 'Primary language — locale fingerprint' },
        { prop: 'languages', risk: 'medium', why: 'Full language list — high entropy' },
        { prop: 'hardwareConcurrency', risk: 'high', why: 'CPU core count — hardware fingerprint' },
        { prop: 'deviceMemory', risk: 'high', why: 'RAM amount — device fingerprint' },
        { prop: 'maxTouchPoints', risk: 'medium', why: 'Touch capability — device type detection' },
        { prop: 'vendor', risk: 'low', why: 'Browser vendor string' },
        { prop: 'appVersion', risk: 'low', why: 'Legacy browser version' },
        { prop: 'cookieEnabled', risk: 'low', why: 'Cookie support check' },
        { prop: 'doNotTrack', risk: 'low', why: 'DNT header — ironically fingerprint signal' },
        { prop: 'webdriver', risk: 'critical', why: 'Automation detection flag' },
        { prop: 'pdfViewerEnabled', risk: 'low', why: 'PDF viewer — FPjs v5 source' }
      ];
      navProps.forEach(function(np) {
        try {
          var d = _realGetDesc.call(Object, Navigator.prototype, np.prop) || _realGetDesc.call(Object, navigator, np.prop);
          if (d && d.get) {
            hookGetter(d.get === (_realGetDesc.call(Object, Navigator.prototype, np.prop) || {}).get ? Navigator.prototype : navigator, 
              np.prop, 'fingerprint', np.risk, { why: np.why });
          }
        } catch(e) {}
      });
    } catch(e) {}

    // ═══ 6. PERMISSIONS API ═══
    try {
      if (navigator.permissions && navigator.permissions.query) {
        hookFn(navigator.permissions, 'query', 'permissions', 'high', {
          detailFn: function(a) { return { name: a[0] ? a[0].name : 'unknown' }; },
          why: 'Permission state probing for fingerprint consistency'
        });
      }
    } catch(e) {}

    // ═══ 7. STORAGE ═══
    try {
      hookFn(Storage.prototype, 'getItem', 'storage', 'low', {
        detailFn: function(a) { return { key: String(a[0]).slice(0, 50) }; },
        valueFn: function(v) { return v ? String(v).slice(0, 100) : null; },
        why: 'Storage read — tracking/fingerprint data retrieval'
      });
      hookFn(Storage.prototype, 'setItem', 'storage', 'medium', {
        detailFn: function(a) { return { key: String(a[0]).slice(0, 50), size: a[1] ? String(a[1]).length : 0 }; },
        why: 'Storage write — tracking cookie/supercookie creation'
      });
    } catch(e) {}

    try {
      if (typeof indexedDB !== 'undefined' && indexedDB.open) {
        hookFn(IDBFactory.prototype, 'open', 'storage', 'medium', {
          detailFn: function(a) { return { dbName: String(a[0]).slice(0, 50) }; },
          why: 'IndexedDB open — persistent fingerprint storage'
        });
      }
    } catch(e) {}

    // Cookie access
    try {
      var cookieDesc = _realGetDesc.call(Object, Document.prototype, 'cookie');
      if (cookieDesc) {
        var origCookieGet = cookieDesc.get;
        var origCookieSet = cookieDesc.set;
        var cookieReadCount = 0;
        _realDefProp.call(Object, Document.prototype, 'cookie', {
          get: function() {
            cookieReadCount++;
            var val = origCookieGet.call(this);
            if (cookieReadCount <= 3 || cookieReadCount % 50 === 0) {
              log('storage', 'document.cookie.get', { readCount: cookieReadCount }, 'low', {
                returnValue: val ? val.slice(0, 100) : '', why: 'Cookie read'
              });
            }
            return val;
          },
          set: function(v) {
            log('storage', 'document.cookie.set', { preview: String(v).slice(0, 80) }, 'medium', {
              why: 'Cookie write — tracking or session'
            });
            return origCookieSet.call(this, v);
          },
          enumerable: cookieDesc.enumerable,
          configurable: true
        });
      }
    } catch(e) {}

    // ═══ 8. SCREEN/DISPLAY ═══
    try {
      var screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
      screenProps.forEach(function(prop) {
        try {
          var d = _realGetDesc.call(Object, Screen.prototype, prop);
          if (d && d.get) {
            hookGetter(Screen.prototype, prop, 'screen', 'medium', { why: 'Screen ' + prop + ' — display fingerprint' });
          }
        } catch(e) {}
      });
    } catch(e) {}

    try {
      var dprDesc = _realGetDesc.call(Object, window, 'devicePixelRatio') || _realGetDesc.call(Object, Window.prototype, 'devicePixelRatio');
      if (dprDesc && dprDesc.get) {
        var dprTarget = _realGetDesc.call(Object, Window.prototype, 'devicePixelRatio') ? Window.prototype : window;
        hookGetter(dprTarget, 'devicePixelRatio', 'screen', 'medium', { why: 'Device pixel ratio — display density fingerprint' });
      }
    } catch(e) {}

    // matchMedia
    try {
      hookFn(window, 'matchMedia', 'screen', 'medium', {
        detailFn: function(a) { return { query: String(a[0]).slice(0, 100) }; },
        valueFn: function(v) { return v ? { matches: v.matches } : null; },
        why: 'CSS media query — prefers-color-scheme, reduced-motion fingerprint'
      });
    } catch(e) {}

    // ═══ 9. NETWORK / FETCH / XHR ═══
    try {
      var origFetch = window.fetch;
      if (origFetch) {
        window.fetch = function() {
          var url = arguments[0];
          var urlStr = '';
          try { urlStr = typeof url === 'string' ? url : (url && url.url ? url.url : String(url)); } catch(e) {}
          log('network', 'fetch', { url: urlStr.slice(0, 200) }, 'medium', {
            why: 'Network request — potential data exfiltration'
          });
          return origFetch.apply(this, arguments);
        };
        try { window.fetch.toString = function() { return origFetch.toString(); }; } catch(e) {}
      }
    } catch(e) {}

    try {
      var origXHROpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, url) {
        log('network', 'XMLHttpRequest.open', { method: method, url: String(url).slice(0, 200) }, 'medium', {
          why: 'XHR request — data transmission monitoring'
        });
        return origXHROpen.apply(this, arguments);
      };
    } catch(e) {}

    try {
      if (navigator.sendBeacon) {
        var origBeacon = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function(url, data) {
          log('exfiltration', 'sendBeacon', { url: String(url).slice(0, 200), size: data ? data.length || 0 : 0 }, 'high', {
            why: 'Beacon API — fire-and-forget data exfiltration'
          });
          return origBeacon(url, data);
        };
      }
    } catch(e) {}

    // ═══ 10. WEBRTC ═══
    try {
      if (typeof RTCPeerConnection !== 'undefined') {
        var OrigRTC = RTCPeerConnection;
        window.RTCPeerConnection = function() {
          var config = arguments[0];
          log('webrtc', 'RTCPeerConnection', { servers: config ? JSON.stringify(config.iceServers || []).slice(0, 200) : 'none' }, 'critical', {
            why: 'WebRTC connection — can leak real IP behind VPN/proxy'
          });
          var pc = new OrigRTC(config);
          var origCreateOffer = pc.createOffer.bind(pc);
          pc.createOffer = function() {
            log('webrtc', 'createOffer', {}, 'critical', { why: 'ICE offer generation — IP harvesting step' });
            return origCreateOffer.apply(pc, arguments);
          };
          return pc;
        };
        window.RTCPeerConnection.prototype = OrigRTC.prototype;
      }
    } catch(e) {}

    // ═══ 11. PERFORMANCE TIMING ═══
    try {
      hookFn(Performance.prototype, 'getEntries', 'perf-timing', 'medium', {
        valueFn: function(v) { return v ? { count: v.length } : null; },
        why: 'Performance entries — resource timing fingerprint'
      });
      hookFn(Performance.prototype, 'getEntriesByType', 'perf-timing', 'medium', {
        detailFn: function(a) { return { type: a[0] }; },
        valueFn: function(v) { return v ? { count: v.length } : null; },
        why: 'Performance entries by type'
      });
    } catch(e) {}

    try {
      if (performance.now) {
        var origPerfNow = performance.now.bind(performance);
        var perfNowCount = 0;
        performance.now = function() {
          perfNowCount++;
          var val = origPerfNow();
          if (perfNowCount <= 2 || perfNowCount % 200 === 0) {
            log('perf-timing', 'performance.now', { callCount: perfNowCount }, 'low', {
              returnValue: Math.round(val*100)/100, why: 'High-res timer — timing attack / micro-benchmark'
            });
          }
          return val;
        };
      }
    } catch(e) {}

    // ═══ 12. MEDIA DEVICES ═══
    try {
      if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        hookFn(navigator.mediaDevices, 'enumerateDevices', 'media-devices', 'high', {
          valueFn: function(v) { return v ? { count: v.length } : null; },
          why: 'Media device enumeration — camera/mic inventory fingerprint'
        });
      }
    } catch(e) {}

    // ═══ 13. DOM PROBING ═══
    try {
      var origCreateElement = document.createElement.bind(document);
      document.createElement = function(tag) {
        var lTag = tag ? tag.toLowerCase() : '';
        if (['canvas', 'iframe', 'audio', 'video', 'object', 'embed'].indexOf(lTag) >= 0) {
          log('dom-probe', 'createElement', { tag: lTag }, lTag === 'canvas' ? 'high' : 'medium', {
            why: 'Dynamic element creation — canvas/iframe for fingerprinting'
          });
        }
        return origCreateElement.apply(document, arguments);
      };
      try { document.createElement.toString = function() { return 'function createElement() { [native code] }'; }; } catch(e) {}
    } catch(e) {}

    // ═══ 14. CLIPBOARD ═══
    try {
      if (navigator.clipboard) {
        if (navigator.clipboard.readText) {
          var origClipRead = navigator.clipboard.readText.bind(navigator.clipboard);
          navigator.clipboard.readText = function() {
            log('clipboard', 'clipboard.readText', {}, 'critical', { why: 'Clipboard read — private data access' });
            return origClipRead();
          };
        }
        if (navigator.clipboard.writeText) {
          var origClipWrite = navigator.clipboard.writeText.bind(navigator.clipboard);
          navigator.clipboard.writeText = function(text) {
            log('clipboard', 'clipboard.writeText', { size: text ? text.length : 0 }, 'high', { why: 'Clipboard write' });
            return origClipWrite(text);
          };
        }
      }
    } catch(e) {}

    // ═══ 15. GEOLOCATION ═══
    try {
      if (navigator.geolocation) {
        var origGetPos = navigator.geolocation.getCurrentPosition;
        navigator.geolocation.getCurrentPosition = function() {
          log('geolocation', 'getCurrentPosition', {}, 'critical', { why: 'Physical location tracking' });
          return origGetPos.apply(navigator.geolocation, arguments);
        };
        var origWatchPos = navigator.geolocation.watchPosition;
        navigator.geolocation.watchPosition = function() {
          log('geolocation', 'watchPosition', {}, 'critical', { why: 'Continuous location tracking' });
          return origWatchPos.apply(navigator.geolocation, arguments);
        };
      }
    } catch(e) {}

    // ═══ 16. SERVICE WORKER ═══
    try {
      if (navigator.serviceWorker && navigator.serviceWorker.register) {
        var origSWReg = navigator.serviceWorker.register;
        navigator.serviceWorker.register = function(url) {
          log('service-worker', 'sw.register', { url: String(url).slice(0, 100) }, 'critical', {
            why: 'Service worker — persistent background code'
          });
          return origSWReg.apply(navigator.serviceWorker, arguments);
        };
      }
    } catch(e) {}

    // ═══ 17. BATTERY API ═══
    try {
      if (navigator.getBattery) {
        var origGetBattery = navigator.getBattery.bind(navigator);
        navigator.getBattery = function() {
          var result = origGetBattery();
          result.then(function(battery) {
            log('hardware', 'getBattery', {}, 'high', {
              returnValue: { charging: battery.charging, level: battery.level },
              why: 'Battery status — mobile device fingerprint'
            });
          }).catch(function(){});
          return result;
        };
      }
    } catch(e) {}

    // ═══ 18. DATE/TIMEZONE ═══
    try {
      hookFn(Date.prototype, 'getTimezoneOffset', 'fingerprint', 'medium', {
        valueFn: function(v) { return v; },
        why: 'Timezone offset reveals region'
      });
    } catch(e) {}

    try {
      if (window.Intl && window.Intl.DateTimeFormat) {
        var origDTF = window.Intl.DateTimeFormat;
        var origResolved = origDTF.prototype.resolvedOptions;
        origDTF.prototype.resolvedOptions = function() {
          var result = origResolved.call(this);
          log('fingerprint', 'Intl.DateTimeFormat.resolvedOptions', {}, 'medium', {
            returnValue: result ? { locale: result.locale, timeZone: result.timeZone } : null,
            why: 'Intl locale/timezone — FPjs v5 dateTimeLocale source'
          });
          return result;
        };
      }
    } catch(e) {}

    // ═══ 19. MATH FINGERPRINTING ═══
    try {
      var mathFns = ['acos', 'acosh', 'asin', 'asinh', 'atan', 'atanh', 'atan2', 'cos', 'cosh', 'exp', 'expm1', 'log', 'log1p', 'log2', 'sin', 'sinh', 'sqrt', 'tan', 'tanh'];
      mathFns.forEach(function(fn) {
        try {
          if (typeof Math[fn] === 'function') {
            hookFn(Math, fn, 'math-fingerprint', 'medium', {
              detailFn: function(a) { return { args: Array.prototype.slice.call(a, 0, 2) }; },
              valueFn: function(v) { return v; },
              why: 'Math.' + fn + ' precision varies across engines/architectures'
            });
          }
        } catch(e) {}
      });
    } catch(e) {}

    // ═══════════════════════════════════════════
    //  LAYER 4: EXTENDED VECTORS (12 new categories)
    // ═══════════════════════════════════════════

    // ═══ 20. SPEECH SYNTHESIS ═══
    try {
      if (window.speechSynthesis && window.speechSynthesis.getVoices) {
        var origGetVoices = window.speechSynthesis.getVoices.bind(window.speechSynthesis);
        window.speechSynthesis.getVoices = function() {
          var voices = origGetVoices();
          log('speech', 'speechSynthesis.getVoices', { voiceCount: voices ? voices.length : 0 }, 'high', {
            returnValue: voices ? voices.slice(0, 5).map(function(v) { return { name: v.name, lang: v.lang }; }) : [],
            why: 'Speech voice list reveals OS, installed language packs'
          });
          return voices;
        };
      }
    } catch(e) {}

    // ═══ 21. CLIENT HINTS ═══
    try {
      if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
        var origHEV = navigator.userAgentData.getHighEntropyValues.bind(navigator.userAgentData);
        navigator.userAgentData.getHighEntropyValues = function(hints) {
          log('client-hints', 'getHighEntropyValues', { hints: hints }, 'high', {
            why: 'Client Hints — OS version, CPU arch, device model'
          });
          return origHEV(hints);
        };
      }
    } catch(e) {}

    // ═══ 22. INTL FINGERPRINTING ═══
    try {
      if (window.Intl) {
        ['ListFormat', 'NumberFormat', 'Collator', 'PluralRules', 'RelativeTimeFormat'].forEach(function(cls) {
          try {
            if (window.Intl[cls] && window.Intl[cls].prototype.resolvedOptions) {
              var origRO = window.Intl[cls].prototype.resolvedOptions;
              window.Intl[cls].prototype.resolvedOptions = function() {
                var r = origRO.call(this);
                log('intl-fingerprint', 'Intl.' + cls + '.resolvedOptions', {}, 'medium', {
                  returnValue: r ? { locale: r.locale } : null,
                  why: 'Intl.' + cls + ' locale data — fingerprint entropy'
                });
                return r;
              };
            }
          } catch(e) {}
        });
      }
    } catch(e) {}

    // ═══ 23. CSS.supports FINGERPRINTING ═══
    try {
      if (window.CSS && window.CSS.supports) {
        var origCSSSupports = window.CSS.supports;
        var cssCount = 0;
        window.CSS.supports = function() {
          cssCount++;
          var result = origCSSSupports.apply(window.CSS, arguments);
          if (cssCount <= 10 || cssCount % 50 === 0) {
            log('css-fingerprint', 'CSS.supports', { query: String(arguments[0]).slice(0, 80), callCount: cssCount }, 'medium', {
              returnValue: result, why: 'CSS feature detection fingerprint'
            });
          }
          return result;
        };
      }
    } catch(e) {}

    // ═══ 24. PROPERTY ENUMERATION (CreepJS lie detection) ═══
    try {
      var origObjKeys = Object.keys;
      Object.keys = function(obj) {
        var result = origObjKeys.call(Object, obj);
        if (obj === navigator || obj === screen || obj === Navigator.prototype || obj === Screen.prototype) {
          log('property-enum', 'Object.keys', { target: obj === navigator ? 'navigator' : 'screen' }, 'high', {
            returnValue: { count: result.length },
            why: 'Property enumeration — CreepJS-style lie detection'
          });
        }
        return result;
      };
    } catch(e) {}

    try {
      var origObjGetOPN = Object.getOwnPropertyNames;
      Object.getOwnPropertyNames = function(obj) {
        var result = origObjGetOPN.call(Object, obj);
        if (obj === navigator || obj === screen || obj === Navigator.prototype || obj === Screen.prototype) {
          log('property-enum', 'Object.getOwnPropertyNames', { target: 'navigator/screen' }, 'high', {
            returnValue: { count: result.length },
            why: 'Property name enumeration — prototype lie detection'
          });
        }
        return result;
      };
    } catch(e) {}

    // ═══ 25. OFFSCREEN CANVAS ═══
    try {
      if (typeof OffscreenCanvas !== 'undefined') {
        var OrigOffscreen = OffscreenCanvas;
        window.OffscreenCanvas = function(w, h) {
          log('offscreen-canvas', 'new OffscreenCanvas', { width: w, height: h }, 'high', {
            why: 'OffscreenCanvas — worker-based canvas fingerprinting'
          });
          return new OrigOffscreen(w, h);
        };
        window.OffscreenCanvas.prototype = OrigOffscreen.prototype;
      }
    } catch(e) {}

    // ═══ 26. EXFILTRATION MONITORING (Image pixel, WebSocket) ═══
    try {
      var origImage = window.Image;
      window.Image = function() {
        var img = new origImage();
        var origSrcDesc = _realGetDesc.call(Object, HTMLImageElement.prototype, 'src') || _realGetDesc.call(Object, img.__proto__, 'src');
        if (origSrcDesc && origSrcDesc.set) {
          var origSrcSet = origSrcDesc.set;
          _realDefProp.call(Object, img, 'src', {
            set: function(v) {
              var urlStr = String(v);
              if (urlStr.length > 200 || /collect|track|pixel|beacon|fingerprint|fp/.test(urlStr)) {
                log('exfiltration', 'img.src', { url: urlStr.slice(0, 200) }, 'high', {
                  why: 'Image pixel tracking — data exfiltration via URL params'
                });
              }
              return origSrcSet.call(this, v);
            },
            get: origSrcDesc.get,
            enumerable: true,
            configurable: true
          });
        }
        return img;
      };
    } catch(e) {}

    try {
      if (typeof WebSocket !== 'undefined') {
        var OrigWS = WebSocket;
        window.WebSocket = function(url, protocols) {
          log('exfiltration', 'WebSocket', { url: String(url).slice(0, 200) }, 'high', {
            why: 'WebSocket connection — potential realtime data exfiltration'
          });
          return protocols ? new OrigWS(url, protocols) : new OrigWS(url);
        };
        window.WebSocket.prototype = OrigWS.prototype;
        window.WebSocket.CONNECTING = OrigWS.CONNECTING;
        window.WebSocket.OPEN = OrigWS.OPEN;
        window.WebSocket.CLOSING = OrigWS.CLOSING;
        window.WebSocket.CLOSED = OrigWS.CLOSED;
      }
    } catch(e) {}

    // ═══ 27. HONEYPOT TRAP ═══
    try {
      var honeypotProps = ['__fpjs_d_m', '__fp_hash', '_browserfp', '__canvas_fp', '_device_id', '__track_id'];
      honeypotProps.forEach(function(prop) {
        try {
          _realDefProp.call(Object, window, prop, {
            get: function() {
              log('honeypot', 'honeypot.' + prop, { trap: prop }, 'critical', {
                why: 'HONEYPOT TRIGGERED — script probed trap property: ' + prop
              });
              return undefined;
            },
            set: function(v) {
              log('honeypot', 'honeypot.' + prop + '.set', { trap: prop, value: String(v).slice(0, 50) }, 'critical', {
                why: 'HONEYPOT WRITE — script set trap property: ' + prop
              });
            },
            enumerable: false,
            configurable: true
          });
        } catch(e) {}
      });
    } catch(e) {}

    // ═══ 28. CREDENTIAL MANAGEMENT ═══
    try {
      if (navigator.credentials) {
        if (navigator.credentials.get) {
          hookFn(navigator.credentials, 'get', 'credential', 'critical', {
            why: 'Credential API get — WebAuthn/FIDO fingerprint'
          });
        }
        if (navigator.credentials.create) {
          hookFn(navigator.credentials, 'create', 'credential', 'critical', {
            why: 'Credential API create — authenticator fingerprint'
          });
        }
      }
    } catch(e) {}

    // ═══ 29. MUTATION OBSERVER (DOM probe detection) ═══
    try {
      var OrigMO = MutationObserver;
      window.MutationObserver = function(callback) {
        log('dom-probe-mo', 'new MutationObserver', {}, 'low', {
          why: 'MutationObserver — monitors DOM changes (tracking/fingerprint)'
        });
        return new OrigMO(callback);
      };
      window.MutationObserver.prototype = OrigMO.prototype;
    } catch(e) {}

    // ═══ 30. INTERSECTION OBSERVER ═══
    try {
      if (typeof IntersectionObserver !== 'undefined') {
        var OrigIO = IntersectionObserver;
        window.IntersectionObserver = function(callback, options) {
          log('dom-probe-io', 'new IntersectionObserver', { rootMargin: options ? options.rootMargin : '' }, 'low', {
            why: 'IntersectionObserver — viewport tracking / ad visibility'
          });
          return new OrigIO(callback, options);
        };
        window.IntersectionObserver.prototype = OrigIO.prototype;
      }
    } catch(e) {}

    // ═══ 31. GAMEPAD API ═══
    try {
      if (navigator.getGamepads) {
        hookFn(navigator, 'getGamepads', 'hardware', 'medium', {
          valueFn: function(v) { return v ? { count: Array.from(v).filter(Boolean).length } : null; },
          why: 'Gamepad enumeration — hardware peripherals fingerprint'
        });
      }
    } catch(e) {}

    // ═══════════════════════════════════════════
    //  BOOT_OK + GLOBAL EXPORT
    // ═══════════════════════════════════════════

    // BOOT_OK — mandatory coverage proof event
    _sentinel.bootOk = true;
    try {
      log('system', 'BOOT_OK', {
        frameId: _sentinel.frameId,
        url: location.href,
        origin: location.origin,
        isTop: window === window.top,
        timestamp: Date.now()
      }, 'info', {
        why: 'Coverage proof — Sentinel is active in this execution context'
      });
    } catch(e) {}

    // Global export — this is how the Node.js side reads results
    window.__SENTINEL_DATA__ = _sentinel;

    window.__SENTINEL_CONTEXT_MAP__ = [{
      type: 'page',
      url: (function() { try { return location.href; } catch(e) { return 'unknown'; } })(),
      origin: (function() { try { return location.origin; } catch(e) { return 'unknown'; } })(),
      frameId: _sentinel.frameId,
      bootOk: true,
      timestamp: Date.now()
    }];

    // ═══ PUSH TELEMETRY (optional, sends COPIES not splice) ═══
    if (typeof window.__SENTINEL_PUSH__ === 'function') {
      var _lastPushIndex = 0;
      setInterval(function() {
        if (_sentinel.events.length > _lastPushIndex) {
          try {
            var newEvents = _sentinel.events.slice(_lastPushIndex, _lastPushIndex + 500);
            _lastPushIndex += newEvents.length;
            window.__SENTINEL_PUSH__(JSON.stringify({
              type: 'event_batch',
              frameId: _sentinel.frameId,
              origin: (function() { try { return location.origin; } catch(e) { return 'unknown'; } })(),
              events: newEvents
            }));
          } catch(e) {}
        }
      }, 2000);
    }

    console.log('[Sentinel v4.1] Forensic Maling Catcher active — monitoring 31 categories | Frame: ' + _sentinel.frameId);
  })();
  `;
}

module.exports = { getInterceptorScript };
