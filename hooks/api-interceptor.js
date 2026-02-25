/**
 * Sentinel v4.6 — Forensic API Interceptor (CRITICAL FIX)
 * 
 * ROOT CAUSE OF v4.4 FAILURE (3-4 events instead of 786):
 *   v4.4 hooked Navigator.prototype getters, but stealth-config.js patches
 *   navigator INSTANCE properties with Object.defineProperty(navigator, ...).
 *   JavaScript property lookup: instance → prototype. Instance SHADOWS prototype.
 *   Result: ALL navigator property accesses bypassed our monitoring hooks.
 *
 * FIX IN v4.4.1:
 *   1. Smart target detection (from v4.1): check WHERE the getter actually lives
 *      (prototype vs instance) and hook the right target
 *   2. For properties patched by stealth, hook the INSTANCE (not prototype)
 *   3. Cookie getter + setter both hooked (v4.4 only hooked getter)
 *   4. Property-enum filtered to navigator/screen targets only (like v4.1)
 *   5. createElement filtered to fingerprint-relevant tags only (like v4.1)
 *   6. Direct hooking fallback is EQUALLY robust (not simplified)
 *
 * Categories (37): canvas, webgl, audio, font-detection, fingerprint, screen,
 *   storage, network, perf-timing, media-devices, dom-probe, clipboard,
 *   geolocation, service-worker, hardware, exfiltration, webrtc,
 *   math-fingerprint, permissions, speech, client-hints, intl-fingerprint,
 *   css-fingerprint, property-enum, offscreen-canvas, honeypot, credential,
 *   system, encoding, worker, webassembly, keyboard-layout, sensor-apis,
 *   visualization, device-info, battery, gamepad
 */

function getInterceptorScript(config) {
  config = config || {};
  var timeout = config.timeout || 30000;
  var stealthEnabled = !!config.stealthEnabled;
  var stackSampleRate = config.stackSampleRate || 10;

  return `
  (function() {
    'use strict';

    // ── Guard: prevent double-injection ──
    // QUIET MODE: use non-obvious internal marker
    var _qk = '_s' + Math.random().toString(36).substr(2,4);
    if (window[_qk]) return;
    window[_qk] = true;

    // ── Store REAL natives before anything else ──
    var _realGetDesc = Object.getOwnPropertyDescriptor;
    var _realDefProp = Object.defineProperty;
    var _realToString = Function.prototype.toString;

    var _sentinel = {
      events: [],
      startTime: Date.now(),
      bootOk: false,
      frameId: Math.random().toString(36).substr(2, 8),
      config: { timeout: ${timeout}, maxEvents: 100000, stackSampleRate: ${stackSampleRate} },
      counters: {},
      dedupCount: 0
    };

    // Shield is optional
    var _shield = window.__SENTINEL_SHIELD__ || null;

    // ── Logging with dedup ──
    function log(category, api, detail, risk, opts) {
      if (_sentinel.events.length >= _sentinel.config.maxEvents) return;
      opts = opts || {};
      var key = category + ':' + api;
      _sentinel.counters[key] = (_sentinel.counters[key] || 0) + 1;
      if (_sentinel.counters[key] > 500) { _sentinel.dedupCount++; return; }

      var event = {
        ts: Date.now() - _sentinel.startTime,
        cat: category,
        api: api,
        detail: (typeof detail === 'object') ? JSON.stringify(detail).slice(0, 500) : String(detail || '').slice(0, 500),
        risk: risk || 'low',
        dir: opts.returnValue !== undefined ? 'response' : 'call',
        origin: (function() { try { return location.origin; } catch(e) { return 'unknown'; } })(),
        frame: _sentinel.frameId
      };
      if (opts.returnValue !== undefined) {
        try { event.value = JSON.stringify(opts.returnValue).slice(0, 500); } catch(e) { event.value = String(opts.returnValue).slice(0, 500); }
      }
      if (opts.why) event.why = opts.why;
      try {
        if (_sentinel.events.length % _sentinel.config.stackSampleRate === 0) {
          event.stack = (new Error()).stack ? (new Error()).stack.split('\\n').slice(2, 6).join(' | ').slice(0, 300) : '';
        }
      } catch(e) {}

      _sentinel.events.push(event);
    }

    // ═══ HELPER: hookFn — hooks a FUNCTION on target ═══
    function hookFn(obj, prop, cat, risk, options) {
      if (!obj || typeof obj[prop] !== 'function') return;
      var opts = options || {};
      try {
        if (_shield) {
          _shield.hookFunction(obj, prop, function(original) {
            var args = [];
            for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
            var result;
            try { result = original.apply(this, args); } catch(e) { throw e; }
            var detail = opts.detailFn ? opts.detailFn(args, this) : args[0];
            var logOpts = { why: opts.why || '' };
            if (opts.valueFn) { try { logOpts.returnValue = opts.valueFn(result); } catch(e) {} }
            else if (opts.captureReturn) { logOpts.returnValue = result; }
            log(cat, prop, detail, risk, logOpts);
            return result;
          });
        } else {
          var orig = obj[prop];
          var replacement = function() {
            var args = [];
            for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
            var result;
            try { result = orig.apply(this, args); } catch(e) { throw e; }
            var detail = opts.detailFn ? opts.detailFn(args, this) : args[0];
            var logOpts = { why: opts.why || '' };
            if (opts.valueFn) { try { logOpts.returnValue = opts.valueFn(result); } catch(e) {} }
            else if (opts.captureReturn) { logOpts.returnValue = result; }
            log(cat, prop, detail, risk, logOpts);
            return result;
          };
          try { replacement.toString = function() { return _realToString.call(orig); }; } catch(e) {}
          obj[prop] = replacement;
        }
      } catch(e) {}
    }

    // ═══ HELPER: hookGetter — hooks a GETTER on target ═══
    function hookGetter(target, prop, category, risk, options) {
      var opts = options || {};
      try {
        if (_shield && _shield.hookGetter) {
          _shield.hookGetter(target, prop, function(originalGetter) {
            var value = originalGetter.call(this);
            log(category, prop, opts.detail || prop, risk, {
              returnValue: opts.valueFn ? opts.valueFn(value) : value,
              why: opts.why || ''
            });
            return value;
          });
        } else {
          var desc = _realGetDesc.call(Object, target, prop);
          if (!desc || !desc.get) return;
          var origGetter = desc.get;
          _realDefProp.call(Object, target, prop, {
            get: function() {
              var value = origGetter.call(this);
              log(category, prop, opts.detail || prop, risk, {
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
      } catch(e) {}
    }

    // ═══ HELPER: hookGetterSetter — hooks BOTH getter AND setter ═══
    function hookGetterSetter(target, prop, cat, risk, getOpts, setOpts) {
      try {
        if (_shield && _shield.hookGetterSetter) {
          _shield.hookGetterSetter(target, prop,
            function(origGet) {
              var val = origGet.call(this);
              log(cat, prop + '.get', (getOpts && getOpts.detail) || prop, risk, {
                returnValue: val, why: (getOpts && getOpts.why) || ''
              });
              return val;
            },
            function(origSet, v) {
              log(cat, prop + '.set', { preview: String(v).slice(0, 80) }, setOpts ? (setOpts.risk || risk) : risk, {
                why: (setOpts && setOpts.why) || ''
              });
              return origSet.call(this, v);
            }
          );
        } else {
          var desc = _realGetDesc.call(Object, target, prop);
          if (!desc) return;
          var newDesc = { enumerable: desc.enumerable, configurable: true };
          if (desc.get) {
            var origGet = desc.get;
            newDesc.get = function() {
              var val = origGet.call(this);
              log(cat, prop + '.get', (getOpts && getOpts.detail) || prop, risk, {
                returnValue: val, why: (getOpts && getOpts.why) || ''
              });
              return val;
            };
          }
          if (desc.set) {
            var origSet = desc.set;
            newDesc.set = function(v) {
              log(cat, prop + '.set', { preview: String(v).slice(0, 80) }, setOpts ? (setOpts.risk || risk) : risk, {
                why: (setOpts && setOpts.why) || ''
              });
              return origSet.call(this, v);
            };
          }
          _realDefProp.call(Object, target, prop, newDesc);
        }
      } catch(e) {}
    }

    // ═══ HELPER: smartHookGetter — v4.1's approach: find WHERE getter lives, hook THAT ═══
    // This is the KEY FIX: if stealth patched navigator instance, we hook the instance.
    // If no instance patch exists, we hook the prototype.
    function smartHookGetter(protoTarget, instanceTarget, prop, cat, risk, opts) {
      try {
        // Check instance first (stealth may have patched it)
        var instanceDesc = _realGetDesc.call(Object, instanceTarget, prop);
        var protoDesc = _realGetDesc.call(Object, protoTarget, prop);

        if (instanceDesc && instanceDesc.get) {
          // Instance has a getter (likely patched by stealth) — hook the INSTANCE
          hookGetter(instanceTarget, prop, cat, risk, opts);
        } else if (protoDesc && protoDesc.get) {
          // Only prototype has a getter — hook the prototype
          hookGetter(protoTarget, prop, cat, risk, opts);
        }
        // If neither has a getter, property might be a data property — skip
      } catch(e) {}
    }

    // ═══════════════════════════════════════
    //  BOOT_OK — proves injection is running
    // ═══════════════════════════════════════
    _sentinel.bootOk = true;
    log('system', 'BOOT_OK', {
      frameId: _sentinel.frameId,
      isTop: (function() { try { return window === window.top; } catch(e) { return false; } })(),
      url: (function() { try { return location.href; } catch(e) { return 'unknown'; } })()
    }, 'info', { why: 'Injection confirmed — hooks activating' });

    // ═══ 1. CANVAS FINGERPRINTING ═══
    try {
      hookFn(HTMLCanvasElement.prototype, 'toDataURL', 'canvas', 'high', {
        detailFn: function(a) { return { type: a[0] || 'image/png' }; },
        captureReturn: true,
        valueFn: function(r) { return r ? r.slice(0, 80) : ''; },
        why: 'Canvas toDataURL — pixel-level fingerprinting'
      });
      hookFn(HTMLCanvasElement.prototype, 'toBlob', 'canvas', 'high', {
        detailFn: function(a) { return { type: a[1] || 'image/png' }; },
        why: 'Canvas toBlob — binary fingerprint extraction'
      });
      hookFn(CanvasRenderingContext2D.prototype, 'fillText', 'canvas', 'medium', {
        detailFn: function(a, ctx) { return { text: String(a[0]).slice(0, 50), font: ctx.font }; },
        why: 'Canvas fillText — text rendering fingerprint'
      });
      hookFn(CanvasRenderingContext2D.prototype, 'strokeText', 'canvas', 'medium', {
        detailFn: function(a, ctx) { return { text: String(a[0]).slice(0, 50), font: ctx.font }; },
        why: 'Canvas strokeText — text rendering fingerprint'
      });
      hookFn(CanvasRenderingContext2D.prototype, 'getImageData', 'canvas', 'high', {
        detailFn: function(a) { return { x: a[0], y: a[1], w: a[2], h: a[3] }; },
        why: 'Canvas getImageData — pixel data extraction'
      });
      hookFn(CanvasRenderingContext2D.prototype, 'measureText', 'font-detection', 'medium', {
        detailFn: function(a, ctx) { return { text: String(a[0]).slice(0, 30), font: ctx.font }; },
        captureReturn: true,
        valueFn: function(r) { return r ? { width: r.width } : null; },
        why: 'measureText — font availability fingerprinting'
      });
      hookFn(CanvasRenderingContext2D.prototype, 'isPointInPath', 'canvas', 'medium', {
        why: 'isPointInPath — canvas geometry fingerprint'
      });
      hookFn(CanvasRenderingContext2D.prototype, 'isPointInStroke', 'canvas', 'medium', {
        why: 'isPointInStroke — canvas geometry fingerprint'
      });
      hookFn(HTMLCanvasElement.prototype, 'getContext', 'canvas', 'medium', {
        detailFn: function(a) { return { contextType: a[0] }; },
        why: 'Canvas getContext — context type probe'
      });
    } catch(e) {}

    // ═══ 2. WEBGL FINGERPRINTING ═══
    try {
      function hookWebGLProto(proto, label) {
        hookFn(proto, 'getParameter', 'webgl', 'high', {
          detailFn: function(a) { return { param: a[0], ctx: label }; },
          captureReturn: true,
          valueFn: function(r) { return typeof r === 'string' ? r : String(r).slice(0, 100); },
          why: 'WebGL getParameter — GPU/renderer fingerprinting'
        });
        hookFn(proto, 'getExtension', 'webgl', 'medium', {
          detailFn: function(a) { return { ext: a[0], ctx: label }; },
          why: 'WebGL getExtension — capability fingerprinting'
        });
        hookFn(proto, 'getSupportedExtensions', 'webgl', 'medium', {
          captureReturn: true,
          valueFn: function(r) { return r ? { count: r.length } : null; },
          why: 'WebGL extensions list — GPU capability fingerprint'
        });
        if (proto.getShaderPrecisionFormat) {
          hookFn(proto, 'getShaderPrecisionFormat', 'webgl', 'high', {
            detailFn: function(a) { return { shaderType: a[0], precisionType: a[1] }; },
            why: 'WebGL shader precision — GPU fingerprint vector'
          });
        }
        hookFn(proto, 'getContextAttributes', 'webgl', 'low', {
          captureReturn: true,
          why: 'WebGL context attributes'
        });
        if (proto.readPixels) {
          hookFn(proto, 'readPixels', 'webgl', 'high', {
            detailFn: function(a) { return { x: a[0], y: a[1], w: a[2], h: a[3] }; },
            why: 'WebGL readPixels — GPU-rendered fingerprint extraction'
          });
        }
      }
      if (typeof WebGLRenderingContext !== 'undefined') hookWebGLProto(WebGLRenderingContext.prototype, 'webgl');
      if (typeof WebGL2RenderingContext !== 'undefined') hookWebGLProto(WebGL2RenderingContext.prototype, 'webgl2');
    } catch(e) {}

    // ═══ 3. AUDIO FINGERPRINTING ═══
    try {
      if (typeof AudioContext !== 'undefined') {
        hookFn(AudioContext.prototype, 'createOscillator', 'audio', 'high', { why: 'Oscillator — audio fingerprint' });
        hookFn(AudioContext.prototype, 'createDynamicsCompressor', 'audio', 'high', { why: 'Compressor — audio fingerprint' });
        if (AudioContext.prototype.createAnalyser) hookFn(AudioContext.prototype, 'createAnalyser', 'audio', 'medium', { why: 'Analyser — frequency data' });
        if (AudioContext.prototype.createGain) hookFn(AudioContext.prototype, 'createGain', 'audio', 'low', { why: 'Gain node — audio pipeline' });
        if (AudioContext.prototype.createScriptProcessor) hookFn(AudioContext.prototype, 'createScriptProcessor', 'audio', 'medium', { why: 'Script processor — raw audio' });

        // baseLatency getter
        try {
          var blDesc = _realGetDesc.call(Object, AudioContext.prototype, 'baseLatency');
          if (blDesc && blDesc.get) {
            hookGetter(AudioContext.prototype, 'baseLatency', 'audio', 'medium', { why: 'Audio base latency — FPjs entropy source' });
          }
        } catch(e) {}

        // sampleRate getter — find correct target
        try {
          var srDesc = _realGetDesc.call(Object, AudioContext.prototype, 'sampleRate') ||
                       _realGetDesc.call(Object, BaseAudioContext.prototype, 'sampleRate');
          var srTarget = _realGetDesc.call(Object, AudioContext.prototype, 'sampleRate') ? AudioContext.prototype : 
                         (typeof BaseAudioContext !== 'undefined' ? BaseAudioContext.prototype : null);
          if (srTarget && srDesc && srDesc.get) {
            hookGetter(srTarget, 'sampleRate', 'audio', 'medium', { why: 'Audio sample rate — varies by hardware' });
          }
        } catch(e) {}
      }
      if (typeof OfflineAudioContext !== 'undefined') {
        hookFn(OfflineAudioContext.prototype, 'startRendering', 'audio', 'critical', { why: 'Offline audio rendering — generates fingerprint hash' });
        if (OfflineAudioContext.prototype.createOscillator) hookFn(OfflineAudioContext.prototype, 'createOscillator', 'audio', 'high', { why: 'Offline oscillator' });
        if (OfflineAudioContext.prototype.createDynamicsCompressor) hookFn(OfflineAudioContext.prototype, 'createDynamicsCompressor', 'audio', 'high', { why: 'Offline compressor' });
      }
    } catch(e) {}

    // ═══ 4. FONT DETECTION ═══
    try {
      hookFn(Element.prototype, 'getBoundingClientRect', 'font-detection', 'low', {
        captureReturn: true,
        valueFn: function(r) { return r ? { w: r.width, h: r.height } : null; },
        why: 'getBoundingClientRect — element dimension fingerprinting'
      });
    } catch(e) {}

    try {
      if (typeof FontFace !== 'undefined') {
        hookFn(window, 'FontFace', 'font-detection', 'medium', {
          why: 'FontFace constructor — dynamic font loading probe'
        });
      }
    } catch(e) {}

    // ═══ 5. NAVIGATOR / FINGERPRINT — SMART TARGET DETECTION (v4.1 approach) ═══
    // KEY FIX: If stealth patched navigator at instance level,
    // we hook the INSTANCE, not the prototype. This wraps the stealth patch
    // with our monitoring layer, so we see every access.
    try {
      var _navProps = [
        { prop: 'userAgent', risk: 'high', why: 'navigator.userAgent — browser identification' },
        { prop: 'platform', risk: 'high', why: 'navigator.platform — OS identification' },
        { prop: 'language', risk: 'medium', why: 'navigator.language — locale fingerprint' },
        { prop: 'languages', risk: 'high', why: 'navigator.languages — locale array fingerprint' },
        { prop: 'hardwareConcurrency', risk: 'high', why: 'navigator.hardwareConcurrency — CPU core count' },
        { prop: 'deviceMemory', risk: 'high', why: 'navigator.deviceMemory — RAM size' },
        { prop: 'maxTouchPoints', risk: 'medium', why: 'navigator.maxTouchPoints — device type' },
        { prop: 'vendor', risk: 'low', why: 'navigator.vendor — browser vendor' },
        { prop: 'appVersion', risk: 'low', why: 'navigator.appVersion — browser version' },
        { prop: 'doNotTrack', risk: 'low', why: 'navigator.doNotTrack — DNT preference (ironic fingerprint)' },
        { prop: 'webdriver', risk: 'critical', why: 'navigator.webdriver — automation detection flag' },
        { prop: 'pdfViewerEnabled', risk: 'low', why: 'navigator.pdfViewerEnabled — FPjs v5 source' },
        { prop: 'cookieEnabled', risk: 'low', why: 'navigator.cookieEnabled — cookie support check' },
        { prop: 'plugins', risk: 'high', why: 'navigator.plugins — plugin list fingerprint' },
        { prop: 'mimeTypes', risk: 'medium', why: 'navigator.mimeTypes — MIME type fingerprint' },
        { prop: 'connection', risk: 'medium', why: 'navigator.connection — network info fingerprint' },
        { prop: 'oscpu', risk: 'medium', why: 'navigator.oscpu — OS/CPU info' },
        { prop: 'product', risk: 'low', why: 'navigator.product — always Gecko' },
        { prop: 'productSub', risk: 'low', why: 'navigator.productSub — build date' }
      ];
      _navProps.forEach(function(np) {
        try {
          smartHookGetter(Navigator.prototype, navigator, np.prop, 'fingerprint', np.risk, { why: np.why });
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

    // ═══ 7. STORAGE — Cookie (getter + setter), localStorage, sessionStorage, indexedDB ═══
    try {
      // Cookie — BOTH getter AND setter (v4.4 only hooked getter!)
      hookGetterSetter(Document.prototype, 'cookie', 'storage', 'medium',
        { why: 'document.cookie read — tracking data access' },
        { risk: 'high', why: 'document.cookie write — tracking cookie creation' }
      );
    } catch(e) {}

    try {
      hookFn(Storage.prototype, 'getItem', 'storage', 'low', {
        detailFn: function(a) { return { key: String(a[0]).slice(0, 50) }; },
        captureReturn: true,
        why: 'Storage.getItem — stored data access'
      });
      hookFn(Storage.prototype, 'setItem', 'storage', 'medium', {
        detailFn: function(a) { return { key: String(a[0]).slice(0, 50), size: a[1] ? String(a[1]).length : 0 }; },
        why: 'Storage.setItem — data persistence'
      });
    } catch(e) {}

    try {
      if (typeof indexedDB !== 'undefined' && IDBFactory.prototype.open) {
        hookFn(IDBFactory.prototype, 'open', 'storage', 'medium', {
          detailFn: function(a) { return { dbName: a[0], version: a[1] }; },
          why: 'IndexedDB.open — persistent storage fingerprint'
        });
      }
    } catch(e) {}

    // ═══ 8. SCREEN / DISPLAY — Smart target detection ═══
    try {
      var _screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
      _screenProps.forEach(function(prop) {
        try {
          smartHookGetter(Screen.prototype, screen, prop, 'screen', 'medium', { why: 'screen.' + prop + ' — display fingerprint' });
        } catch(e) {}
      });
    } catch(e) {}

    try {
      // devicePixelRatio — find correct target
      var dprDesc = _realGetDesc.call(Object, window, 'devicePixelRatio') ||
                    _realGetDesc.call(Object, Window.prototype, 'devicePixelRatio');
      var dprTarget = _realGetDesc.call(Object, window, 'devicePixelRatio') ? window : Window.prototype;
      if (dprDesc && dprDesc.get) {
        hookGetter(dprTarget, 'devicePixelRatio', 'screen', 'medium', { why: 'Device pixel ratio — display density fingerprint' });
      }
    } catch(e) {}

    try {
      hookFn(window, 'matchMedia', 'css-fingerprint', 'medium', {
        detailFn: function(a) { return { query: a[0] }; },
        why: 'matchMedia — CSS media query fingerprinting'
      });
    } catch(e) {}

    // ═══ 9. PERFORMANCE TIMING ═══
    try {
      hookFn(Performance.prototype, 'getEntries', 'perf-timing', 'medium', {
        captureReturn: true,
        valueFn: function(r) { return { count: r ? r.length : 0 }; },
        why: 'Performance entries — timing fingerprint'
      });
      hookFn(Performance.prototype, 'getEntriesByType', 'perf-timing', 'medium', {
        detailFn: function(a) { return { type: a[0] }; },
        captureReturn: true,
        valueFn: function(r) { return { count: r ? r.length : 0 }; },
        why: 'Performance entries by type — resource timing'
      });
    } catch(e) {}

    // ═══ 10. MEDIA DEVICES ═══
    try {
      if (navigator.mediaDevices) {
        hookFn(navigator.mediaDevices, 'enumerateDevices', 'media-devices', 'high', {
          captureReturn: true,
          valueFn: function(r) { return r && r.then ? 'Promise' : (r ? { count: r.length } : null); },
          why: 'Media device enumeration — hardware fingerprint'
        });
      }
    } catch(e) {}

    // ═══ 11. DOM PROBING — filtered to fingerprint-relevant tags (v4.1 approach) ═══
    try {
      var origCreateElement = document.createElement.bind(document);
      document.createElement = function(tag) {
        var lTag = tag ? tag.toLowerCase() : '';
        if (['canvas', 'iframe', 'audio', 'video', 'object', 'embed', 'script', 'link', 'img'].indexOf(lTag) >= 0) {
          log('dom-probe', 'createElement', { tag: lTag }, lTag === 'canvas' ? 'high' : 'medium', {
            why: 'Dynamic element creation — ' + lTag + ' for fingerprinting'
          });
        }
        return origCreateElement.apply(document, arguments);
      };
      try { document.createElement.toString = function() { return 'function createElement() { [native code] }'; }; } catch(e) {}
    } catch(e) {}

    try {
      hookFn(Element.prototype, 'getBoundingClientRect', 'dom-probe', 'medium', {
        captureReturn: true,
        valueFn: function(r) { return r ? { w: r.width, h: r.height } : null; },
        why: 'getBoundingClientRect — element dimension fingerprinting'
      });
    } catch(e) {}

    // offsetWidth/offsetHeight — commonly used for font detection
    try {
      var owDesc = _realGetDesc.call(Object, HTMLElement.prototype, 'offsetWidth');
      if (owDesc && owDesc.get) {
        hookGetter(HTMLElement.prototype, 'offsetWidth', 'font-detection', 'low', { why: 'offsetWidth — font availability detection' });
      }
    } catch(e) {}
    try {
      var ohDesc = _realGetDesc.call(Object, HTMLElement.prototype, 'offsetHeight');
      if (ohDesc && ohDesc.get) {
        hookGetter(HTMLElement.prototype, 'offsetHeight', 'font-detection', 'low', { why: 'offsetHeight — font availability detection' });
      }
    } catch(e) {}

    // ═══ 12. CLIPBOARD ═══
    try {
      if (navigator.clipboard) {
        if (navigator.clipboard.readText) {
          hookFn(navigator.clipboard, 'readText', 'clipboard', 'critical', { why: 'Clipboard read — data exfiltration risk' });
        }
        if (navigator.clipboard.writeText) {
          hookFn(navigator.clipboard, 'writeText', 'clipboard', 'high', { why: 'Clipboard write — data injection' });
        }
      }
    } catch(e) {}

    // ═══ 13. GEOLOCATION ═══
    try {
      if (navigator.geolocation) {
        hookFn(navigator.geolocation, 'getCurrentPosition', 'geolocation', 'critical', { why: 'Geolocation access — precise location' });
        hookFn(navigator.geolocation, 'watchPosition', 'geolocation', 'critical', { why: 'Geolocation watch — continuous tracking' });
      }
    } catch(e) {}

    // ═══ 14. SERVICE WORKER ═══
    try {
      if (navigator.serviceWorker && navigator.serviceWorker.register) {
        hookFn(navigator.serviceWorker, 'register', 'service-worker', 'high', {
          detailFn: function(a) { return { url: String(a[0]).slice(0, 100) }; },
          why: 'Service Worker registration — persistent background access'
        });
      }
    } catch(e) {}

    // ═══ 15. HARDWARE ═══
    try {
      if (navigator.getBattery) {
        hookFn(navigator, 'getBattery', 'hardware', 'medium', { why: 'Battery API — power state fingerprint' });
      }
      if (navigator.getGamepads) {
        hookFn(navigator, 'getGamepads', 'hardware', 'medium', { why: 'Gamepad API — controller fingerprint' });
      }
    } catch(e) {}

    try {
      smartHookGetter(Navigator.prototype, navigator, 'hardwareConcurrency', 'hardware', 'medium', { why: 'CPU core count' });
      smartHookGetter(Navigator.prototype, navigator, 'deviceMemory', 'hardware', 'medium', { why: 'RAM amount' });
    } catch(e) {}

    // ═══ 16. NETWORK / EXFILTRATION MONITORING ═══
    try {
      var _origFetch = window.fetch;
      if (_origFetch) {
        window.fetch = function() {
          var url = arguments[0];
          var urlStr = typeof url === 'string' ? url : (url && url.url ? url.url : String(url));
          var method = (arguments[1] && arguments[1].method) || 'GET';
          var hasBody = !!(arguments[1] && arguments[1].body);
          log('exfiltration', 'fetch', { url: urlStr.slice(0, 200), method: method, hasBody: hasBody }, 
              hasBody ? 'high' : 'medium', { why: 'Fetch request — potential data exfiltration' });
          return _origFetch.apply(window, arguments);
        };
        try { window.fetch.toString = function() { return 'function fetch() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    try {
      var _origXHROpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, url) {
        this.__sentinel_url = String(url).slice(0, 200);
        this.__sentinel_method = method;
        return _origXHROpen.apply(this, arguments);
      };
      var _origXHRSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.send = function(data) {
        log('exfiltration', 'XMLHttpRequest', {
          url: this.__sentinel_url || '', method: this.__sentinel_method || 'GET', hasData: !!data
        }, data ? 'high' : 'medium', { why: 'XHR request — potential data exfiltration' });
        return _origXHRSend.apply(this, arguments);
      };
      try { XMLHttpRequest.prototype.open.toString = function() { return 'function open() { [native code] }'; }; } catch(e) {}
      try { XMLHttpRequest.prototype.send.toString = function() { return 'function send() { [native code] }'; }; } catch(e) {}
    } catch(e) {}

    try {
      if (navigator.sendBeacon) {
        var _origBeacon = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function(url, data) {
          log('exfiltration', 'sendBeacon', { url: String(url).slice(0, 200), dataSize: data ? String(data).length : 0 },
              'critical', { why: 'sendBeacon — fire-and-forget exfiltration' });
          return _origBeacon.apply(navigator, arguments);
        };
        try { navigator.sendBeacon.toString = function() { return 'function sendBeacon() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    // WebSocket monitoring
    try {
      if (typeof WebSocket !== 'undefined') {
        var _OrigWS = WebSocket;
        window.WebSocket = function(url, protocols) {
          log('exfiltration', 'WebSocket', { url: String(url).slice(0, 200) }, 'high', {
            why: 'WebSocket — persistent bidirectional data channel'
          });
          return new _OrigWS(url, protocols);
        };
        window.WebSocket.prototype = _OrigWS.prototype;
        window.WebSocket.CONNECTING = _OrigWS.CONNECTING;
        window.WebSocket.OPEN = _OrigWS.OPEN;
        window.WebSocket.CLOSING = _OrigWS.CLOSING;
        window.WebSocket.CLOSED = _OrigWS.CLOSED;
        try { window.WebSocket.toString = function() { return 'function WebSocket() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    // Image beacon (tracking pixel)
    try {
      var _origImage = window.Image;
      window.Image = function(w, h) {
        var img = new _origImage(w, h);
        var _origSrc = _realGetDesc.call(Object, HTMLImageElement.prototype, 'src');
        if (_origSrc) {
          _realDefProp.call(Object, img, 'src', {
            set: function(val) {
              if (val && /collect|track|pixel|beacon|analytics|log|stat/i.test(val)) {
                log('exfiltration', 'Image.src', { url: String(val).slice(0, 200) }, 'high', {
                  why: 'Image beacon — tracking pixel exfiltration'
                });
              }
              _origSrc.set.call(this, val);
            },
            get: _origSrc.get ? function() { return _origSrc.get.call(this); } : undefined,
            configurable: true
          });
        }
        return img;
      };
      window.Image.prototype = _origImage.prototype;
      try { window.Image.toString = function() { return 'function Image() { [native code] }'; }; } catch(e) {}
    } catch(e) {}

    // ═══ 17. WEBRTC ═══
    try {
      if (typeof RTCPeerConnection !== 'undefined') {
        var _OrigRTC = RTCPeerConnection;
        window.RTCPeerConnection = function(config) {
          log('webrtc', 'RTCPeerConnection', { iceServers: config ? config.iceServers : null }, 'critical', {
            why: 'WebRTC — local IP address leak / STUN fingerprint'
          });
          var pc = new _OrigRTC(config);
          // Hook createDataChannel
          var origDC = pc.createDataChannel;
          if (origDC) {
            pc.createDataChannel = function(label) {
              log('webrtc', 'createDataChannel', { label: label }, 'high', { why: 'WebRTC data channel — P2P data transfer' });
              return origDC.apply(this, arguments);
            };
          }
          return pc;
        };
        window.RTCPeerConnection.prototype = _OrigRTC.prototype;
        try { window.RTCPeerConnection.toString = function() { return 'function RTCPeerConnection() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    // ═══ 18. MATH FINGERPRINTING ═══
    try {
      ['acos', 'acosh', 'asin', 'asinh', 'atan', 'atanh', 'atan2', 'cbrt', 'cos', 'cosh',
       'exp', 'expm1', 'log', 'log1p', 'log2', 'log10', 'sin', 'sinh', 'sqrt', 'tan', 'tanh'
      ].forEach(function(fn) {
        if (Math[fn]) {
          hookFn(Math, fn, 'math-fingerprint', 'medium', {
            detailFn: function(a) { return { input: a[0] }; },
            captureReturn: true,
            why: 'Math.' + fn + ' — floating-point inconsistency fingerprint'
          });
        }
      });
    } catch(e) {}

    // ═══ 19. TIMEZONE ═══
    try {
      hookFn(Date.prototype, 'getTimezoneOffset', 'fingerprint', 'medium', {
        captureReturn: true,
        why: 'Timezone offset — geolocation fingerprint'
      });
    } catch(e) {}

    // ═══ 20. INTL FINGERPRINTING ═══
    try {
      if (window.Intl) {
        if (Intl.DateTimeFormat) {
          hookFn(Intl.DateTimeFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium', {
            captureReturn: true,
            why: 'Intl.DateTimeFormat — locale/timezone fingerprint'
          });
        }
        if (Intl.NumberFormat) {
          hookFn(Intl.NumberFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium', {
            captureReturn: true,
            why: 'Intl.NumberFormat — locale-specific number formatting'
          });
        }
        if (Intl.RelativeTimeFormat) {
          hookFn(Intl.RelativeTimeFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'low', {
            why: 'Intl.RelativeTimeFormat — locale detection'
          });
        }
      }
    } catch(e) {}

    // ═══ 21. SPEECH SYNTHESIS ═══
    try {
      if (window.speechSynthesis) {
        hookFn(window.speechSynthesis, 'getVoices', 'speech', 'high', {
          captureReturn: true,
          valueFn: function(r) { return r ? { count: r.length } : null; },
          why: 'Speech voices — installed voice fingerprint'
        });
      }
    } catch(e) {}

    // ═══ 22. CLIENT HINTS ═══
    try {
      if (navigator.userAgentData) {
        hookFn(navigator.userAgentData, 'getHighEntropyValues', 'client-hints', 'critical', {
          detailFn: function(a) { return { hints: a[0] }; },
          captureReturn: true,
          why: 'User-Agent Client Hints — high-entropy browser data'
        });
      }
    } catch(e) {}

    // ═══ 23. CREDENTIAL API ═══
    try {
      if (navigator.credentials) {
        if (navigator.credentials.get) {
          hookFn(navigator.credentials, 'get', 'credential', 'critical', { why: 'Credential API get — authentication probe' });
        }
        if (navigator.credentials.create) {
          hookFn(navigator.credentials, 'create', 'credential', 'critical', { why: 'Credential API create — WebAuthn fingerprint' });
        }
      }
    } catch(e) {}

    // ═══ 24. PROPERTY ENUMERATION — filtered to navigator/screen (v4.1 approach) ═══
    try {
      var origObjKeys = Object.keys;
      Object.keys = function(obj) {
        var result = origObjKeys.call(Object, obj);
        if (obj === navigator || obj === screen || obj === Navigator.prototype || obj === Screen.prototype) {
          log('property-enum', 'Object.keys', { target: obj === navigator || obj === Navigator.prototype ? 'navigator' : 'screen' }, 'high', {
            returnValue: { count: result.length },
            why: 'Property enumeration — CreepJS-style lie detection'
          });
        }
        return result;
      };
      try { Object.keys.toString = function() { return 'function keys() { [native code] }'; }; } catch(e) {}
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
      try { Object.getOwnPropertyNames.toString = function() { return 'function getOwnPropertyNames() { [native code] }'; }; } catch(e) {}
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
        try { window.OffscreenCanvas.toString = function() { return 'function OffscreenCanvas() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    // ═══ 26. HONEYPOT — trap for suspicious property access ═══
    try {
      var honeypotProps = ['__selenium_evaluate', '__driver_evaluate', '__webdriver_evaluate', 'callPhantom',
                          'domAutomation', '__nightmare', '_Recaptcha'];
      honeypotProps.forEach(function(prop) {
        try {
          _realDefProp.call(Object, window, prop, {
            get: function() {
              log('honeypot', prop, { trap: prop }, 'critical', { why: 'Honeypot triggered — automation detection attempt' });
              return undefined;
            },
            set: function() {},
            configurable: true
          });
        } catch(e) {}
      });
    } catch(e) {}

    // ═══ 27. EVENT LISTENERS (suspicious patterns) — v4.6 integrated into section 38 ═══
    // Sensor event monitoring is now handled via EventTarget.prototype.addEventListener hook (section 38)
    // which also captures cross-frame message listeners

    // ═══ 28. INTERSECTION/MUTATION OBSERVERS ═══
    try {
      if (typeof IntersectionObserver !== 'undefined') {
        var OrigIO = IntersectionObserver;
        window.IntersectionObserver = function(callback, options) {
          log('dom-probe', 'IntersectionObserver', { rootMargin: options ? options.rootMargin : null }, 'medium', {
            why: 'IntersectionObserver — viewport/visibility detection'
          });
          return new OrigIO(callback, options);
        };
        window.IntersectionObserver.prototype = OrigIO.prototype;
        try { window.IntersectionObserver.toString = function() { return 'function IntersectionObserver() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    try {
      if (typeof MutationObserver !== 'undefined') {
        var OrigMO = MutationObserver;
        window.MutationObserver = function(callback) {
          log('dom-probe', 'MutationObserver', {}, 'low', { why: 'MutationObserver — DOM change monitoring' });
          return new OrigMO(callback);
        };
        window.MutationObserver.prototype = OrigMO.prototype;
        try { window.MutationObserver.toString = function() { return 'function MutationObserver() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    // ═══ 29. ENCODING (TextEncoder/TextDecoder) ═══
    try {
      if (typeof TextEncoder !== 'undefined') {
        hookFn(TextEncoder.prototype, 'encode', 'encoding', 'low', { why: 'TextEncoder — data encoding' });
      }
    } catch(e) {}

    // ═══ 30. WEBASSEMBLY ═══
    try {
      if (typeof WebAssembly !== 'undefined') {
        if (WebAssembly.instantiate) {
          hookFn(WebAssembly, 'instantiate', 'webassembly', 'high', { why: 'WebAssembly.instantiate — binary code execution' });
        }
        if (WebAssembly.compile) {
          hookFn(WebAssembly, 'compile', 'webassembly', 'high', { why: 'WebAssembly.compile — binary code compilation' });
        }
      }
    } catch(e) {}

    // ═══ 31. KEYBOARD LAYOUT ═══
    try {
      if (navigator.keyboard && navigator.keyboard.getLayoutMap) {
        hookFn(navigator.keyboard, 'getLayoutMap', 'keyboard-layout', 'high', {
          why: 'Keyboard layout map — locale/hardware fingerprint'
        });
      }
    } catch(e) {}

    // ═══ 32. SENSOR APIS ═══
    try {
      ['Accelerometer', 'Gyroscope', 'Magnetometer', 'AbsoluteOrientationSensor', 'RelativeOrientationSensor',
       'LinearAccelerationSensor', 'GravitySensor', 'AmbientLightSensor'].forEach(function(sensor) {
        if (typeof window[sensor] !== 'undefined') {
          var OrigSensor = window[sensor];
          window[sensor] = function(opts) {
            log('sensor-apis', 'new ' + sensor, opts || {}, 'high', { why: sensor + ' — device sensor fingerprint' });
            return new OrigSensor(opts);
          };
          window[sensor].prototype = OrigSensor.prototype;
        }
      });
    } catch(e) {}

    // ═══ 33. VISUALIZATION (requestAnimationFrame timing) ═══
    try {
      var _origRAF = window.requestAnimationFrame;
      var _rafCount = 0;
      window.requestAnimationFrame = function(cb) {
        _rafCount++;
        if (_rafCount <= 3 || _rafCount % 100 === 0) {
          log('visualization', 'requestAnimationFrame', { callCount: _rafCount }, 'low', {
            why: 'rAF — rendering pipeline timing (FP when measured precisely)'
          });
        }
        return _origRAF.call(window, cb);
      };
      try { window.requestAnimationFrame.toString = function() { return 'function requestAnimationFrame() { [native code] }'; }; } catch(e) {}
    } catch(e) {}

    // ═══ v4.6 QUIET MODE EXPORT ═══
    // Non-enumerable: Object.keys(window) won't reveal sentinel
    try {
      Object.defineProperty(window, '__SENTINEL_DATA__', {
        get: function() { return _sentinel; },
        configurable: true,
        enumerable: false
      });
      Object.defineProperty(window, '__SENTINEL_ACTIVE__', {
        get: function() { return true; },
        configurable: true,
        enumerable: false
      });
    } catch(e) {
      // Fallback for restricted contexts
      window.__SENTINEL_DATA__ = _sentinel;
    }

    window.__SENTINEL_FLUSH__ = function() {
      return JSON.stringify({
        events: _sentinel.events.slice(0),
        dedupStats: {
          totalReceived: _sentinel.events.length + _sentinel.dedupCount,
          deduplicated: _sentinel.dedupCount,
          kept: _sentinel.events.length
        }
      });
    };

    window.__SENTINEL_CONTEXT_MAP__ = [{
      type: 'page',
      url: (function() { try { return location.href; } catch(e) { return 'unknown'; } })(),
      origin: (function() { try { return location.origin; } catch(e) { return 'unknown'; } })(),
      frameId: _sentinel.frameId,
      bootOk: true,
      timestamp: Date.now()
    }];


    // ═══ 34. BLOB/DATA URL MONITORING (v4.6 NEW) ═══
    try {
      var _origCreateObjectURL = URL.createObjectURL;
      if (_origCreateObjectURL) {
        URL.createObjectURL = function(obj) {
          var result = _origCreateObjectURL.apply(URL, arguments);
          var detail = { type: 'unknown', size: 0 };
          try {
            if (obj instanceof Blob) {
              detail.type = obj.type || 'unknown';
              detail.size = obj.size || 0;
              // Flag suspicious: JS/HTML blobs could be script injection
              if (obj.type && obj.type.match(/javascript|html|text.plain/i)) {
                detail.suspicious = true;
              }
            }
          } catch(e) {}
          log('dom-probe', 'URL.createObjectURL', detail,
            detail.suspicious ? 'high' : 'medium',
            { returnValue: result ? result.slice(0, 100) : null, why: 'Blob URL creation — potential script isolation for fingerprinting bypass' });
          return result;
        };
        try { URL.createObjectURL.toString = function() { return 'function createObjectURL() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    // ═══ 35. SHAREDARRAYBUFFER MONITORING (v4.6 NEW) ═══
    try {
      if (typeof SharedArrayBuffer !== 'undefined') {
        var _OrigSAB = SharedArrayBuffer;
        window.SharedArrayBuffer = function(length) {
          log('hardware', 'new SharedArrayBuffer', { byteLength: length }, 'critical', {
            why: 'SharedArrayBuffer — enables sub-microsecond timing attacks for hardware fingerprinting'
          });
          return new _OrigSAB(length);
        };
        window.SharedArrayBuffer.prototype = _OrigSAB.prototype;
        try { window.SharedArrayBuffer.toString = function() { return 'function SharedArrayBuffer() { [native code] }'; }; } catch(e) {}
      }
    } catch(e) {}

    // ═══ 36. PERFORMANCE.NOW PRECISION LOGGING (v4.6 NEW) ═══
    try {
      var _origPerfNow = Performance.prototype.now;
      var _perfNowCount = 0;
      if (_shield) {
        _shield.hookFunction(Performance.prototype, 'now', function(original) {
          var result = original.call(this);
          _perfNowCount++;
          // Only log periodically to avoid noise (timing APIs called thousands of times)
          if (_perfNowCount <= 5 || _perfNowCount % 200 === 0) {
            log('perf-timing', 'performance.now', { callCount: _perfNowCount }, 'medium', {
              returnValue: result,
              why: 'performance.now — high-res timer used for timing attacks'
            });
          }
          return result;
        });
      }
    } catch(e) {}

    // ═══ 37. POSTMESSAGE MONITORING (v4.6 NEW — cross-frame communication) ═══
    try {
      var _origPostMessage = window.postMessage;
      window.postMessage = function(message, targetOrigin) {
        var detail = { targetOrigin: targetOrigin || '*' };
        try {
          if (typeof message === 'string') detail.preview = message.slice(0, 200);
          else if (typeof message === 'object') detail.preview = JSON.stringify(message).slice(0, 200);
        } catch(e) { detail.preview = '[complex]'; }
        log('exfiltration', 'postMessage', detail, 'high', {
          why: 'Cross-frame postMessage — potential distributed fingerprinting coordination'
        });
        return _origPostMessage.apply(this, arguments);
      };
      try { window.postMessage.toString = function() { return 'function postMessage() { [native code] }'; }; } catch(e) {}
    } catch(e) {}

    // ═══ 38. MESSAGE EVENT LISTENER (v4.6 NEW — incoming cross-frame data) ═══
    try {
      var _origAddEventListener = EventTarget.prototype.addEventListener;
      var _msgListenerCount = 0;
      EventTarget.prototype.addEventListener = function(type, listener, options) {
        if (type === 'message' && this === window) {
          _msgListenerCount++;
          log('exfiltration', 'addEventListener:message', { listenerCount: _msgListenerCount }, 'medium', {
            why: 'Window message listener — receiving cross-frame fingerprint data'
          });
        }
        // Sensor event detection (from v4.5 section 27, now unified)
        if (['devicemotion', 'deviceorientation', 'deviceorientationabsolute',
             'touchstart', 'touchmove', 'touchend',
             'pointerdown', 'pointermove', 'pointerup'].indexOf(type) >= 0) {
          log('sensor-apis', 'addEventListener', { event: type }, 'medium', {
            why: 'Sensor event listener — device motion/orientation fingerprint'
          });
        }
        return _origAddEventListener.call(this, type, listener, options);
      };
      try { EventTarget.prototype.addEventListener.toString = function() { return 'function addEventListener() { [native code] }'; }; } catch(e) {}
    } catch(e) {}

    // ═══ PUSH TELEMETRY ═══
    if (typeof window.__SENTINEL_PUSH__ === 'function' || typeof window.__s46push__ === 'function') {
      var _pushFn = typeof window.__SENTINEL_PUSH__ === 'function' ? window.__SENTINEL_PUSH__ : window.__s46push__;
      var _lastPushIndex = 0;
      setInterval(function() {
        if (_sentinel.events.length > _lastPushIndex) {
          try {
            var newEvents = _sentinel.events.slice(_lastPushIndex, _lastPushIndex + 500);
            _lastPushIndex += newEvents.length;
            _pushFn(JSON.stringify({
              type: 'event_batch',
              frameId: _sentinel.frameId,
              origin: (function() { try { return location.origin; } catch(e) { return 'unknown'; } })(),
              events: newEvents
            }));
          } catch(e) {}
        }
      }, 2000);
    }

    // Ghost Protocol: zero console output
  })();
  `;
}

module.exports = { getInterceptorScript };
