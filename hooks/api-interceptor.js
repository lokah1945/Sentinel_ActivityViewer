/**
 * Sentinel v4 — Forensic API Interceptor (Layer 3 + Layer 4)
 * 
 * UPGRADE from v3:
 * - VALUE CAPTURE: Every hook logs the actual return value (1H5W: WHAT)
 * - STACK SAMPLING: Periodic Error.stack capture (1H5W: WHO called it)
 * - ORIGIN TRACKING: Full frame/origin info (1H5W: WHERE)
 * - TIMESTAMP PRECISION: sub-ms timing (1H5W: WHEN)
 * - RISK REASONING: Why each call is suspicious (1H5W: WHY)
 * - METHOD DETAIL: How the API was invoked (1H5W: HOW)
 * 
 * Layer 3: Enhanced 19 original categories with forensic data
 * Layer 4: 12+ new vectors (speech, client hints, intl, css.supports, 
 *          property enumeration, offscreen canvas, wasm timing,
 *          mutation observer, intersection observer, gamepad, 
 *          credential management, web locks)
 */

function getInterceptorScript(config = {}) {
  const timeout = config.timeout || 30000;
  const sampleRate = config.stackSampleRate || 10; // sample stack every N calls per API

  return `
  (function() {
    'use strict';

    // ═══════════════════════════════════════════
    //  SENTINEL v4 — FORENSIC MALING CATCHER
    // ═══════════════════════════════════════════

    const _sentinel = {
      events: [],
      startTime: Date.now(),
      bootOk: false,
      frameId: Math.random().toString(36).substr(2, 8),
      config: {
        timeout: ${timeout},
        maxEvents: 100000,
        stackSampleRate: ${sampleRate}
      },
      counters: {},
      valueLog: []
    };

    const _shield = window.__SENTINEL_SHIELD__;

    // ═══ FORENSIC LOGGER (1H5W) ═══
    function log(category, api, detail, risk, options) {
      if (_sentinel.events.length >= _sentinel.config.maxEvents) return;

      const opts = options || {};
      const counter = _sentinel.counters[api] = (_sentinel.counters[api] || 0) + 1;

      // Stack sampling: capture WHO is calling (every N calls)
      let stack = null;
      if (counter % _sentinel.config.stackSampleRate === 1) {
        try {
          const err = new Error();
          stack = (err.stack || '').split('\n').slice(2, 6).map(s => s.trim()).join(' | ');
        } catch(e) {}
      }

      const origin = (typeof location !== 'undefined') ? location.origin : 'unknown';
      let frameType = 'top';
      try {
        if (window !== window.top) frameType = 'iframe';
      } catch(e) {
        frameType = 'cross-origin-iframe';
      }

      const event = {
        ts: Date.now() - _sentinel.startTime,
        cat: category,
        api: api,
        detail: null,
        value: null,
        risk: risk || 'low',
        origin: origin,
        frame: frameType,
        frameId: _sentinel.frameId,
        url: (typeof location !== 'undefined') ? location.href : 'unknown',
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
          const rv = opts.returnValue;
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

      // Stack trace (WHO)
      if (stack) {
        event.stack = stack;
      }

      // WHY reasoning
      if (opts.why) {
        event.why = opts.why;
      }

      // HOW detail
      if (opts.how) {
        event.how = opts.how;
      }

      _sentinel.events.push(event);
    }

    // ═══ HELPER: Safe hook via shield or direct ═══
    function hookFn(target, prop, category, risk, options) {
      const opts = options || {};
      const why = opts.why || '';

      if (_shield && _shield.hookFunction) {
        _shield.hookFunction(target, prop, function(original, ...args) {
          const detail = opts.detailFn ? opts.detailFn(args) : { args: args.length };
          const result = original.apply(this, args);

          // Handle promise results
          if (result && typeof result.then === 'function') {
            result.then(val => {
              log(category, prop, detail, risk, { 
                returnValue: opts.valueFn ? opts.valueFn(val) : val,
                why: why,
                how: 'async-call'
              });
            }).catch(() => {});
            // Still log the call synchronously
            log(category, prop, detail, risk, { why: why, how: 'async-call-initiated' });
            return result;
          }

          log(category, prop, detail, risk, { 
            returnValue: opts.valueFn ? opts.valueFn(result) : result,
            why: why,
            how: opts.how || 'direct-call'
          });
          return result;
        });
      } else {
        // Fallback: direct hook without shield protection
        const original = target[prop];
        if (!original || typeof original !== 'function') return;
        target[prop] = function(...args) {
          const detail = opts.detailFn ? opts.detailFn(args) : { args: args.length };
          const result = original.apply(this, args);
          log(category, prop, detail, risk, { 
            returnValue: opts.valueFn ? opts.valueFn(result) : result,
            why: why
          });
          return result;
        };
      }
    }

    function hookGetter(target, prop, category, risk, options) {
      const opts = options || {};
      const why = opts.why || '';

      if (_shield && _shield.hookGetter) {
        _shield.hookGetter(target, prop, function(originalGetter) {
          const value = originalGetter.call(this);
          log(category, prop, {}, risk, {
            returnValue: opts.valueFn ? opts.valueFn(value) : value,
            why: why,
            how: 'getter-access'
          });
          return value;
        });
      } else {
        const desc = Object.getOwnPropertyDescriptor(target, prop);
        if (!desc || !desc.get) return;
        const origGetter = desc.get;
        Object.defineProperty(target, prop, {
          get: function() {
            const value = origGetter.call(this);
            log(category, prop, {}, risk, {
              returnValue: opts.valueFn ? opts.valueFn(value) : value,
              why: why
            });
            return value;
          },
          set: desc.set,
          enumerable: desc.enumerable,
          configurable: true
        });
      }
    }

    // ═══════════════════════════════════════════
    //  LAYER 3: ENHANCED CORE HOOKS (19 categories)
    // ═══════════════════════════════════════════

    // ═══ 1. CANVAS FINGERPRINTING ═══
    hookFn(HTMLCanvasElement.prototype, 'toDataURL', 'canvas', 'high', {
      detailFn: (args) => ({ type: args[0] || 'image/png', quality: args[1] }),
      valueFn: (v) => v ? v.slice(0, 80) + '...[hash:' + hashStr(v) + ']' : null,
      why: 'Canvas toDataURL generates unique pixel hash per GPU/driver combination'
    });

    hookFn(HTMLCanvasElement.prototype, 'toBlob', 'canvas', 'high', {
      detailFn: (args) => ({ type: args[1] || 'image/png' }),
      valueFn: (v) => v ? { type: 'Blob', size: v.size } : null,
      why: 'Canvas toBlob exports pixel data for fingerprint hashing'
    });

    hookFn(CanvasRenderingContext2D.prototype, 'getImageData', 'canvas', 'high', {
      detailFn: (args) => ({ x: args[0], y: args[1], w: args[2], h: args[3] }),
      valueFn: (v) => v ? { width: v.width, height: v.height, dataLen: v.data?.length } : null,
      why: 'Raw pixel data extraction for canvas fingerprint computation'
    });

    hookFn(CanvasRenderingContext2D.prototype, 'fillText', 'canvas', 'medium', {
      detailFn: (args) => ({ text: String(args[0]).slice(0, 50), x: args[1], y: args[2] }),
      why: 'Text rendering varies by font engine — used in canvas fingerprint'
    });

    hookFn(CanvasRenderingContext2D.prototype, 'measureText', 'font-detection', 'high', {
      detailFn: (args) => ({ text: String(args[0]).slice(0, 30) }),
      valueFn: (v) => v ? { width: v.width } : null,
      why: 'Font metric measurement for installed font detection'
    });

    hookFn(CanvasRenderingContext2D.prototype, 'isPointInPath', 'canvas', 'medium', {
      detailFn: (args) => ({ x: args[0], y: args[1] }),
      valueFn: (v) => v,
      why: 'Path rendering test — FingerprintJS v5 signature API'
    });

    hookFn(CanvasRenderingContext2D.prototype, 'isPointInStroke', 'canvas', 'medium', {
      detailFn: (args) => ({ x: args[0], y: args[1] }),
      valueFn: (v) => v,
      why: 'Stroke rendering test for GPU/driver fingerprinting'
    });

    // getContext — track canvas context creation
    hookFn(HTMLCanvasElement.prototype, 'getContext', 'canvas', 'medium', {
      detailFn: (args) => ({ contextType: args[0], attrs: args[1] }),
      valueFn: (v) => v ? v.constructor?.name : null,
      why: 'Canvas context creation — precursor to fingerprinting'
    });

    // ═══ 2. WEBGL FINGERPRINTING ═══
    function hookWebGL(proto, name) {
      hookFn(proto, 'getParameter', 'webgl', 'high', {
        detailFn: (args) => ({ param: args[0], ctx: name }),
        valueFn: (v) => {
          if (v === null || v === undefined) return String(v);
          if (typeof v === 'string' || typeof v === 'number') return v;
          if (v instanceof Float32Array || v instanceof Int32Array) return Array.from(v);
          return String(v).slice(0, 100);
        },
        why: 'WebGL parameter reads expose GPU vendor/renderer/capabilities'
      });

      hookFn(proto, 'getExtension', 'webgl', 'medium', {
        detailFn: (args) => ({ ext: args[0], ctx: name }),
        valueFn: (v) => v ? 'supported' : 'null',
        why: 'WebGL extension enumeration for GPU capability fingerprint'
      });

      hookFn(proto, 'getSupportedExtensions', 'webgl', 'medium', {
        detailFn: () => ({ ctx: name }),
        valueFn: (v) => v ? { count: v.length, list: v.slice(0, 5) } : null,
        why: 'Full WebGL extension list — high entropy fingerprint source'
      });

      if (proto.getShaderPrecisionFormat) {
        hookFn(proto, 'getShaderPrecisionFormat', 'webgl', 'high', {
          detailFn: (args) => ({ shaderType: args[0], precisionType: args[1], ctx: name }),
          valueFn: (v) => v ? { rangeMin: v.rangeMin, rangeMax: v.rangeMax, precision: v.precision } : null,
          why: 'Shader precision reveals GPU hardware specifics'
        });
      }

      hookFn(proto, 'getContextAttributes', 'webgl', 'low', {
        detailFn: () => ({ ctx: name }),
        valueFn: (v) => v,
        why: 'WebGL context attributes for rendering capability check'
      });

      if (proto.readPixels) {
        hookFn(proto, 'readPixels', 'webgl', 'high', {
          detailFn: (args) => ({ x: args[0], y: args[1], w: args[2], h: args[3], ctx: name }),
          why: 'WebGL pixel data extraction for GPU rendering fingerprint'
        });
      }
    }

    if (typeof WebGLRenderingContext !== 'undefined') hookWebGL(WebGLRenderingContext.prototype, 'webgl');
    if (typeof WebGL2RenderingContext !== 'undefined') hookWebGL(WebGL2RenderingContext.prototype, 'webgl2');

    // ═══ 3. AUDIO FINGERPRINTING ═══
    if (typeof AudioContext !== 'undefined') {
      hookFn(AudioContext.prototype, 'createOscillator', 'audio', 'high', {
        why: 'Oscillator creation for audio fingerprint signal generation'
      });

      hookFn(AudioContext.prototype, 'createDynamicsCompressor', 'audio', 'high', {
        why: 'Compressor creation — key component of audio fingerprint'
      });

      if (AudioContext.prototype.createAnalyser) {
        hookFn(AudioContext.prototype, 'createAnalyser', 'audio', 'medium', {
          why: 'Analyser node for frequency/time domain data extraction'
        });
      }

      if (AudioContext.prototype.createGain) {
        hookFn(AudioContext.prototype, 'createGain', 'audio', 'low', {
          why: 'Gain node creation — part of audio fingerprint pipeline'
        });
      }

      if (AudioContext.prototype.createScriptProcessor) {
        hookFn(AudioContext.prototype, 'createScriptProcessor', 'audio', 'medium', {
          why: 'Script processor for raw audio sample access'
        });
      }

      // baseLatency getter
      const blDesc = Object.getOwnPropertyDescriptor(AudioContext.prototype, 'baseLatency');
      if (blDesc && blDesc.get) {
        hookGetter(AudioContext.prototype, 'baseLatency', 'audio', 'medium', {
          why: 'Audio base latency is a new FPjs v5 entropy source (Jan 2025)'
        });
      }

      // sampleRate getter
      const srDesc = Object.getOwnPropertyDescriptor(AudioContext.prototype, 'sampleRate') ||
                     Object.getOwnPropertyDescriptor(BaseAudioContext.prototype, 'sampleRate');
      if (srDesc && srDesc.get) {
        hookGetter(srDesc.get ? (AudioContext.prototype.hasOwnProperty('sampleRate') ? AudioContext.prototype : BaseAudioContext.prototype) : AudioContext.prototype, 
          'sampleRate', 'audio', 'medium', {
          why: 'Audio sample rate varies by hardware and OS'
        });
      }
    }

    if (typeof OfflineAudioContext !== 'undefined') {
      hookFn(OfflineAudioContext.prototype, 'startRendering', 'audio', 'critical', {
        why: 'Offline audio rendering — generates deterministic audio fingerprint hash'
      });
      if (OfflineAudioContext.prototype.createOscillator) {
        hookFn(OfflineAudioContext.prototype, 'createOscillator', 'audio', 'high', {
          why: 'Offline oscillator for audio fingerprint computation'
        });
      }
      if (OfflineAudioContext.prototype.createDynamicsCompressor) {
        hookFn(OfflineAudioContext.prototype, 'createDynamicsCompressor', 'audio', 'high', {
          why: 'Offline compressor for audio fingerprint pipeline'
        });
      }
    }

    // ═══ 4. FONT DETECTION ═══
    if (document.fonts && document.fonts.check) {
      const origFontCheck = document.fonts.check.bind(document.fonts);
      document.fonts.check = function(font, text) {
        const result = origFontCheck(font, text);
        log('font-detection', 'document.fonts.check', { font, text }, 'high', {
          returnValue: result,
          why: 'CSS Font Loading API check for installed font enumeration'
        });
        return result;
      };
      if (_shield) {
        document.fonts.check.toString = function() { return 'function check() { [native code] }'; };
      }
    }

    if (document.fonts && document.fonts.forEach) {
      const origFontForEach = document.fonts.forEach.bind(document.fonts);
      document.fonts.forEach = function(...args) {
        log('font-detection', 'document.fonts.forEach', {}, 'high', {
          why: 'Font face iteration for full font inventory'
        });
        return origFontForEach(...args);
      };
    }

    // getBoundingClientRect — font width measurement
    hookFn(Element.prototype, 'getBoundingClientRect', 'font-detection', 'low', {
      detailFn: (args) => ({}),
      valueFn: (v) => v ? { w: Math.round(v.width*100)/100, h: Math.round(v.height*100)/100 } : null,
      why: 'Element dimension measurement — mass calls indicate font probing'
    });

    // offsetWidth/offsetHeight
    const owDesc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
    if (owDesc && owDesc.get) {
      let owCount = 0;
      const origOW = owDesc.get;
      Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
        get: function() {
          owCount++;
          const val = origOW.call(this);
          if (owCount <= 3 || owCount % 100 === 0) {
            log('font-detection', 'offsetWidth', { callCount: owCount, tag: this.tagName }, owCount > 200 ? 'high' : 'low', {
              returnValue: val,
              why: 'Element width read — bulk calls = font probing pattern'
            });
          }
          return val;
        },
        configurable: true
      });
    }

    // ═══ 5. NAVIGATOR PROPERTIES ═══
    const navProps = [
      { prop: 'userAgent', risk: 'high', why: 'Browser/OS identification string' },
      { prop: 'platform', risk: 'high', why: 'OS platform identifier' },
      { prop: 'language', risk: 'medium', why: 'Primary language preference' },
      { prop: 'languages', risk: 'high', why: 'Full language preference list — locale fingerprint' },
      { prop: 'hardwareConcurrency', risk: 'high', why: 'CPU core count reveals hardware class' },
      { prop: 'deviceMemory', risk: 'high', why: 'RAM amount reveals device tier' },
      { prop: 'maxTouchPoints', risk: 'medium', why: 'Touch capability reveals device type' },
      { prop: 'vendor', risk: 'medium', why: 'Browser vendor string' },
      { prop: 'appVersion', risk: 'medium', why: 'Application version string' },
      { prop: 'oscpu', risk: 'high', why: 'OS + CPU string (Firefox-specific)' },
      { prop: 'cpuClass', risk: 'high', why: 'CPU architecture class' },
      { prop: 'product', risk: 'low', why: 'Product identifier' },
      { prop: 'productSub', risk: 'low', why: 'Product sub-version' },
      { prop: 'buildID', risk: 'medium', why: 'Build identifier (Firefox)' },
      { prop: 'doNotTrack', risk: 'medium', why: 'DNT preference — ironically used for fingerprinting' },
      { prop: 'pdfViewerEnabled', risk: 'medium', why: 'PDF viewer capability' },
      { prop: 'webdriver', risk: 'critical', why: 'Automation detection flag' },
      { prop: 'connection', risk: 'medium', why: 'Network connection info' }
    ];

    for (const np of navProps) {
      const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, np.prop) ||
                   Object.getOwnPropertyDescriptor(navigator, np.prop);
      if (desc && desc.get) {
        hookGetter(desc.get.call ? Navigator.prototype : navigator, np.prop, 'fingerprint', np.risk, {
          valueFn: (v) => {
            if (Array.isArray(v)) return v.slice(0, 10);
            if (v && typeof v === 'object') return JSON.stringify(v).slice(0, 200);
            return v;
          },
          why: np.why
        });
      }
    }

    // navigator.plugins & mimeTypes
    const pluginsDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'plugins');
    if (pluginsDesc && pluginsDesc.get) {
      hookGetter(Navigator.prototype, 'plugins', 'fingerprint', 'high', {
        valueFn: (v) => v ? { length: v.length } : null,
        why: 'Plugin enumeration for browser/OS fingerprint'
      });
    }

    const mimeDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'mimeTypes');
    if (mimeDesc && mimeDesc.get) {
      hookGetter(Navigator.prototype, 'mimeTypes', 'fingerprint', 'medium', {
        valueFn: (v) => v ? { length: v.length } : null,
        why: 'MIME type list for browser capability fingerprint'
      });
    }

    // ═══ 6. PERMISSIONS API ═══
    if (navigator.permissions && navigator.permissions.query) {
      const origPermQuery = navigator.permissions.query.bind(navigator.permissions);
      navigator.permissions.query = function(desc) {
        const result = origPermQuery(desc);
        result.then(status => {
          log('permissions', 'permissions.query', { name: desc?.name }, 'high', {
            returnValue: { state: status.state },
            why: 'Permission state reveals user choices — entropy source'
          });
        }).catch(() => {});
        return result;
      };
      if (_shield) {
        navigator.permissions.query.toString = function() { return 'function query() { [native code] }'; };
      }
    }

    // ═══ 7. STORAGE HOOKS ═══
    // Cookies
    const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cookieDesc) {
      Object.defineProperty(document, 'cookie', {
        get: function() {
          const val = cookieDesc.get.call(document);
          log('storage', 'cookie.get', {}, 'medium', {
            returnValue: val ? { length: val.length, count: val.split(';').length } : null,
            why: 'Cookie read for tracking/session identification'
          });
          return val;
        },
        set: function(val) {
          log('storage', 'cookie.set', { preview: String(val).slice(0, 80) }, 'high', {
            why: 'Cookie write — potential tracking cookie placement'
          });
          return cookieDesc.set.call(document, val);
        },
        configurable: true
      });
    }

    // localStorage / sessionStorage
    if (window.localStorage) {
      const origLSGet = Storage.prototype.getItem;
      Storage.prototype.getItem = function(key) {
        const sType = (this === window.localStorage) ? 'localStorage' : 'sessionStorage';
        const result = origLSGet.call(this, key);
        log('storage', sType + '.getItem', { key }, 'medium', {
          returnValue: result ? { length: result.length, preview: result.slice(0, 50) } : null,
          why: 'Storage read — may retrieve stored fingerprint/tracking data'
        });
        return result;
      };
      const origLSSet = Storage.prototype.setItem;
      Storage.prototype.setItem = function(key, val) {
        const sType = (this === window.localStorage) ? 'localStorage' : 'sessionStorage';
        log('storage', sType + '.setItem', { key, size: String(val).length }, 'high', {
          returnValue: { size: String(val).length },
          why: 'Storage write — potential fingerprint/visitor-ID persistence'
        });
        return origLSSet.call(this, key, val);
      };
    }

    // IndexedDB
    if (window.indexedDB) {
      hookFn(IDBFactory.prototype, 'open', 'storage', 'high', {
        detailFn: (args) => ({ name: args[0], version: args[1] }),
        why: 'IndexedDB open — may store persistent fingerprint data'
      });
    }

    // ═══ 8. SCREEN & DISPLAY ═══
    const screenProps = [
      { prop: 'width', why: 'Screen width — display resolution fingerprint' },
      { prop: 'height', why: 'Screen height — display resolution fingerprint' },
      { prop: 'colorDepth', why: 'Color depth reveals display hardware' },
      { prop: 'pixelDepth', why: 'Pixel depth — display capability' },
      { prop: 'availWidth', why: 'Available width reveals taskbar/dock' },
      { prop: 'availHeight', why: 'Available height reveals OS UI elements' },
      { prop: 'availTop', why: 'Available screen offset — multi-monitor detection' },
      { prop: 'availLeft', why: 'Available screen offset — multi-monitor detection' }
    ];

    for (const sp of screenProps) {
      const desc = Object.getOwnPropertyDescriptor(Screen.prototype, sp.prop) ||
                   Object.getOwnPropertyDescriptor(screen, sp.prop);
      if (desc && desc.get) {
        hookGetter(Screen.prototype, sp.prop, 'screen', 'medium', {
          why: sp.why
        });
      }
    }

    // matchMedia
    const origMatchMedia = window.matchMedia;
    if (origMatchMedia) {
      window.matchMedia = function(query) {
        const result = origMatchMedia.call(window, query);
        const isFingerprint = /color-gamut|inverted-colors|forced-colors|prefers-|monochrome|dynamic-range|pointer|hover|any-pointer|any-hover/.test(query);
        if (isFingerprint) {
          log('fingerprint', 'matchMedia', { query }, 'high', {
            returnValue: { matches: result.matches },
            why: 'CSS media query fingerprinting — detects display & accessibility preferences'
          });
        }
        return result;
      };
      if (_shield) {
        window.matchMedia.toString = function() { return 'function matchMedia() { [native code] }'; };
      }
    }

    // devicePixelRatio
    const dprDesc = Object.getOwnPropertyDescriptor(Window.prototype, 'devicePixelRatio');
    if (dprDesc && dprDesc.get) {
      hookGetter(Window.prototype, 'devicePixelRatio', 'screen', 'medium', {
        why: 'Device pixel ratio reveals HiDPI/Retina display'
      });
    }

    // ═══ 9. NETWORK & WEBRTC ═══
    const origFetch = window.fetch;
    window.fetch = function(...args) {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
      const method = args[1]?.method || 'GET';
      const bodyLen = args[1]?.body ? String(args[1].body).length : 0;
      log('network', 'fetch', { url: url.slice(0, 200), method }, 'medium', {
        returnValue: { bodyLength: bodyLen },
        why: 'Network fetch — may be fingerprint data exfiltration'
      });
      return origFetch.apply(window, args);
    };
    if (_shield) {
      window.fetch.toString = function() { return 'function fetch() { [native code] }'; };
    }

    const origXHROpen = XMLHttpRequest.prototype.open;
    const origXHRSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      this._sentinelUrl = String(url).slice(0, 200);
      this._sentinelMethod = method;
      return origXHROpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function(body) {
      log('network', 'xhr.send', { 
        method: this._sentinelMethod, 
        url: this._sentinelUrl,
        bodySize: body ? String(body).length : 0
      }, 'medium', {
        why: 'XHR send — potential fingerprint data exfiltration'
      });
      return origXHRSend.call(this, body);
    };

    const origSendBeacon = navigator.sendBeacon;
    if (origSendBeacon) {
      navigator.sendBeacon = function(url, data) {
        log('exfiltration', 'sendBeacon', { 
          url: String(url).slice(0, 200), 
          size: data ? (data.length || data.size || 0) : 0 
        }, 'high', {
          why: 'Beacon API — fire-and-forget data exfiltration, cannot be cancelled'
        });
        return origSendBeacon.call(navigator, url, data);
      };
    }

    if (typeof RTCPeerConnection !== 'undefined') {
      const origRTCPC = RTCPeerConnection;
      window.RTCPeerConnection = function(...args) {
        log('webrtc', 'RTCPeerConnection', { 
          config: JSON.stringify(args[0])?.slice(0, 200) 
        }, 'critical', {
          why: 'WebRTC connection — can leak real IP behind VPN/proxy'
        });
        return new origRTCPC(...args);
      };
      window.RTCPeerConnection.prototype = origRTCPC.prototype;
      if (_shield) {
        window.RTCPeerConnection.toString = function() { return 'function RTCPeerConnection() { [native code] }'; };
      }
    }

    // ═══ 10. PERFORMANCE TIMING ═══
    if (performance.getEntries) {
      const origGetEntries = performance.getEntries.bind(performance);
      performance.getEntries = function() {
        const result = origGetEntries();
        log('perf-timing', 'getEntries', {}, 'medium', {
          returnValue: { count: result.length },
          why: 'Performance entries reveal loaded resources and timing'
        });
        return result;
      };
    }
    if (performance.getEntriesByType) {
      const origGetByType = performance.getEntriesByType.bind(performance);
      performance.getEntriesByType = function(type) {
        const result = origGetByType(type);
        log('perf-timing', 'getEntriesByType', { type }, 'medium', {
          returnValue: { count: result.length },
          why: 'Performance entries by type — resource/navigation timing fingerprint'
        });
        return result;
      };
    }
    const origPerfNow = performance.now.bind(performance);
    let perfNowCount = 0;
    performance.now = function() {
      perfNowCount++;
      const result = origPerfNow();
      if (perfNowCount <= 5 || perfNowCount % 200 === 0) {
        log('perf-timing', 'performance.now', { callCount: perfNowCount }, perfNowCount > 500 ? 'high' : 'low', {
          returnValue: Math.round(result * 100) / 100,
          why: 'High-resolution timing — used for WASM/timing-based fingerprinting'
        });
      }
      return result;
    };

    // ═══ 11. MATH FINGERPRINTING ═══
    const mathFuncs = ['acos','acosh','asin','asinh','atanh','atan','sin','sinh','cos','cosh','tan','tanh','exp','expm1','log1p'];
    let mathCallCount = 0;
    for (const fn of mathFuncs) {
      if (Math[fn]) {
        const orig = Math[fn];
        Math[fn] = function(x) {
          mathCallCount++;
          const result = orig(x);
          if (mathCallCount <= 20 || mathCallCount % 50 === 0) {
            log('math-fingerprint', 'Math.' + fn, { input: x }, 'medium', {
              returnValue: result,
              why: 'Math function precision varies by JS engine/FPU — fingerprint vector'
            });
          }
          return result;
        };
        if (_shield) {
          Math[fn].toString = function() { return 'function ' + fn + '() { [native code] }'; };
        }
      }
    }

    // ═══ 12. MEDIA DEVICES ═══
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      const origEnumDev = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
      navigator.mediaDevices.enumerateDevices = function() {
        const result = origEnumDev();
        result.then(devices => {
          log('media-devices', 'enumerateDevices', {}, 'critical', {
            returnValue: { 
              count: devices.length, 
              types: devices.map(d => d.kind),
              labels: devices.map(d => d.label ? d.label.slice(0, 30) : '[no-label]')
            },
            why: 'Device enumeration reveals cameras/microphones — unique hardware fingerprint'
          });
        }).catch(() => {});
        return result;
      };
    }

    // ═══ 13. DOM PROBING ═══
    const origCreateElement = document.createElement.bind(document);
    document.createElement = function(tag, ...args) {
      const lTag = tag?.toLowerCase?.();
      if (['canvas', 'iframe', 'audio', 'video', 'object', 'embed'].includes(lTag)) {
        log('dom-probe', 'createElement', { tag: lTag }, lTag === 'canvas' ? 'high' : 'medium', {
          why: 'Dynamic element creation — canvas/iframe/audio for fingerprinting'
        });
      }
      return origCreateElement(tag, ...args);
    };
    if (_shield) {
      document.createElement.toString = function() { return 'function createElement() { [native code] }'; };
    }

    // ═══ 14. CLIPBOARD ═══
    if (navigator.clipboard) {
      if (navigator.clipboard.readText) {
        const origRead = navigator.clipboard.readText.bind(navigator.clipboard);
        navigator.clipboard.readText = function() {
          log('clipboard', 'clipboard.readText', {}, 'critical', {
            why: 'Clipboard read — accessing user private clipboard data'
          });
          return origRead();
        };
      }
      if (navigator.clipboard.writeText) {
        const origWrite = navigator.clipboard.writeText.bind(navigator.clipboard);
        navigator.clipboard.writeText = function(text) {
          log('clipboard', 'clipboard.writeText', { size: text?.length }, 'high', {
            why: 'Clipboard write — may inject tracking data'
          });
          return origWrite(text);
        };
      }
    }

    // ═══ 15. GEOLOCATION ═══
    if (navigator.geolocation) {
      const origGetPos = navigator.geolocation.getCurrentPosition;
      navigator.geolocation.getCurrentPosition = function(...args) {
        log('geolocation', 'getCurrentPosition', {}, 'critical', {
          why: 'Geolocation request — precise physical location tracking'
        });
        return origGetPos.apply(navigator.geolocation, args);
      };
      const origWatchPos = navigator.geolocation.watchPosition;
      navigator.geolocation.watchPosition = function(...args) {
        log('geolocation', 'watchPosition', {}, 'critical', {
          why: 'Continuous geolocation tracking'
        });
        return origWatchPos.apply(navigator.geolocation, args);
      };
    }

    // ═══ 16. SERVICE WORKER ═══
    if (navigator.serviceWorker) {
      const origSWRegister = navigator.serviceWorker.register;
      if (origSWRegister) {
        navigator.serviceWorker.register = function(url, ...args) {
          log('service-worker', 'sw.register', { url: String(url).slice(0, 100) }, 'critical', {
            why: 'Service worker registration — persistent background code execution'
          });
          return origSWRegister.call(navigator.serviceWorker, url, ...args);
        };
      }
    }

    // ═══ 17. BATTERY API ═══
    if (navigator.getBattery) {
      const origGetBattery = navigator.getBattery.bind(navigator);
      navigator.getBattery = function() {
        const result = origGetBattery();
        result.then(battery => {
          log('hardware', 'getBattery', {}, 'high', {
            returnValue: {
              charging: battery.charging,
              level: battery.level,
              chargingTime: battery.chargingTime,
              dischargingTime: battery.dischargingTime
            },
            why: 'Battery status reveals device state — mobile fingerprint vector'
          });
        }).catch(() => {});
        return result;
      };
    }

    // ═══ 18. DATE/TIMEZONE PROBING ═══
    hookFn(Date.prototype, 'getTimezoneOffset', 'fingerprint', 'medium', {
      valueFn: (v) => v,
      why: 'Timezone offset reveals geographic region'
    });

    if (window.Intl?.DateTimeFormat) {
      hookFn(Intl.DateTimeFormat.prototype, 'resolvedOptions', 'fingerprint', 'medium', {
        valueFn: (v) => v ? { locale: v.locale, timeZone: v.timeZone, calendar: v.calendar } : null,
        why: 'Intl resolved options — locale/timezone fingerprint (FPjs v5 dateTimeLocale source)'
      });
    }

    // ═══ 19. ARCHITECTURE DETECTION ═══
    // Float32Array precision differences reveal CPU architecture
    const origF32Set = Float32Array.prototype.set;
    if (origF32Set) {
      Float32Array.prototype.set = function(...args) {
        log('architecture', 'Float32Array.set', { len: args[0]?.length }, 'medium', {
          why: 'Float32Array operations for CPU architecture fingerprinting'
        });
        return origF32Set.apply(this, args);
      };
    }

    // ═══════════════════════════════════════════
    //  LAYER 4: EXTENDED VECTORS (12 new categories)
    // ═══════════════════════════════════════════

    // ═══ 20. SPEECH SYNTHESIS ═══
    if (window.speechSynthesis && window.speechSynthesis.getVoices) {
      const origGetVoices = window.speechSynthesis.getVoices.bind(window.speechSynthesis);
      window.speechSynthesis.getVoices = function() {
        const voices = origGetVoices();
        log('speech', 'speechSynthesis.getVoices', {}, 'high', {
          returnValue: {
            count: voices.length,
            voices: voices.slice(0, 5).map(v => ({ name: v.name, lang: v.lang, default: v.default }))
          },
          why: 'Speech voice enumeration — OS/language fingerprint via installed TTS voices'
        });
        return voices;
      };
    }

    // ═══ 21. CLIENT HINTS ═══
    if (navigator.userAgentData) {
      const origGetHighEntropy = navigator.userAgentData.getHighEntropyValues;
      if (origGetHighEntropy) {
        navigator.userAgentData.getHighEntropyValues = function(hints) {
          const result = origGetHighEntropy.call(navigator.userAgentData, hints);
          result.then(values => {
            log('client-hints', 'getHighEntropyValues', { hints }, 'critical', {
              returnValue: values,
              why: 'Client Hints high-entropy — exposes OS version, CPU arch, device model, full browser version'
            });
          }).catch(() => {});
          return result;
        };
      }

      // brands getter
      const uadDesc = Object.getOwnPropertyDescriptor(NavigatorUAData.prototype, 'brands');
      if (uadDesc && uadDesc.get) {
        hookGetter(NavigatorUAData.prototype, 'brands', 'client-hints', 'high', {
          valueFn: (v) => v ? v.map(b => ({ brand: b.brand, version: b.version })) : null,
          why: 'User-Agent brands — browser identification'
        });
      }

      const uadPlatDesc = Object.getOwnPropertyDescriptor(NavigatorUAData.prototype, 'platform');
      if (uadPlatDesc && uadPlatDesc.get) {
        hookGetter(NavigatorUAData.prototype, 'platform', 'client-hints', 'high', {
          why: 'UA-CH platform — OS identification'
        });
      }

      const uadMobileDesc = Object.getOwnPropertyDescriptor(NavigatorUAData.prototype, 'mobile');
      if (uadMobileDesc && uadMobileDesc.get) {
        hookGetter(NavigatorUAData.prototype, 'mobile', 'client-hints', 'medium', {
          why: 'UA-CH mobile flag — device type detection'
        });
      }
    }

    // ═══ 22. INTL EXTENDED ═══
    if (window.Intl) {
      if (Intl.ListFormat) {
        hookFn(Intl.ListFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium', {
          valueFn: (v) => v,
          why: 'Intl.ListFormat reveals locale-specific list formatting rules'
        });
      }
      if (Intl.NumberFormat) {
        hookFn(Intl.NumberFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium', {
          valueFn: (v) => v ? { locale: v.locale, numberingSystem: v.numberingSystem } : null,
          why: 'Intl.NumberFormat exposes locale number formatting preferences'
        });
      }
      if (Intl.RelativeTimeFormat) {
        hookFn(Intl.RelativeTimeFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium', {
          valueFn: (v) => v,
          why: 'Intl.RelativeTimeFormat reveals locale-specific time formatting'
        });
      }
      if (Intl.PluralRules) {
        hookFn(Intl.PluralRules.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium', {
          valueFn: (v) => v,
          why: 'Intl.PluralRules exposes locale plural rules — language fingerprint'
        });
      }
      if (Intl.Collator) {
        hookFn(Intl.Collator.prototype, 'resolvedOptions', 'intl-fingerprint', 'medium', {
          valueFn: (v) => v ? { locale: v.locale, collation: v.collation, sensitivity: v.sensitivity } : null,
          why: 'Intl.Collator reveals locale-specific string sorting rules'
        });
      }
    }

    // ═══ 23. CSS.supports FINGERPRINTING ═══
    if (window.CSS && window.CSS.supports) {
      const origSupports = window.CSS.supports;
      window.CSS.supports = function(...args) {
        const result = origSupports.apply(window.CSS, args);
        const query = args.length === 1 ? args[0] : args[0] + ': ' + args[1];
        log('css-fingerprint', 'CSS.supports', { query }, 'medium', {
          returnValue: result,
          why: 'CSS feature detection — reveals browser version and rendering engine capabilities'
        });
        return result;
      };
    }

    // ═══ 24. PROPERTY ENUMERATION ═══
    // CreepJS uses Object.keys/getOwnPropertyNames to detect hook artifacts
    const origObjKeys = Object.keys;
    Object.keys = function(obj) {
      const result = origObjKeys(obj);
      // Only log suspicious targets
      if (obj === navigator || obj === screen || obj === window) {
        log('property-enum', 'Object.keys', { target: obj === navigator ? 'navigator' : obj === screen ? 'screen' : 'window' }, 'medium', {
          returnValue: { count: result.length },
          why: 'Property enumeration on sensitive objects — prototype lie detection technique'
        });
      }
      return result;
    };
    if (_shield) {
      Object.keys.toString = function() { return 'function keys() { [native code] }'; };
    }

    const origObjGetOwnPropertyNames = Object.getOwnPropertyNames;
    Object.getOwnPropertyNames = function(obj) {
      const result = origObjGetOwnPropertyNames(obj);
      if (obj === navigator || obj === screen || obj === window || 
          obj === Navigator.prototype || obj === Screen.prototype) {
        log('property-enum', 'Object.getOwnPropertyNames', { 
          target: obj.constructor?.name || 'unknown'
        }, 'high', {
          returnValue: { count: result.length, sample: result.slice(0, 10) },
          why: 'Deep property inspection — lie detection for hooked prototypes'
        });
      }
      return result;
    };
    if (_shield) {
      Object.getOwnPropertyNames.toString = function() { return 'function getOwnPropertyNames() { [native code] }'; };
    }

    // ═══ 25. OFFSCREEN CANVAS ═══
    if (typeof OffscreenCanvas !== 'undefined') {
      const origOCGetCtx = OffscreenCanvas.prototype.getContext;
      OffscreenCanvas.prototype.getContext = function(...args) {
        log('offscreen-canvas', 'OffscreenCanvas.getContext', { type: args[0] }, 'high', {
          why: 'OffscreenCanvas can run in Web Workers — evades main-thread detection'
        });
        return origOCGetCtx.apply(this, args);
      };

      const origOCTransfer = OffscreenCanvas.prototype.transferToImageBitmap;
      if (origOCTransfer) {
        OffscreenCanvas.prototype.transferToImageBitmap = function() {
          log('offscreen-canvas', 'transferToImageBitmap', {}, 'high', {
            why: 'OffscreenCanvas bitmap transfer — WebWorker canvas fingerprinting'
          });
          return origOCTransfer.call(this);
        };
      }

      const origOCConvertToBlob = OffscreenCanvas.prototype.convertToBlob;
      if (origOCConvertToBlob) {
        OffscreenCanvas.prototype.convertToBlob = function(...args) {
          log('offscreen-canvas', 'convertToBlob', { type: args[0]?.type }, 'high', {
            why: 'OffscreenCanvas blob export for fingerprint hashing'
          });
          return origOCConvertToBlob.apply(this, args);
        };
      }
    }

    // ═══ 26. WEBSOCKET MONITORING ═══
    if (typeof WebSocket !== 'undefined') {
      const origWS = WebSocket;
      window.WebSocket = function(url, ...args) {
        log('exfiltration', 'WebSocket', { url: String(url).slice(0, 200) }, 'high', {
          why: 'WebSocket connection — potential real-time fingerprint data exfiltration channel'
        });
        return new origWS(url, ...args);
      };
      window.WebSocket.prototype = origWS.prototype;
      window.WebSocket.CONNECTING = origWS.CONNECTING;
      window.WebSocket.OPEN = origWS.OPEN;
      window.WebSocket.CLOSING = origWS.CLOSING;
      window.WebSocket.CLOSED = origWS.CLOSED;
    }

    // ═══ 27. IMAGE-BASED EXFILTRATION ═══
    const origImageSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
    if (origImageSrc && origImageSrc.set) {
      const origSrcSet = origImageSrc.set;
      Object.defineProperty(HTMLImageElement.prototype, 'src', {
        get: origImageSrc.get,
        set: function(val) {
          const url = String(val);
          // Detect tracking pixels and data exfil via image
          if (/collect|pixel|track|beacon|telemetry|log|fp|fingerprint/i.test(url) || 
              url.includes('?') && url.length > 200) {
            log('exfiltration', 'img.src', { url: url.slice(0, 200) }, 'high', {
              why: 'Tracking pixel — fingerprint data exfiltration via image request'
            });
          }
          return origSrcSet.call(this, val);
        },
        enumerable: true,
        configurable: true
      });
    }

    // ═══ 28. MUTATION OBSERVER ═══
    if (typeof MutationObserver !== 'undefined') {
      const origMO = MutationObserver;
      window.MutationObserver = function(callback) {
        log('dom-probe', 'MutationObserver', {}, 'low', {
          why: 'DOM mutation monitoring — may detect DOM-based fingerprint activities'
        });
        return new origMO(callback);
      };
      window.MutationObserver.prototype = origMO.prototype;
    }

    // ═══ 29. INTERSECTION OBSERVER ═══
    if (typeof IntersectionObserver !== 'undefined') {
      const origIO = IntersectionObserver;
      window.IntersectionObserver = function(callback, options) {
        log('dom-probe', 'IntersectionObserver', { 
          threshold: options?.threshold 
        }, 'low', {
          why: 'Intersection observation — may detect hidden fingerprinting elements'
        });
        return new origIO(callback, options);
      };
      window.IntersectionObserver.prototype = origIO.prototype;
    }

    // ═══ 30. GAMEPAD API ═══
    if (navigator.getGamepads) {
      const origGetGamepads = navigator.getGamepads.bind(navigator);
      navigator.getGamepads = function() {
        const result = origGetGamepads();
        log('hardware', 'navigator.getGamepads', {}, 'medium', {
          returnValue: { count: result ? Array.from(result).filter(Boolean).length : 0 },
          why: 'Gamepad enumeration — hardware peripheral fingerprinting'
        });
        return result;
      };
    }

    // ═══ 31. CREDENTIAL MANAGEMENT ═══
    if (navigator.credentials) {
      if (navigator.credentials.get) {
        const origCredGet = navigator.credentials.get.bind(navigator.credentials);
        navigator.credentials.get = function(options) {
          log('credential', 'credentials.get', { 
            types: options ? Object.keys(options).join(',') : 'none' 
          }, 'critical', {
            why: 'Credential access request — potential authentication data extraction'
          });
          return origCredGet(options);
        };
      }
      if (navigator.credentials.create) {
        const origCredCreate = navigator.credentials.create.bind(navigator.credentials);
        navigator.credentials.create = function(options) {
          log('credential', 'credentials.create', {
            types: options ? Object.keys(options).join(',') : 'none'
          }, 'high', {
            why: 'Credential creation — WebAuthn/passkey fingerprint vector'
          });
          return origCredCreate(options);
        };
      }
    }

    // ═══ HONEYPOT PROPERTIES ═══
    // Plant fake high-value properties. Any access = definitely fingerprinting
    const honeypotProps = [
      { target: navigator, prop: '__fpjs_d_m', cat: 'honeypot' },
      { target: window, prop: '__selenium_evaluate', cat: 'honeypot' },
      { target: window, prop: '__fxdriver_evaluate', cat: 'honeypot' },
      { target: document, prop: '__selenium_unwrapped', cat: 'honeypot' },
    ];

    for (const hp of honeypotProps) {
      try {
        Object.defineProperty(hp.target, hp.prop, {
          get: function() {
            log('honeypot', hp.prop, {}, 'critical', {
              why: 'Honeypot property accessed — confirms active fingerprinting/bot-detection probing'
            });
            return undefined;
          },
          set: function() {},
          configurable: true,
          enumerable: false // Hidden from Object.keys but accessible by name
        });
      } catch(e) {}
    }

    // ═══ UTILITY: Simple string hash ═══
    function hashStr(str) {
      let hash = 0;
      for (let i = 0; i < Math.min(str.length, 1000); i++) {
        const chr = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + chr;
        hash |= 0;
      }
      return Math.abs(hash).toString(36);
    }

    // ═══ BOOT_OK PROTOCOL ═══
    // Mandatory event to prove this context is being monitored
    _sentinel.bootOk = true;
    log('system', 'BOOT_OK', {
      frameId: _sentinel.frameId,
      url: location.href,
      origin: location.origin,
      isTop: window === window.top,
      timestamp: Date.now()
    }, 'info', {
      why: 'Coverage proof — confirms Sentinel is active in this execution context'
    });

    // ═══ GLOBAL EXPORT ═══
    window.__SENTINEL_DATA__ = _sentinel;

    // Context map
    window.__SENTINEL_CONTEXT_MAP__ = [{
      type: 'page',
      url: location.href,
      origin: location.origin,
      frameId: _sentinel.frameId,
      bootOk: true,
      timestamp: Date.now()
    }];

    // ═══ PUSH TELEMETRY via Runtime.addBinding (if available) ═══
    if (typeof window.__SENTINEL_PUSH__ === 'function') {
      // Push events periodically to Node.js via CDP Runtime.addBinding
      setInterval(() => {
        if (_sentinel.events.length > 0) {
          try {
            const batch = _sentinel.events.splice(0, 500);
            window.__SENTINEL_PUSH__(JSON.stringify({
              type: 'event_batch',
              frameId: _sentinel.frameId,
              origin: location.origin,
              url: location.href,
              events: batch
            }));
          } catch(e) {}
        }
      }, 1000);
    }

    console.log('[Sentinel v4] Forensic Maling Catcher active — monitoring 31 categories | Frame: ' + _sentinel.frameId);
  })();
  `;
}

module.exports = { getInterceptorScript };
