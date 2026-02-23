/**
 * Sentinel v3 — Comprehensive API Interceptor
 * Hooks ALL known fingerprinting vectors including:
 * - Canvas, WebGL, Audio (AudioContext + OfflineAudioContext)
 * - Font detection (document.fonts, measureText)
 * - Storage (cookies, localStorage, sessionStorage, indexedDB)
 * - Navigator properties, Permissions API
 * - Screen/Display info, Performance timing
 * - WebRTC, Network info, Media Devices
 * - DOM probing (adblock detection, iframe manipulation)
 * - Math fingerprinting, Architecture detection
 */

function getInterceptorScript(config = {}) {
  const timeout = config.timeout || 30000;

  return `
  (function() {
    'use strict';

    // ═══════════════════════════════════════════
    //  SENTINEL v3 — MALING CATCHER ENGINE
    // ═══════════════════════════════════════════

    const _sentinel = {
      events: [],
      startTime: Date.now(),
      config: {
        timeout: ${timeout},
        maxEvents: 50000
      }
    };

    function log(category, api, detail, risk) {
      if (_sentinel.events.length >= _sentinel.config.maxEvents) return;
      const origin = (typeof location !== 'undefined') ? location.origin : 'unknown';
      _sentinel.events.push({
        ts: Date.now() - _sentinel.startTime,
        cat: category,
        api: api,
        detail: (typeof detail === 'object') ? JSON.stringify(detail).slice(0, 200) : String(detail || '').slice(0, 200),
        risk: risk || 'low',
        origin: origin,
        frame: (window !== window.top) ? 'iframe' : 'top'
      });
    }

    // ═══ 1. CANVAS FINGERPRINTING ═══
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
      log('canvas', 'toDataURL', { type: args[0] || 'image/png' }, 'high');
      return origToDataURL.apply(this, args);
    };

    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = function(...args) {
      log('canvas', 'toBlob', { type: args[1] || 'image/png' }, 'high');
      return origToBlob.apply(this, args);
    };

    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(...args) {
      log('canvas', 'getImageData', { x: args[0], y: args[1], w: args[2], h: args[3] }, 'high');
      return origGetImageData.apply(this, args);
    };

    const origFillText = CanvasRenderingContext2D.prototype.fillText;
    CanvasRenderingContext2D.prototype.fillText = function(text, ...args) {
      log('canvas', 'fillText', { text: text?.slice?.(0, 50), font: this.font }, 'medium');
      return origFillText.call(this, text, ...args);
    };

    const origMeasureText = CanvasRenderingContext2D.prototype.measureText;
    CanvasRenderingContext2D.prototype.measureText = function(text) {
      log('font-detection', 'measureText', { text: text?.slice?.(0, 30), font: this.font }, 'high');
      return origMeasureText.call(this, text);
    };

    const origIsPointInPath = CanvasRenderingContext2D.prototype.isPointInPath;
    CanvasRenderingContext2D.prototype.isPointInPath = function(...args) {
      log('canvas', 'isPointInPath', { args: args.slice(0,3) }, 'medium');
      return origIsPointInPath.apply(this, args);
    };

    // ═══ 2. WEBGL FINGERPRINTING ═══
    function hookWebGL(proto, name) {
      const origGetParam = proto.getParameter;
      proto.getParameter = function(param) {
        log('webgl', 'getParameter', { param, ctx: name }, 'high');
        return origGetParam.call(this, param);
      };

      const origGetExtension = proto.getExtension;
      proto.getExtension = function(ext) {
        log('webgl', 'getExtension', { ext, ctx: name }, 'medium');
        return origGetExtension.call(this, ext);
      };

      const origGetSupportedExt = proto.getSupportedExtensions;
      proto.getSupportedExtensions = function() {
        log('webgl', 'getSupportedExtensions', { ctx: name }, 'medium');
        return origGetSupportedExt.call(this);
      };

      const origGetShaderPrecision = proto.getShaderPrecisionFormat;
      if (origGetShaderPrecision) {
        proto.getShaderPrecisionFormat = function(...args) {
          log('webgl', 'getShaderPrecisionFormat', { ctx: name }, 'high');
          return origGetShaderPrecision.apply(this, args);
        };
      }

      const origGetContextAttrs = proto.getContextAttributes;
      proto.getContextAttributes = function() {
        log('webgl', 'getContextAttributes', { ctx: name }, 'low');
        return origGetContextAttrs.call(this);
      };

      const origReadPixels = proto.readPixels;
      if (origReadPixels) {
        proto.readPixels = function(...args) {
          log('webgl', 'readPixels', { ctx: name }, 'high');
          return origReadPixels.apply(this, args);
        };
      }
    }

    if (typeof WebGLRenderingContext !== 'undefined') hookWebGL(WebGLRenderingContext.prototype, 'webgl');
    if (typeof WebGL2RenderingContext !== 'undefined') hookWebGL(WebGL2RenderingContext.prototype, 'webgl2');

    // ═══ 3. AUDIO FINGERPRINTING ═══
    if (typeof OfflineAudioContext !== 'undefined' || typeof webkitOfflineAudioContext !== 'undefined') {
      const OAC = typeof OfflineAudioContext !== 'undefined' ? OfflineAudioContext : webkitOfflineAudioContext;
      const origOACConstructor = OAC;
      const origStartRendering = OAC.prototype.startRendering;
      OAC.prototype.startRendering = function() {
        log('audio', 'OfflineAudioContext.startRendering', { length: this.length, sampleRate: this.sampleRate }, 'critical');
        return origStartRendering.call(this);
      };

      const origCreateOscillator = OAC.prototype.createOscillator || (typeof AudioContext !== 'undefined' && AudioContext.prototype.createOscillator);
      if (typeof AudioContext !== 'undefined') {
        const origACCreateOsc = AudioContext.prototype.createOscillator;
        AudioContext.prototype.createOscillator = function() {
          log('audio', 'createOscillator', {}, 'high');
          return origACCreateOsc.call(this);
        };

        const origACCreateDC = AudioContext.prototype.createDynamicsCompressor;
        AudioContext.prototype.createDynamicsCompressor = function() {
          log('audio', 'createDynamicsCompressor', {}, 'high');
          return origACCreateDC.call(this);
        };

        const origACCreateAnalyser = AudioContext.prototype.createAnalyser;
        if (origACCreateAnalyser) {
          AudioContext.prototype.createAnalyser = function() {
            log('audio', 'createAnalyser', {}, 'medium');
            return origACCreateAnalyser.call(this);
          };
        }

        const origACCreateGain = AudioContext.prototype.createGain;
        if (origACCreateGain) {
          AudioContext.prototype.createGain = function() {
            log('audio', 'createGain', {}, 'low');
            return origACCreateGain.call(this);
          };
        }

        const origACCreateScriptProc = AudioContext.prototype.createScriptProcessor;
        if (origACCreateScriptProc) {
          AudioContext.prototype.createScriptProcessor = function(...args) {
            log('audio', 'createScriptProcessor', {}, 'medium');
            return origACCreateScriptProc.apply(this, args);
          };
        }

        // baseLatency hook
        const acProto = AudioContext.prototype;
        const blDesc = Object.getOwnPropertyDescriptor(acProto, 'baseLatency');
        if (blDesc && blDesc.get) {
          const origBL = blDesc.get;
          Object.defineProperty(acProto, 'baseLatency', {
            get: function() {
              log('audio', 'baseLatency', {}, 'medium');
              return origBL.call(this);
            },
            configurable: true
          });
        }
      }

      // Hook OfflineAudioContext methods too
      const origOACCreateOsc = OAC.prototype.createOscillator;
      if (origOACCreateOsc) {
        OAC.prototype.createOscillator = function() {
          log('audio', 'OAC.createOscillator', {}, 'high');
          return origOACCreateOsc.call(this);
        };
      }
      const origOACCreateDC = OAC.prototype.createDynamicsCompressor;
      if (origOACCreateDC) {
        OAC.prototype.createDynamicsCompressor = function() {
          log('audio', 'OAC.createDynamicsCompressor', {}, 'high');
          return origOACCreateDC.call(this);
        };
      }
    }

    // ═══ 4. FONT DETECTION ═══
    if (document.fonts && document.fonts.check) {
      const origFontCheck = document.fonts.check.bind(document.fonts);
      document.fonts.check = function(font, text) {
        log('font-detection', 'document.fonts.check', { font, text }, 'high');
        return origFontCheck(font, text);
      };
    }

    if (document.fonts && document.fonts.forEach) {
      const origFontForEach = document.fonts.forEach.bind(document.fonts);
      document.fonts.forEach = function(...args) {
        log('font-detection', 'document.fonts.forEach', {}, 'high');
        return origFontForEach(...args);
      };
    }

    // getBoundingClientRect — used for font width measurement
    const origGetBCR = Element.prototype.getBoundingClientRect;
    let bcrCallCount = 0;
    Element.prototype.getBoundingClientRect = function() {
      bcrCallCount++;
      // Only log if called excessively (font probing pattern)
      if (bcrCallCount <= 5 || bcrCallCount % 50 === 0) {
        log('font-detection', 'getBoundingClientRect', { callCount: bcrCallCount, tag: this.tagName }, bcrCallCount > 100 ? 'critical' : 'low');
      }
      return origGetBCR.call(this);
    };

    // offsetWidth/offsetHeight — also used for font detection
    const origOffsetWidthDesc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
    let owCallCount = 0;
    if (origOffsetWidthDesc && origOffsetWidthDesc.get) {
      Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
        get: function() {
          owCallCount++;
          if (owCallCount <= 3 || owCallCount % 100 === 0) {
            log('font-detection', 'offsetWidth', { callCount: owCallCount, tag: this.tagName }, owCallCount > 200 ? 'high' : 'low');
          }
          return origOffsetWidthDesc.get.call(this);
        },
        configurable: true
      });
    }

    // ═══ 5. NAVIGATOR PROPERTY READS ═══
    const navProps = [
      'userAgent', 'platform', 'language', 'languages', 'hardwareConcurrency',
      'deviceMemory', 'maxTouchPoints', 'vendor', 'appVersion', 'oscpu',
      'cpuClass', 'product', 'productSub', 'buildID', 'doNotTrack',
      'pdfViewerEnabled', 'webdriver', 'connection'
    ];

    for (const prop of navProps) {
      const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, prop) ||
                   Object.getOwnPropertyDescriptor(navigator, prop);
      if (desc && desc.get) {
        const origGetter = desc.get;
        Object.defineProperty(navigator, prop, {
          get: function() {
            const risk = ['userAgent', 'platform', 'hardwareConcurrency', 'deviceMemory', 'languages'].includes(prop) ? 'high' : 'medium';
            log('fingerprint', prop, {}, risk);
            return origGetter.call(navigator);
          },
          configurable: true,
          enumerable: desc.enumerable
        });
      }
    }

    // navigator.plugins
    const pluginsDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'plugins');
    if (pluginsDesc && pluginsDesc.get) {
      const origPlugins = pluginsDesc.get;
      Object.defineProperty(navigator, 'plugins', {
        get: function() {
          log('fingerprint', 'navigator.plugins', {}, 'high');
          return origPlugins.call(navigator);
        },
        configurable: true
      });
    }

    // navigator.mimeTypes
    const mimeDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'mimeTypes');
    if (mimeDesc && mimeDesc.get) {
      const origMime = mimeDesc.get;
      Object.defineProperty(navigator, 'mimeTypes', {
        get: function() {
          log('fingerprint', 'navigator.mimeTypes', {}, 'medium');
          return origMime.call(navigator);
        },
        configurable: true
      });
    }

    // ═══ 6. PERMISSIONS API ═══
    if (navigator.permissions && navigator.permissions.query) {
      const origPermQuery = navigator.permissions.query.bind(navigator.permissions);
      navigator.permissions.query = function(desc) {
        log('permissions', 'permissions.query', { name: desc?.name }, 'high');
        return origPermQuery(desc);
      };
    }

    // ═══ 7. STORAGE HOOKS ═══
    // Cookies
    const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cookieDesc) {
      Object.defineProperty(document, 'cookie', {
        get: function() {
          log('storage', 'cookie.get', {}, 'medium');
          return cookieDesc.get.call(document);
        },
        set: function(val) {
          log('storage', 'cookie.set', { preview: String(val).slice(0, 60) }, 'high');
          return cookieDesc.set.call(document, val);
        },
        configurable: true
      });
    }

    // localStorage
    if (window.localStorage) {
      const origLSGet = Storage.prototype.getItem;
      Storage.prototype.getItem = function(key) {
        const storageType = (this === window.localStorage) ? 'localStorage' : 'sessionStorage';
        log('storage', storageType + '.getItem', { key }, 'medium');
        return origLSGet.call(this, key);
      };
      const origLSSet = Storage.prototype.setItem;
      Storage.prototype.setItem = function(key, val) {
        const storageType = (this === window.localStorage) ? 'localStorage' : 'sessionStorage';
        log('storage', storageType + '.setItem', { key, size: String(val).length }, 'high');
        return origLSSet.call(this, key, val);
      };
    }

    // IndexedDB
    if (window.indexedDB) {
      const origIDBOpen = IDBFactory.prototype.open;
      IDBFactory.prototype.open = function(name, ver) {
        log('storage', 'indexedDB.open', { name, version: ver }, 'high');
        return origIDBOpen.call(this, name, ver);
      };
    }

    // ═══ 8. SCREEN & DISPLAY ═══
    const screenProps = ['width', 'height', 'colorDepth', 'pixelDepth', 'availWidth', 'availHeight', 'availTop', 'availLeft'];
    for (const prop of screenProps) {
      const desc = Object.getOwnPropertyDescriptor(Screen.prototype, prop) ||
                   Object.getOwnPropertyDescriptor(screen, prop);
      if (desc && desc.get) {
        const origGetter = desc.get;
        Object.defineProperty(screen, prop, {
          get: function() {
            log('screen', 'screen.' + prop, {}, 'medium');
            return origGetter.call(screen);
          },
          configurable: true
        });
      }
    }

    // matchMedia — used for media query fingerprinting
    const origMatchMedia = window.matchMedia;
    if (origMatchMedia) {
      window.matchMedia = function(query) {
        const isFingerprint = /color-gamut|inverted-colors|forced-colors|prefers-|monochrome|dynamic-range/.test(query);
        if (isFingerprint) {
          log('fingerprint', 'matchMedia', { query }, 'high');
        }
        return origMatchMedia.call(window, query);
      };
    }

    // devicePixelRatio
    const dprDesc = Object.getOwnPropertyDescriptor(Window.prototype, 'devicePixelRatio');
    if (dprDesc && dprDesc.get) {
      const origDPR = dprDesc.get;
      Object.defineProperty(window, 'devicePixelRatio', {
        get: function() {
          log('screen', 'devicePixelRatio', {}, 'medium');
          return origDPR.call(window);
        },
        configurable: true
      });
    }

    // ═══ 9. NETWORK & WEBRTC ═══
    const origFetch = window.fetch;
    window.fetch = function(...args) {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
      log('network', 'fetch', { url: url.slice(0, 120) }, 'medium');
      return origFetch.apply(window, args);
    };

    const origXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      log('network', 'xhr.open', { method, url: String(url).slice(0, 120) }, 'medium');
      return origXHROpen.call(this, method, url, ...rest);
    };

    const origSendBeacon = navigator.sendBeacon;
    if (origSendBeacon) {
      navigator.sendBeacon = function(url, data) {
        log('network', 'sendBeacon', { url: String(url).slice(0, 120), size: data?.length || 0 }, 'high');
        return origSendBeacon.call(navigator, url, data);
      };
    }

    if (typeof RTCPeerConnection !== 'undefined') {
      const origRTCPC = RTCPeerConnection;
      window.RTCPeerConnection = function(...args) {
        log('webrtc', 'RTCPeerConnection', { config: JSON.stringify(args[0])?.slice(0, 100) }, 'critical');
        return new origRTCPC(...args);
      };
      window.RTCPeerConnection.prototype = origRTCPC.prototype;
    }

    // ═══ 10. PERFORMANCE TIMING ═══
    if (performance.getEntries) {
      const origGetEntries = performance.getEntries.bind(performance);
      performance.getEntries = function() {
        log('perf-timing', 'getEntries', {}, 'medium');
        return origGetEntries();
      };
    }
    if (performance.getEntriesByType) {
      const origGetByType = performance.getEntriesByType.bind(performance);
      performance.getEntriesByType = function(type) {
        log('perf-timing', 'getEntriesByType', { type }, 'medium');
        return origGetByType(type);
      };
    }
    const origPerfNow = performance.now.bind(performance);
    let perfNowCount = 0;
    performance.now = function() {
      perfNowCount++;
      if (perfNowCount <= 5 || perfNowCount % 200 === 0) {
        log('perf-timing', 'performance.now', { callCount: perfNowCount }, perfNowCount > 500 ? 'high' : 'low');
      }
      return origPerfNow();
    };

    // ═══ 11. MATH FINGERPRINTING ═══
    const mathFuncs = ['acos', 'acosh', 'asin', 'asinh', 'atanh', 'atan', 'sin', 'sinh', 'cos', 'cosh', 'tan', 'tanh', 'exp', 'expm1', 'log1p'];
    let mathCallCount = 0;
    for (const fn of mathFuncs) {
      const origFn = Math[fn];
      if (origFn) {
        Math[fn] = function(...args) {
          mathCallCount++;
          if (mathCallCount <= 3 || mathCallCount % 50 === 0) {
            log('math-fingerprint', 'Math.' + fn, { args: args.slice(0,2) }, 'high');
          }
          return origFn.apply(Math, args);
        };
      }
    }

    // ═══ 12. MEDIA DEVICES ═══
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      const origEnumDev = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
      navigator.mediaDevices.enumerateDevices = function() {
        log('media-devices', 'enumerateDevices', {}, 'critical');
        return origEnumDev();
      };
    }

    // ═══ 13. DOM PROBING / ADBLOCK DETECTION ═══
    const origCreateElement = document.createElement.bind(document);
    let createCount = 0;
    document.createElement = function(tag, ...args) {
      createCount++;
      const lTag = tag?.toLowerCase?.();
      if (['canvas', 'iframe', 'audio', 'video'].includes(lTag)) {
        log('dom-probe', 'createElement', { tag: lTag, count: createCount }, lTag === 'canvas' ? 'high' : 'medium');
      }
      return origCreateElement(tag, ...args);
    };

    // ═══ 14. CLIPBOARD ═══
    if (navigator.clipboard) {
      const origRead = navigator.clipboard.readText;
      if (origRead) {
        navigator.clipboard.readText = function() {
          log('clipboard', 'clipboard.readText', {}, 'critical');
          return origRead.call(navigator.clipboard);
        };
      }
      const origWrite = navigator.clipboard.writeText;
      if (origWrite) {
        navigator.clipboard.writeText = function(text) {
          log('clipboard', 'clipboard.writeText', { size: text?.length }, 'high');
          return origWrite.call(navigator.clipboard, text);
        };
      }
    }

    // ═══ 15. GEOLOCATION ═══
    if (navigator.geolocation) {
      const origGetPos = navigator.geolocation.getCurrentPosition;
      navigator.geolocation.getCurrentPosition = function(...args) {
        log('geolocation', 'getCurrentPosition', {}, 'critical');
        return origGetPos.apply(navigator.geolocation, args);
      };
      const origWatchPos = navigator.geolocation.watchPosition;
      navigator.geolocation.watchPosition = function(...args) {
        log('geolocation', 'watchPosition', {}, 'critical');
        return origWatchPos.apply(navigator.geolocation, args);
      };
    }

    // ═══ 16. SERVICE WORKER ═══
    if (navigator.serviceWorker) {
      const origSWRegister = navigator.serviceWorker.register;
      if (origSWRegister) {
        navigator.serviceWorker.register = function(url, ...args) {
          log('service-worker', 'sw.register', { url: String(url).slice(0, 100) }, 'critical');
          return origSWRegister.call(navigator.serviceWorker, url, ...args);
        };
      }
    }

    // ═══ 17. BATTERY API ═══
    if (navigator.getBattery) {
      const origGetBattery = navigator.getBattery.bind(navigator);
      navigator.getBattery = function() {
        log('hardware', 'getBattery', {}, 'high');
        return origGetBattery();
      };
    }

    // ═══ 18. DATE/TIMEZONE PROBING ═══
    const origDateTZO = Date.prototype.getTimezoneOffset;
    Date.prototype.getTimezoneOffset = function() {
      log('fingerprint', 'getTimezoneOffset', {}, 'medium');
      return origDateTZO.call(this);
    };

    const origIntlDTF = window.Intl?.DateTimeFormat;
    if (origIntlDTF) {
      const origResolved = origIntlDTF.prototype.resolvedOptions;
      origIntlDTF.prototype.resolvedOptions = function() {
        log('fingerprint', 'Intl.DateTimeFormat.resolvedOptions', {}, 'medium');
        return origResolved.call(this);
      };
    }

    // ═══ 19. Float32Array / Architecture detection ═══
    const origFloat32Set = Float32Array.prototype.set;
    // Lightweight — just note if buffer manipulation happens in fingerprint context

    // ═══ GLOBAL EXPORT ═══
    window.__SENTINEL_DATA__ = _sentinel;

    // Context map — track frames
    window.__SENTINEL_CONTEXT_MAP__ = [{
      type: 'page',
      url: location.href,
      origin: location.origin,
      timestamp: Date.now()
    }];

    console.log('[Sentinel v3] 🛡️ Maling Catcher active — monitoring ' + Object.keys({
      canvas:1, webgl:1, audio:1, 'font-detection':1, fingerprint:1, permissions:1,
      storage:1, screen:1, network:1, webrtc:1, 'perf-timing':1, 'math-fingerprint':1,
      'media-devices':1, 'dom-probe':1, clipboard:1, geolocation:1, 'service-worker':1,
      hardware:1
    }).length + ' categories');
  })();
  `;
}

module.exports = { getInterceptorScript };
