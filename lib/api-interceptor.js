/**
 * ApiInterceptor v6.2.0
 * 
 * Hooks browser APIs at the JavaScript level to capture what websites do.
 * 42 categories of monitoring — fingerprinting, exfiltration, honeypots, etc.
 * 
 * All hooks use WeakMap + property descriptor caching for minimal footprint.
 * Events are pushed to the EventPipeline for deduplication and analysis.
 */

'use strict';

class ApiInterceptor {
  constructor(pipeline) {
    this.pipeline = pipeline;
  }

  async inject(page, frameId = 'main') {
    const script = this._getInterceptorScript(frameId);
    try {
      await page.addInitScript(script);
    } catch (e) {
      console.error(`[ApiInterceptor] Inject failed for ${frameId}: ${e.message}`);
    }

    // Expose push function for events from page context
    try {
      await page.exposeFunction('__sentinel_push__', (evtJson) => {
        try {
          const evt = JSON.parse(evtJson);
          this.pipeline.push(evt);
        } catch (e) {}
      });
    } catch (e) {
      // Already exposed in this context (multi-frame scenario)
    }
  }

  _getInterceptorScript(frameId) {
    return `
      (() => {
        'use strict';
        if (window.__sentinel_interceptor_v62__) return;
        window.__sentinel_interceptor_v62__ = true;

        const FID = '${frameId}';
        const BOOT_TS = Date.now();
        let SEQ = 0;
        const SEEN = new Set();

        function emit(cat, api, risk, val, detail, dir) {
          const ts = Date.now();
          const key = cat + '|' + api + '|' + (detail || '').slice(0, 80);
          if (SEEN.has(key) && risk !== 'critical') return;
          SEEN.add(key);

          const evt = JSON.stringify({
            id: ++SEQ,
            ts: BOOT_TS,
            relTs: ts - BOOT_TS,
            cat: cat,
            api: api,
            risk: risk,
            val: val !== undefined ? String(val).slice(0, 200) : undefined,
            detail: detail ? String(detail).slice(0, 500) : undefined,
            src: 'unknown',
            dir: dir || 'call',
            fid: FID,
          });

          try {
            if (typeof window.__sentinel_push__ === 'function') {
              window.__sentinel_push__(evt);
            }
          } catch (e) {}
        }

        // ═══ Descriptor cache ═══
        const descCache = new WeakMap();
        function getDesc(obj, prop) {
          let cache = descCache.get(obj);
          if (!cache) { cache = {}; descCache.set(obj, cache); }
          if (!cache[prop]) {
            cache[prop] = Object.getOwnPropertyDescriptor(obj, prop) ||
                          Object.getOwnPropertyDescriptor(Object.getPrototypeOf(obj), prop);
          }
          return cache[prop];
        }

        function hookGetter(obj, prop, cat, api, risk) {
          const desc = getDesc(obj, prop);
          if (!desc || !desc.get) return;
          try {
            Object.defineProperty(obj, prop, {
              get: function() {
                const val = desc.get.call(this);
                emit(cat, api, risk, val, api + ' fingerprint read ' + JSON.stringify(val), 'response');
                return val;
              },
              set: desc.set,
              configurable: true,
              enumerable: desc.enumerable,
            });
          } catch (e) {}
        }

        function hookMethod(obj, method, cat, api, risk, detailFn) {
          const orig = obj[method];
          if (typeof orig !== 'function') return;
          obj[method] = function(...args) {
            const detail = detailFn ? detailFn(args) : (method + '(' + args.map(a => JSON.stringify(a)).join(',').slice(0,200) + ')');
            emit(cat, api, risk, undefined, detail, 'call');
            return orig.apply(this, args);
          };
          // Preserve toString
          obj[method].toString = () => orig.toString();
        }

        // ═══════════════════════════════════════
        // CATEGORY 1: Navigator Fingerprinting
        // ═══════════════════════════════════════
        const navProps = [
          'userAgent','appVersion','platform','product','vendor','language',
          'languages','hardwareConcurrency','deviceMemory','maxTouchPoints',
          'cookieEnabled','doNotTrack','plugins','mimeTypes','connection',
          'pdfViewerEnabled','webdriver',
        ];
        for (const prop of navProps) {
          hookGetter(navigator, prop, 'fingerprint', prop, 'high');
        }

        // ═══════════════════════════════════════
        // CATEGORY 2: Screen Fingerprinting
        // ═══════════════════════════════════════
        const screenProps = [
          'width','height','availWidth','availHeight','colorDepth','pixelDepth',
          'availLeft','availTop','orientation',
        ];
        for (const prop of screenProps) {
          hookGetter(screen, prop, 'screen', 'screen.' + prop, 'medium');
        }
        hookGetter(window, 'devicePixelRatio', 'screen', 'devicePixelRatio', 'medium');
        hookGetter(window, 'innerWidth', 'screen', 'innerWidth', 'medium');
        hookGetter(window, 'innerHeight', 'screen', 'innerHeight', 'medium');
        hookGetter(window, 'outerWidth', 'screen', 'outerWidth', 'medium');
        hookGetter(window, 'outerHeight', 'screen', 'outerHeight', 'medium');

        // ═══════════════════════════════════════
        // CATEGORY 3: Canvas Fingerprinting
        // ═══════════════════════════════════════
        const canvasProto = CanvasRenderingContext2D.prototype;
        hookMethod(canvasProto, 'fillText', 'canvas', 'fillText', 'high',
          args => 'Canvas text rendering' + String(args[0]).slice(0,50) + ', ' + args[1] + ', ' + args[2]);
        hookMethod(canvasProto, 'strokeText', 'canvas', 'strokeText', 'high',
          args => 'Canvas stroke text' + String(args[0]).slice(0,50));
        hookMethod(canvasProto, 'getImageData', 'canvas', 'getImageData', 'high',
          args => 'Canvas pixel readback' + args[0] + ', ' + args[1] + ', ' + args[2]);
        hookMethod(canvasProto, 'toDataURL', 'canvas', 'toDataURL', 'high',
          () => 'Canvas fingerprint extraction');
        hookMethod(canvasProto, 'isPointInPath', 'canvas', 'isPointInPath', 'high',
          args => 'Canvas point-in-path test' + args.join(', '));

        if (typeof HTMLCanvasElement !== 'undefined') {
          hookMethod(HTMLCanvasElement.prototype, 'toDataURL', 'canvas', 'toDataURL', 'high',
            () => 'Canvas fingerprint extraction');
          hookMethod(HTMLCanvasElement.prototype, 'toBlob', 'canvas', 'toBlob', 'high',
            () => 'Canvas blob extraction');
        }

        // ═══════════════════════════════════════
        // CATEGORY 4: WebGL Fingerprinting
        // ═══════════════════════════════════════
        for (const glProto of [WebGLRenderingContext?.prototype, WebGL2RenderingContext?.prototype].filter(Boolean)) {
          hookMethod(glProto, 'getParameter', 'webgl', 'getParameter', 'high',
            args => 'WebGL parameter read' + args[0]);
          hookMethod(glProto, 'getExtension', 'webgl', 'getExtension', 'high',
            args => 'WebGL extension query' + args[0]);
          hookMethod(glProto, 'getSupportedExtensions', 'webgl', 'getSupportedExtensions', 'high',
            () => 'WebGL supported extensions list');
          hookMethod(glProto, 'getShaderPrecisionFormat', 'webgl', 'getShaderPrecisionFormat', 'high',
            args => 'WebGL shader precision' + args[0] + ', ' + args[1]);
          hookMethod(glProto, 'readPixels', 'webgl', 'readPixels', 'high',
            args => 'WebGL pixel readback' + args[0] + ', ' + args[1] + ', ' + args[2]);
        }

        // ═══════════════════════════════════════
        // CATEGORY 5: Audio Fingerprinting
        // ═══════════════════════════════════════
        if (typeof AudioContext !== 'undefined' || typeof webkitAudioContext !== 'undefined') {
          const ACProto = (typeof AudioContext !== 'undefined' ? AudioContext : webkitAudioContext).prototype;
          hookMethod(ACProto, 'createOscillator', 'audio', 'createOscillator', 'critical',
            () => 'Audio oscillator creation');
          hookMethod(ACProto, 'createDynamicsCompressor', 'audio', 'createDynamicsCompressor', 'critical',
            () => 'Audio compressor creation');
          hookMethod(ACProto, 'createAnalyser', 'audio', 'createAnalyser', 'high',
            () => 'Audio analyser creation');

          if (typeof OfflineAudioContext !== 'undefined') {
            hookMethod(OfflineAudioContext.prototype, 'startRendering', 'audio', 'startRendering', 'critical',
              () => 'Audio fingerprint rendering');
          }
        }

        // ═══════════════════════════════════════
        // CATEGORY 6: WebRTC Fingerprinting
        // ═══════════════════════════════════════
        if (typeof RTCPeerConnection !== 'undefined') {
          const rtcProto = RTCPeerConnection.prototype;
          const origRTC = RTCPeerConnection;
          window.RTCPeerConnection = function(...args) {
            emit('webrtc', 'RTCPeerConnection', 'critical', undefined,
              'ICE config ' + JSON.stringify(args[0]).slice(0,300), 'call');
            const pc = new origRTC(...args);
            const origOnIce = Object.getOwnPropertyDescriptor(rtcProto, 'onicecandidate');
            if (origOnIce) {
              Object.defineProperty(pc, 'onicecandidate', {
                set: function(fn) {
                  origOnIce.set.call(this, function(evt) {
                    if (evt.candidate) {
                      emit('webrtc', 'onicecandidate', 'critical', undefined,
                        'ICE candidate ' + evt.candidate.candidate.slice(0,200), 'response');
                    }
                    if (fn) fn.call(this, evt);
                  });
                },
                get: origOnIce.get,
                configurable: true,
              });
            }
            return pc;
          };
          window.RTCPeerConnection.prototype = rtcProto;
          window.RTCPeerConnection.toString = () => 'function RTCPeerConnection() { [native code] }';

          hookMethod(rtcProto, 'createDataChannel', 'webrtc', 'createDataChannel', 'critical',
            () => 'Data channel created');
          hookMethod(rtcProto, 'createOffer', 'webrtc', 'createOffer', 'high',
            () => 'SDP offer creation');
        }

        // ═══════════════════════════════════════
        // CATEGORY 7: Font Detection
        // ═══════════════════════════════════════
        hookMethod(Element.prototype, 'getBoundingClientRect', 'font-detection', 'getBoundingClientRect', 'critical',
          () => 'Font width/height probe');
        hookMethod(Element.prototype, 'getClientRects', 'font-detection', 'getClientRects', 'high',
          () => 'Font client rects probe');

        // ═══════════════════════════════════════
        // CATEGORY 8: Storage
        // ═══════════════════════════════════════
        hookMethod(Storage.prototype, 'setItem', 'storage', 'localStorage.setItem', 'medium',
          args => 'localStorage write ' + args[0]);
        hookMethod(Storage.prototype, 'getItem', 'storage', 'localStorage.getItem', 'medium',
          args => 'localStorage read ' + args[0]);

        // Cookie monitoring
        const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
        if (cookieDesc) {
          Object.defineProperty(document, 'cookie', {
            get: function() {
              const val = cookieDesc.get.call(this);
              emit('storage', 'cookie read', 'medium', undefined, 'document.cookie read');
              return val;
            },
            set: function(v) {
              emit('storage', 'cookie write', 'high', undefined,
                'document.cookie write tracking cookie creation ' + String(v).slice(0,200));
              return cookieDesc.set.call(this, v);
            },
            configurable: true,
          });
        }

        // IndexedDB
        if (typeof indexedDB !== 'undefined') {
          hookMethod(indexedDB, 'open', 'storage', 'indexedDB.open', 'medium',
            args => 'IndexedDB open ' + args[0]);
        }

        // ═══════════════════════════════════════
        // CATEGORY 9: Network Exfiltration
        // ═══════════════════════════════════════
        // fetch
        const origFetch = window.fetch;
        window.fetch = function(...args) {
          const url = typeof args[0] === 'string' ? args[0] : args[0]?.url;
          const method = args[1]?.method || 'GET';
          const body = args[1]?.body;
          if (method === 'POST' && body) {
            emit('exfiltration', 'fetch', 'critical', undefined,
              'POST data ' + String(body).slice(0,300) + ' ' + url, 'call');
          }
          return origFetch.apply(this, args);
        };
        window.fetch.toString = () => 'function fetch() { [native code] }';

        // XMLHttpRequest
        const origXHR = XMLHttpRequest.prototype.send;
        const origXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...rest) {
          this.__sentinel_url = url;
          this.__sentinel_method = method;
          return origXHROpen.call(this, method, url, ...rest);
        };
        XMLHttpRequest.prototype.send = function(body) {
          if (body && this.__sentinel_method !== 'GET') {
            emit('exfiltration', 'XMLHttpRequest.send', 'critical', undefined,
              'XHR data ' + String(body).slice(0,300) + ' ' + (this.__sentinel_url || ''), 'call');
          }
          return origXHR.call(this, body);
        };

        // WebSocket
        const origWS = window.WebSocket;
        window.WebSocket = function(url, ...args) {
          emit('exfiltration', 'WebSocket', 'critical', undefined,
            'WS connection ' + url, 'call');
          return new origWS(url, ...args);
        };
        window.WebSocket.prototype = origWS.prototype;
        window.WebSocket.toString = () => 'function WebSocket() { [native code] }';

        // sendBeacon
        hookMethod(navigator, 'sendBeacon', 'exfiltration', 'sendBeacon', 'critical',
          args => 'Beacon data exfiltration' + args[0]);

        // Image beacon
        const origImgSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
        if (origImgSrc) {
          Object.defineProperty(HTMLImageElement.prototype, 'src', {
            set: function(v) {
              if (v && typeof v === 'string' && (v.startsWith('http') || v.startsWith('//'))) {
                emit('exfiltration', 'Image.src', 'high', undefined,
                  'Image beacon ' + v.slice(0,300), 'call');
              }
              return origImgSrc.set.call(this, v);
            },
            get: origImgSrc.get,
            configurable: true,
          });
        }

        // ═══════════════════════════════════════
        // CATEGORY 10: DOM Probing
        // ═══════════════════════════════════════
        hookMethod(document, 'createElement', 'dom-probe', 'createElement', 'medium',
          args => 'createElement ' + args[0]);
        hookMethod(document, 'querySelector', 'dom-probe', 'querySelector', 'medium',
          args => 'querySelector ' + args[0]);
        hookMethod(document, 'querySelectorAll', 'dom-probe', 'querySelectorAll', 'medium',
          args => 'querySelectorAll ' + args[0]);
        hookMethod(document, 'getElementById', 'dom-probe', 'getElementById', 'medium',
          args => 'getElementById ' + args[0]);

        // ═══════════════════════════════════════
        // CATEGORY 11: CSS Fingerprinting
        // ═══════════════════════════════════════
        hookMethod(window, 'getComputedStyle', 'css-fingerprint', 'getComputedStyle', 'medium',
          () => 'CSS computed style probe');
        if (typeof CSS !== 'undefined' && CSS.supports) {
          hookMethod(CSS, 'supports', 'css-fingerprint', 'CSS.supports', 'medium',
            args => 'CSS.supports ' + args.join(', '));
        }
        hookMethod(window, 'matchMedia', 'css-fingerprint', 'matchMedia', 'medium',
          args => 'matchMedia ' + args[0]);

        // ═══════════════════════════════════════
        // CATEGORY 12: Performance Timing
        // ═══════════════════════════════════════
        if (window.performance) {
          hookMethod(performance, 'now', 'perf-timing', 'performance.now', 'medium',
            () => 'High-res timer probe');
          hookMethod(performance, 'getEntries', 'perf-timing', 'getEntries', 'medium',
            () => 'Resource timing enumeration');
          hookMethod(performance, 'getEntriesByType', 'perf-timing', 'getEntriesByType', 'medium',
            args => 'Resource timing by type ' + args[0]);
          hookMethod(performance, 'getEntriesByName', 'perf-timing', 'getEntriesByName', 'medium',
            args => 'Resource timing by name ' + args[0]);
          if (performance.mark) {
            hookMethod(performance, 'mark', 'perf-timing', 'performance.mark', 'medium',
              args => 'Performance mark ' + args[0]);
          }
          if (performance.measure) {
            hookMethod(performance, 'measure', 'perf-timing', 'performance.measure', 'medium',
              args => 'Performance measure ' + args[0]);
          }
        }

        // ═══════════════════════════════════════
        // CATEGORY 13: Math Fingerprinting
        // ═══════════════════════════════════════
        for (const fn of ['sin','cos','tan','asin','acos','atan','atan2','log','exp','sqrt','pow']) {
          const orig = Math[fn];
          if (typeof orig === 'function') {
            Math[fn] = function(...args) {
              const result = orig.apply(this, args);
              emit('math-fingerprint', 'Math.' + fn, 'medium', result,
                'Math.' + fn + '(' + args.join(',') + ')', 'response');
              return result;
            };
            Math[fn].toString = () => orig.toString();
          }
        }

        // ═══════════════════════════════════════
        // CATEGORY 14: Intl Fingerprinting
        // ═══════════════════════════════════════
        if (typeof Intl !== 'undefined') {
          hookMethod(Intl.DateTimeFormat.prototype, 'resolvedOptions', 'intl-fingerprint', 'resolvedOptions', 'medium',
            () => 'Intl.DateTimeFormat.resolvedOptions');
        }

        // ═══════════════════════════════════════
        // CATEGORY 15: Encoding
        // ═══════════════════════════════════════
        if (typeof TextEncoder !== 'undefined') {
          hookMethod(TextEncoder.prototype, 'encode', 'encoding', 'encode', 'low',
            args => 'TextEncoder probe' + (args[0]||'').slice(0,30));
        }

        // ═══════════════════════════════════════
        // CATEGORY 16: Visualization (Canvas2D + requestAnimationFrame)
        // ═══════════════════════════════════════
        hookMethod(canvasProto, 'fillRect', 'visualization', 'fillRect', 'medium',
          args => 'Canvas fill ' + args.join(','));
        hookMethod(canvasProto, 'arc', 'visualization', 'arc', 'medium',
          args => 'Canvas arc');
        const origRAF = window.requestAnimationFrame;
        let rafCount = 0;
        window.requestAnimationFrame = function(cb) {
          if (++rafCount <= 5) emit('visualization', 'rAF', 'medium', undefined, 'requestAnimationFrame');
          return origRAF.call(this, cb);
        };

        // ═══════════════════════════════════════
        // CATEGORY 17: Event Monitoring
        // ═══════════════════════════════════════
        const origAEL = EventTarget.prototype.addEventListener;
        const monitoredEvents = new Set([
          'mousemove','mousedown','mouseup','click','keydown','keyup',
          'touchstart','touchend','touchmove','scroll','wheel','resize',
          'focus','blur','visibilitychange','deviceorientation','devicemotion',
          'pointerdown','pointerup','pointermove',
        ]);
        EventTarget.prototype.addEventListener = function(type, listener, opts) {
          if (monitoredEvents.has(type)) {
            emit('event-monitoring', 'addEventListener', 'medium', undefined,
              'Event listener: ' + type, 'call');
          }
          return origAEL.call(this, type, listener, opts);
        };

        // ═══════════════════════════════════════
        // CATEGORY 18: Network Info
        // ═══════════════════════════════════════
        if (navigator.connection) {
          for (const prop of ['effectiveType','downlink','rtt','saveData','type']) {
            hookGetter(navigator.connection, prop, 'network', 'connection.' + prop, 'medium');
          }
        }

        // ═══════════════════════════════════════
        // CATEGORY 19: Honeypot Detection
        // ═══════════════════════════════════════
        const honeypots = [
          ['__webdriver_evaluate','seleniumevaluate','Selenium evaluate trap accessed'],
          ['_Selenium_IDE_Recorder','SeleniumIDERecorder','Selenium trap accessed'],
          ['__nightmare','nightmare','Nightmare trap accessed'],
          ['__phantomas','phantomas','Phantomas trap accessed'],
          ['callPhantom','callPhantom','PhantomJS trap accessed'],
          ['_phantom','phantom','PhantomJS internal trap accessed'],
          ['domAutomation','domAutomation','Chrome automation trap accessed'],
          ['domAutomationController','domAutomationController','Chrome devtools automation trap'],
        ];
        for (const [prop, api, detail] of honeypots) {
          try {
            Object.defineProperty(window, prop, {
              get: () => { emit('honeypot', api, 'critical', undefined, detail); return undefined; },
              set: () => { emit('honeypot', api, 'critical', undefined, detail + ' (write)'); },
              configurable: true,
            });
          } catch (e) {}
        }

        // ═══════════════════════════════════════
        // CATEGORY 20: PostMessage Exfiltration
        // ═══════════════════════════════════════
        const origPostMessage = window.postMessage;
        window.postMessage = function(msg, ...args) {
          emit('postmessage-exfil', 'postMessage', 'medium', undefined,
            'postMessage ' + JSON.stringify(msg).slice(0,200), 'call');
          return origPostMessage.call(this, msg, ...args);
        };

        // ═══════════════════════════════════════
        // CATEGORY 21: Speech API
        // ═══════════════════════════════════════
        if (typeof speechSynthesis !== 'undefined') {
          hookMethod(speechSynthesis, 'getVoices', 'speech', 'getVoices', 'high',
            () => 'Voice enumeration fingerprint');
        }

        // ═══════════════════════════════════════
        // CATEGORY 22: System
        // ═══════════════════════════════════════
        if (typeof Date !== 'undefined') {
          hookMethod(Date.prototype, 'getTimezoneOffset', 'system', 'getTimezoneOffset', 'info',
            () => 'Timezone offset probe');
        }

        // Notify sentinel that injection is active
        emit('system', 'sentinel-boot', 'info', undefined, 'ApiInterceptor v6.2.0 active in ' + FID);

      })();
    `;
  }
}

module.exports = { ApiInterceptor };
