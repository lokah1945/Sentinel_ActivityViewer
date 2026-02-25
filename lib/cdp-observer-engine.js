// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — CDP OBSERVER ENGINE
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - FROM v6.4: Full CDP observer engine (PRESERVED INTACT)
//   - FIX: pushCdp calls aligned with unified pipeline
//   - REG-026: All CDP collectors enabled
//   - REG-028: rebrowser-patched core compatible
//   - Domains: Network, Page, Security, Console, DOM, Performance
//
// LAST HISTORY LOG:
//   v6.4.0: cdp-observer-engine.js — CDP-only observer
//   v7.0.0: Preserved + pipeline alignment
// ═══════════════════════════════════════════════════════════════

'use strict';

var FINGERPRINT_SIGNATURES = {
  'fingerprintjs': ['FingerprintJS', 'fpPromise', 'fp.get', 'requestIdleCallback', 'getVisitorId'],
  'creepjs': ['creepworker', 'getPhantomDark', 'getFingerprint', 'lieDetector', 'getPrototypeLies'],
  'botd': ['BotD', 'BotdError', 'detect-bot', 'automationTool', 'searchBotDetector'],
  'evercookie': ['evercookie', 'ievercookie', 'window.name', 'userData', 'silverlight'],
  'browserscan': ['browserscan', 'BrowserScan', '/api/fp', '/api/detect'],
  'canvas-fingerprint': ['toDataURL', 'canvas2d', 'getImageData', 'fillText', 'arc('],
  'webgl-fingerprint': ['webgl', 'WEBGL_debug_renderer_info', 'getParameter', 'getSupportedExtensions'],
  'recaptcha': ['recaptcha', 'grecaptcha', 'www.google.com/recaptcha'],
  'hcaptcha': ['hcaptcha', 'hcaptcha.com'],
  'datadome': ['datadome', 'DataDome', 'dd.js', '/captcha/']
};

class CdpObserverEngine {
  constructor(pipeline, cdpSession) {
    this.pipeline = pipeline;
    this.cdp = cdpSession;
    this.requestMap = new Map();
    this.frameMap = new Map();
    this.stats = { requests: 0, responses: 0, frames: 0, scripts: 0, libs: 0 };
  }

  async start() {
    var self = this;

    // ─── Enable CDP Domains (REG-026: ALL enabled) ───
    await Promise.allSettled([
      self.cdp.send('Network.enable', { maxTotalBufferSize: 10 * 1024 * 1024 }),
      self.cdp.send('Page.enable'),
      self.cdp.send('Security.enable'),
      self.cdp.send('Console.enable'),
      self.cdp.send('DOM.enable'),
      self.cdp.send('Performance.enable', { timeDomain: 'timeTicks' }),
      self.cdp.send('Runtime.enable')
    ]);

    // ─── NETWORK: Request ───
    self.cdp.on('Network.requestWillBeSent', function(params) {
      self.stats.requests++;
      var req = params.request || {};
      var init = params.initiator || {};
      self.requestMap.set(params.requestId, {
        url: req.url,
        method: req.method,
        type: params.type,
        initiator: init.type,
        ts: Date.now()
      });

      var bodyPreview = '';
      if (req.postData) bodyPreview = req.postData.slice(0, 300);

      self.pipeline.pushCdp({
        cat: 'network-request',
        api: req.method || 'GET',
        risk: bodyPreview.length > 50 ? 'high' : 'info',
        detail: (req.method || 'GET') + ' ' + (req.url || '').slice(0, 300),
        meta: {
          requestId: params.requestId,
          type: params.type,
          initiator: init.type,
          postData: bodyPreview
        }
      });

      // Exfiltration detection: POST with body
      if (req.method === 'POST' && bodyPreview.length > 0) {
        self.pipeline.pushCdp({
          cat: 'exfiltration',
          api: 'POST',
          risk: 'high',
          detail: 'POST ' + (req.url || '').slice(0, 200) + ' body=' + bodyPreview.slice(0, 100),
          meta: { requestId: params.requestId, bodyLength: bodyPreview.length }
        });
      }
    });

    // ─── NETWORK: Response ───
    self.cdp.on('Network.responseReceived', function(params) {
      self.stats.responses++;
      var resp = params.response || {};
      var reqData = self.requestMap.get(params.requestId) || {};

      self.pipeline.pushCdp({
        cat: 'network-response',
        api: String(resp.status || 0),
        risk: resp.status >= 400 ? 'high' : 'info',
        detail: resp.status + ' ' + (resp.url || '').slice(0, 300),
        meta: {
          requestId: params.requestId,
          status: resp.status,
          mimeType: resp.mimeType,
          size: resp.encodedDataLength,
          protocol: resp.protocol,
          ip: resp.remoteIPAddress,
          type: params.type
        }
      });

      // Cookie tracking from response
      var setCookies = (resp.headers || {})['set-cookie'] || (resp.headers || {})['Set-Cookie'];
      if (setCookies) {
        self.pipeline.pushCdp({
          cat: 'cookie-set',
          api: 'Set-Cookie',
          risk: 'high',
          detail: String(setCookies).slice(0, 200),
          meta: { requestId: params.requestId }
        });
      }

      // Library detection via URL patterns
      var url = resp.url || '';
      self._detectLibrary(url, params.requestId, params.type);
    });

    // ─── NETWORK: Request Extra Info (cookies sent) ───
    self.cdp.on('Network.requestWillBeSentExtraInfo', function(params) {
      var cookies = (params.headers || {}).cookie || (params.headers || {}).Cookie;
      if (cookies) {
        self.pipeline.pushCdp({
          cat: 'cookie-sent',
          api: 'Cookie',
          risk: 'medium',
          detail: 'Cookies: ' + String(cookies).slice(0, 200),
          meta: { requestId: params.requestId }
        });
      }
    });

    // ─── NETWORK: Loading Failed ───
    self.cdp.on('Network.loadingFailed', function(params) {
      self.pipeline.pushCdp({
        cat: 'network-error',
        api: params.type || 'unknown',
        risk: params.blockedReason ? 'high' : 'medium',
        detail: (params.errorText || 'Failed') + ' ' + (params.blockedReason || ''),
        meta: { requestId: params.requestId, canceled: params.canceled }
      });
    });

    // ─── NETWORK: WebSocket ───
    self.cdp.on('Network.webSocketCreated', function(params) {
      self.pipeline.pushCdp({
        cat: 'websocket',
        api: 'created',
        risk: 'critical',
        detail: 'WS: ' + (params.url || '').slice(0, 200),
        meta: { requestId: params.requestId }
      });
    });
    self.cdp.on('Network.webSocketFrameSent', function(params) {
      self.pipeline.pushCdp({
        cat: 'websocket',
        api: 'frame-sent',
        risk: 'high',
        detail: 'WS sent: ' + ((params.response || {}).payloadData || '').slice(0, 100),
        meta: { requestId: params.requestId }
      });
    });
    self.cdp.on('Network.webSocketFrameReceived', function(params) {
      self.pipeline.pushCdp({
        cat: 'websocket',
        api: 'frame-received',
        risk: 'medium',
        detail: 'WS recv: ' + ((params.response || {}).payloadData || '').slice(0, 100),
        meta: { requestId: params.requestId }
      });
    });
    self.cdp.on('Network.webSocketClosed', function(params) {
      self.pipeline.pushCdp({
        cat: 'websocket',
        api: 'closed',
        risk: 'info',
        detail: 'WS closed',
        meta: { requestId: params.requestId }
      });
    });

    // ─── PAGE: Frame Lifecycle ───
    self.cdp.on('Page.frameAttached', function(params) {
      self.stats.frames++;
      self.pipeline.pushCdp({
        cat: 'frame-lifecycle',
        api: 'frameAttached',
        risk: 'info',
        detail: 'Frame attached: ' + params.frameId + ' parent=' + (params.parentFrameId || 'main'),
        meta: { frameId: params.frameId, parentFrameId: params.parentFrameId }
      });
    });
    self.cdp.on('Page.frameNavigated', function(params) {
      var frame = params.frame || {};
      self.frameMap.set(frame.id, { url: frame.url, name: frame.name });
      self.pipeline.pushCdp({
        cat: 'frame-lifecycle',
        api: 'frameNavigated',
        risk: 'info',
        detail: 'Frame navigated: ' + (frame.url || '').slice(0, 200),
        meta: { frameId: frame.id, url: frame.url }
      });
    });
    self.cdp.on('Page.frameDetached', function(params) {
      self.pipeline.pushCdp({
        cat: 'frame-lifecycle',
        api: 'frameDetached',
        risk: 'info',
        detail: 'Frame detached: ' + params.frameId,
        meta: { frameId: params.frameId, reason: params.reason }
      });
    });
    self.cdp.on('Page.frameStartedLoading', function(params) {
      self.pipeline.pushCdp({
        cat: 'frame-lifecycle',
        api: 'frameStartedLoading',
        risk: 'info',
        detail: 'Frame loading: ' + params.frameId,
        meta: { frameId: params.frameId }
      });
    });
    self.cdp.on('Page.frameStoppedLoading', function(params) {
      self.pipeline.pushCdp({
        cat: 'frame-lifecycle',
        api: 'frameStoppedLoading',
        risk: 'info',
        detail: 'Frame loaded: ' + params.frameId,
        meta: { frameId: params.frameId }
      });
    });

    // ─── PAGE: JavaScript Dialog ───
    self.cdp.on('Page.javascriptDialogOpening', function(params) {
      self.pipeline.pushCdp({
        cat: 'browser-dialog',
        api: params.type,
        risk: 'high',
        detail: params.type + ': ' + (params.message || '').slice(0, 200),
        meta: { type: params.type, hasBrowserHandler: params.hasBrowserHandler }
      });
    });

    // ─── PAGE: Download ───
    self.cdp.on('Page.downloadWillBegin', function(params) {
      self.pipeline.pushCdp({
        cat: 'download',
        api: 'downloadBegin',
        risk: 'critical',
        detail: 'Download: ' + (params.url || '').slice(0, 200),
        meta: { guid: params.guid, suggestedFilename: params.suggestedFilename }
      });
    });

    // ─── SECURITY: TLS State ───
    self.cdp.on('Security.visibleSecurityStateChanged', function(params) {
      var state = params.visibleSecurityState || {};
      var cert = state.certificateSecurityState || {};
      self.pipeline.pushCdp({
        cat: 'security-state',
        api: 'tls-state',
        risk: state.securityState === 'insecure' ? 'critical' : cert.obsoleteSslProtocol ? 'high' : 'low',
        detail: JSON.stringify({
          securityState: state.securityState,
          protocol: cert.protocol,
          cipher: cert.cipher,
          issuer: cert.issuer
        }).slice(0, 300),
        meta: cert
      });
    });
    self.cdp.on('Security.certificateError', function(params) {
      self.pipeline.pushCdp({
        cat: 'security-state',
        api: 'cert-error',
        risk: 'critical',
        detail: 'Cert error: ' + params.errorType + ' ' + (params.requestURL || '').slice(0, 200)
      });
    });

    // ─── CONSOLE ───
    self.cdp.on('Console.messageAdded', function(params) {
      var msg = params.message || {};
      self.pipeline.pushCdp({
        cat: 'browser-log',
        api: msg.level || 'log',
        risk: msg.level === 'error' ? 'high' : msg.level === 'warning' ? 'medium' : 'info',
        detail: (msg.text || '').slice(0, 300),
        meta: { source: msg.source, url: msg.url, line: msg.line }
      });
    });

    // ─── DOM: Document Updated ───
    self.cdp.on('DOM.documentUpdated', function() {
      self.pipeline.pushCdp({
        cat: 'dom-mutation',
        api: 'documentUpdated',
        risk: 'info',
        detail: 'DOM document updated'
      });
    });

    // ─── PERFORMANCE: Metrics ───
    self.cdp.on('Performance.metrics', function(params) {
      var metrics = {};
      (params.metrics || []).forEach(function(m) { metrics[m.name] = m.value; });
      self.pipeline.pushCdp({
        cat: 'performance-metrics',
        api: 'metrics',
        risk: 'info',
        detail: JSON.stringify(metrics).slice(0, 300),
        meta: metrics
      });
    });

    // ─── RUNTIME: Exception ───
    self.cdp.on('Runtime.exceptionThrown', function(params) {
      var ex = params.exceptionDetails || {};
      self.pipeline.pushCdp({
        cat: 'runtime-error',
        api: 'exception',
        risk: 'high',
        detail: (ex.text || '') + ' ' + ((ex.exception || {}).description || '').slice(0, 200)
      });
    });
  }

  _detectLibrary(url, requestId, type) {
    var urlLower = url.toLowerCase();
    var self = this;
    Object.keys(FINGERPRINT_SIGNATURES).forEach(function(libName) {
      var patterns = FINGERPRINT_SIGNATURES[libName];
      var matched = [];
      for (var i = 0; i < patterns.length; i++) {
        if (urlLower.indexOf(patterns[i].toLowerCase()) !== -1) {
          matched.push(patterns[i]);
        }
      }
      if (matched.length > 0) {
        self.stats.libs++;
        self.pipeline.pushCdp({
          cat: 'library-detected',
          api: libName,
          risk: 'high',
          detail: 'Library: ' + libName + ' patterns=[' + matched.join(', ') + ']',
          meta: { library: libName, url: url.slice(0, 200), patterns: matched, requestId: requestId }
        });
      }
    });
  }

  getFrames() {
    var frames = [];
    this.frameMap.forEach(function(val, key) {
      frames.push({ id: key, url: val.url, name: val.name });
    });
    return frames;
  }

  getStats() {
    return this.stats;
  }
}

module.exports = { CdpObserverEngine };
