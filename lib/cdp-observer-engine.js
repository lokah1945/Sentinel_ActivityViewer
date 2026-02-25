// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — CDP OBSERVER ENGINE
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - FROM v6.4: All CDP domain collectors preserved
//   - REG-018: Promise.allSettled for CDP enable
//   - REG-026: All 6 domains enabled (Network, Page, Security, Console, DOM, Performance)
//   - Also: Runtime domain for error capture
//   - Network: request, response, websocket, error
//   - Page: frame lifecycle
//   - Security: state changes
//   - Console: browser logs
//   - DOM: mutations (childNodeCountUpdated, attributeModified)
//   - Performance: metrics
//   - Runtime: exceptions
//   - Library detection from network URLs
// ═══════════════════════════════════════════════════════════════

'use strict';

var signatureDb = require('./signature-db');

function CdpObserverEngine(pipeline, cdp) {
  this._pipeline = pipeline;
  this._cdp = cdp;
  this._frames = [];
  this._handlers = [];
}

CdpObserverEngine.prototype.start = async function() {
  var self = this;
  var cdp = this._cdp;
  var p = this._pipeline;

  // REG-026: Enable all domains
  // REG-018: Promise.allSettled for safe enable
  await Promise.allSettled([
    cdp.send('Network.enable', { maxTotalBufferSize: 10000000, maxResourceBufferSize: 5000000 }),
    cdp.send('Page.enable'),
    cdp.send('Security.enable'),
    cdp.send('Console.enable'),
    cdp.send('DOM.enable'),
    cdp.send('Performance.enable', { timeDomain: 'timeTicks' }),
    cdp.send('Runtime.enable')
  ]);

  // ─── Network.requestWillBeSent ───
  this._on('Network.requestWillBeSent', function(params) {
    var url = params.request ? params.request.url : '';
    var method = params.request ? params.request.method : '';
    p.pushCDP({
      cat: 'network-request',
      api: method,
      risk: 'info',
      detail: method + ' ' + url.slice(0, 500),
      meta: { url: url, type: params.type, initiator: params.initiator ? params.initiator.type : '' }
    });
    // Library detection
    var lib = signatureDb.matchUrl(url);
    if (lib) {
      p.pushCDP({ cat: 'library-detected', api: lib.name, risk: 'high', detail: 'Library: ' + lib.name + ' v' + (lib.version || '?') + ' (' + lib.category + ')' });
    }
    // Cookie detection from request headers
    if (params.request && params.request.headers) {
      var cookie = params.request.headers['Cookie'] || params.request.headers['cookie'];
      if (cookie) {
        p.pushCDP({ cat: 'cookie-sent', api: 'request-cookie', risk: 'medium', detail: 'Cookie sent (' + cookie.length + ' chars): ' + url.slice(0, 200) });
      }
    }
  });

  // ─── Network.responseReceived ───
  this._on('Network.responseReceived', function(params) {
    var url = params.response ? params.response.url : '';
    var status = params.response ? params.response.status : 0;
    p.pushCDP({
      cat: 'network-response',
      api: String(status),
      risk: status >= 400 ? 'high' : 'info',
      detail: status + ' ' + url.slice(0, 500),
      meta: { url: url, mimeType: params.response ? params.response.mimeType : '' }
    });
    // Set-Cookie detection from response
    if (params.response && params.response.headers) {
      var sc = params.response.headers['Set-Cookie'] || params.response.headers['set-cookie'];
      if (sc) {
        p.pushCDP({ cat: 'cookie-set', api: 'response-set-cookie', risk: 'medium', detail: 'Set-Cookie from: ' + url.slice(0, 200) });
      }
    }
  });

  // ─── Network.webSocketCreated ───
  this._on('Network.webSocketCreated', function(params) {
    p.pushCDP({ cat: 'websocket', api: 'created', risk: 'high', detail: 'WebSocket: ' + (params.url || '').slice(0, 300) });
  });

  // ─── Network.loadingFailed ───
  this._on('Network.loadingFailed', function(params) {
    p.pushCDP({ cat: 'network-error', api: 'loadingFailed', risk: 'medium', detail: params.errorText + ' (' + params.type + ')' });
  });

  // ─── Page.frameAttached ───
  this._on('Page.frameAttached', function(params) {
    self._frames.push({ id: params.frameId, parentId: params.parentFrameId, type: 'attached' });
    p.pushCDP({ cat: 'frame-lifecycle', api: 'frameAttached', risk: 'info', detail: 'Frame attached: ' + params.frameId });
  });

  // ─── Page.frameNavigated ───
  this._on('Page.frameNavigated', function(params) {
    var url = params.frame ? params.frame.url : '';
    self._frames.push({ id: params.frame ? params.frame.id : '', url: url, type: 'navigated' });
    p.pushCDP({ cat: 'frame-lifecycle', api: 'frameNavigated', risk: 'info', detail: 'Frame navigated: ' + url.slice(0, 300) });
  });

  // ─── Page.frameDetached ───
  this._on('Page.frameDetached', function(params) {
    p.pushCDP({ cat: 'frame-lifecycle', api: 'frameDetached', risk: 'info', detail: 'Frame detached: ' + params.frameId });
  });

  // ─── Security.securityStateChanged ───
  this._on('Security.securityStateChanged', function(params) {
    p.pushCDP({ cat: 'security-state', api: params.securityState || 'unknown', risk: params.securityState === 'insecure' ? 'high' : 'info', detail: 'Security: ' + (params.securityState || '') + ' - ' + (params.summary || '') });
  });

  // ─── Console.messageAdded ───
  this._on('Console.messageAdded', function(params) {
    var msg = params.message || {};
    p.pushCDP({ cat: 'browser-log', api: msg.level || 'log', risk: msg.level === 'error' ? 'high' : 'info', detail: (msg.text || '').slice(0, 500) });
  });

  // ─── DOM.childNodeCountUpdated ───
  this._on('DOM.childNodeCountUpdated', function(params) {
    p.pushCDP({ cat: 'dom-mutation', api: 'childNodeCountUpdated', risk: 'info', detail: 'Node ' + params.nodeId + ' children: ' + params.childNodeCount });
  });

  // ─── DOM.attributeModified ───
  this._on('DOM.attributeModified', function(params) {
    p.pushCDP({ cat: 'dom-mutation', api: 'attributeModified', risk: 'info', detail: 'Node ' + params.nodeId + ': ' + params.name + '=' + (params.value || '').slice(0, 100) });
  });

  // ─── Performance.metrics ───
  this._on('Performance.metrics', function(params) {
    p.pushCDP({ cat: 'performance-metrics', api: 'metrics', risk: 'info', detail: 'Performance metrics: ' + (params.title || '') });
  });

  // ─── Runtime.exceptionThrown ───
  this._on('Runtime.exceptionThrown', function(params) {
    var ex = params.exceptionDetails || {};
    var text = ex.text || '';
    if (ex.exception && ex.exception.description) text = ex.exception.description;
    p.pushCDP({ cat: 'runtime-error', api: 'exception', risk: 'medium', detail: text.slice(0, 500) });
  });
};

CdpObserverEngine.prototype._on = function(event, handler) {
  this._cdp.on(event, handler);
  this._handlers.push({ event: event, handler: handler });
};

CdpObserverEngine.prototype.stop = async function() {
  for (var i = 0; i < this._handlers.length; i++) {
    try { this._cdp.off(this._handlers[i].event, this._handlers[i].handler); } catch(e) {}
  }
  this._handlers = [];
};

CdpObserverEngine.prototype.getFrames = function() {
  return this._frames.slice();
};

module.exports = { CdpObserverEngine: CdpObserverEngine };
