// ═══════════════════════════════════════════════════════════════
//  SENTINEL v6.0.0 — CDP NETWORK COLLECTOR
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.0.0 (2026-02-25):
//   - NEW: CDP Network.* lifecycle monitoring (request/response/extra info)
//   - NEW: WebSocket frame capture (sent + received + created + closed)
//   - NEW: EventSource (SSE) message capture
//   - NEW: Loading failed / CORS error capture
//   - NEW: Cookie tracking from request/response extra info
//   - NEW: TLS/Security info from response headers
//   - NEW: Initiator chain tracking (WHO started this request)
//   - NEW: Redirect chain tracking
//   - NEW: DNS timing from response.timing
//
// LAST HISTORY LOG:
//   v6.0.0: Initial creation — replaces page.on('request'/'response') from v5
// ═══════════════════════════════════════════════════════════════

class CDPNetworkCollector {
  constructor(cdpSession, pipeline, options) {
    this.cdp = cdpSession;
    this.pipeline = pipeline;
    this.verbose = (options && options.verbose) || false;
    this.requestMap = new Map();
  }

  async initialize() {
    await this.cdp.send('Network.enable', {
      maxTotalBufferSize: 10000000,
      maxResourceBufferSize: 5000000
    });

    var self = this;

    this.cdp.on('Network.requestWillBeSent', function(params) {
      self._onRequestWillBeSent(params);
    });

    this.cdp.on('Network.requestWillBeSentExtraInfo', function(params) {
      self._onRequestExtraInfo(params);
    });

    this.cdp.on('Network.responseReceived', function(params) {
      self._onResponseReceived(params);
    });

    this.cdp.on('Network.responseReceivedExtraInfo', function(params) {
      self._onResponseExtraInfo(params);
    });

    this.cdp.on('Network.loadingFinished', function(params) {
      self._onLoadingFinished(params);
    });

    this.cdp.on('Network.loadingFailed', function(params) {
      self._onLoadingFailed(params);
    });

    this.cdp.on('Network.webSocketCreated', function(params) {
      self._onWSCreated(params);
    });

    this.cdp.on('Network.webSocketFrameSent', function(params) {
      self._onWSFrameSent(params);
    });

    this.cdp.on('Network.webSocketFrameReceived', function(params) {
      self._onWSFrameReceived(params);
    });

    this.cdp.on('Network.webSocketClosed', function(params) {
      self._onWSClosed(params);
    });

    this.cdp.on('Network.eventSourceMessageReceived', function(params) {
      self._onEventSource(params);
    });

    if (this.verbose) process.stderr.write('[CDPNetworkCollector] Initialized\n');
  }

  _onRequestWillBeSent(params) {
    var req = params.request;
    var initiator = params.initiator || {};

    this.requestMap.set(params.requestId, {
      url: req.url,
      method: req.method,
      type: params.type,
      initiator: initiator,
      frameId: params.frameId,
      ts: params.timestamp,
      wallTime: params.wallTime
    });

    this.pipeline.push({
      ts: Date.now(),
      cat: 'cdp-network',
      api: 'request',
      source: 'cdp',
      detail: JSON.stringify({
        url: (req.url || '').substring(0, 300),
        method: req.method,
        type: params.type,
        hasPostData: req.hasPostData || false,
        initiatorType: initiator.type,
        initiatorUrl: (initiator.url || '').substring(0, 200),
        initiatorLine: initiator.lineNumber,
        redirectResponse: params.redirectResponse ? {
          status: params.redirectResponse.status,
          url: (params.redirectResponse.url || '').substring(0, 200)
        } : null,
        frameId: params.frameId
      }).substring(0, 500),
      risk: this._classifyRequestRisk(req.url, params.type, initiator),
      origin: this._extractOrigin(req.url)
    });
  }

  _onRequestExtraInfo(params) {
    if (params.associatedCookies && params.associatedCookies.length > 0) {
      var blocked = [];
      for (var i = 0; i < params.associatedCookies.length; i++) {
        var c = params.associatedCookies[i];
        if (c.blockedReasons && c.blockedReasons.length > 0) {
          blocked.push(c);
        }
      }

      this.pipeline.push({
        ts: Date.now(),
        cat: 'cdp-cookie',
        api: 'request-cookies',
        source: 'cdp',
        detail: JSON.stringify({
          requestId: params.requestId,
          totalCookies: params.associatedCookies.length,
          blockedCookies: blocked.length,
          headers: {
            'sec-ch-ua': (params.headers && params.headers['sec-ch-ua']) || '',
            'sec-ch-ua-platform': (params.headers && params.headers['sec-ch-ua-platform']) || ''
          }
        }).substring(0, 500),
        risk: blocked.length > 0 ? 'high' : 'low'
      });
    }
  }

  _onResponseReceived(params) {
    var resp = params.response;

    this.pipeline.push({
      ts: Date.now(),
      cat: 'cdp-network',
      api: 'response',
      source: 'cdp',
      detail: JSON.stringify({
        url: (resp.url || '').substring(0, 300),
        status: resp.status,
        mimeType: resp.mimeType,
        protocol: resp.protocol,
        remoteIP: resp.remoteIPAddress,
        remotePort: resp.remotePort,
        fromCache: resp.fromDiskCache || resp.fromServiceWorker || false,
        timing: resp.timing ? {
          dnsStart: resp.timing.dnsStart,
          dnsEnd: resp.timing.dnsEnd,
          connectStart: resp.timing.connectStart,
          connectEnd: resp.timing.connectEnd,
          sslStart: resp.timing.sslStart,
          sslEnd: resp.timing.sslEnd,
          sendStart: resp.timing.sendStart,
          receiveHeadersEnd: resp.timing.receiveHeadersEnd
        } : null,
        securityState: resp.securityState,
        securityDetails: resp.securityDetails ? {
          protocol: resp.securityDetails.protocol,
          issuer: resp.securityDetails.issuer,
          validFrom: resp.securityDetails.validFrom,
          validTo: resp.securityDetails.validTo,
          cipher: resp.securityDetails.cipher
        } : null,
        setCookie: ((resp.headers && resp.headers['set-cookie']) || '').substring(0, 200),
        server: (resp.headers && resp.headers['server']) || '',
        csp: ((resp.headers && resp.headers['content-security-policy']) || '').substring(0, 200)
      }).substring(0, 800),
      risk: this._classifyResponseRisk(resp),
      origin: this._extractOrigin(resp.url)
    });
  }

  _onResponseExtraInfo(params) {
    if (params.headers && params.headers['set-cookie']) {
      var blockedCookies = [];
      if (params.blockedCookies) {
        for (var i = 0; i < params.blockedCookies.length && i < 10; i++) {
          blockedCookies.push({
            name: params.blockedCookies[i].cookie ? params.blockedCookies[i].cookie.name : '',
            reason: params.blockedCookies[i].blockedReasons
          });
        }
      }
      this.pipeline.push({
        ts: Date.now(),
        cat: 'cdp-cookie',
        api: 'set-cookie-detail',
        source: 'cdp',
        detail: JSON.stringify({
          requestId: params.requestId,
          cookies: params.headers['set-cookie'].substring(0, 500),
          blockedCookies: blockedCookies
        }).substring(0, 500),
        risk: 'medium'
      });
    }
  }

  _onLoadingFinished(params) {
    this.requestMap.delete(params.requestId);
  }

  _onLoadingFailed(params) {
    this.pipeline.push({
      ts: Date.now(),
      cat: 'cdp-network',
      api: 'request.failed',
      source: 'cdp',
      detail: JSON.stringify({
        requestId: params.requestId,
        errorText: params.errorText,
        canceled: params.canceled,
        blockedReason: params.blockedReason,
        corsErrorStatus: params.corsErrorStatus
      }),
      risk: params.blockedReason ? 'high' : 'low'
    });
    this.requestMap.delete(params.requestId);
  }

  _onWSCreated(params) {
    this.pipeline.push({
      ts: Date.now(),
      cat: 'cdp-websocket',
      api: 'ws.created',
      source: 'cdp',
      detail: JSON.stringify({
        requestId: params.requestId,
        url: (params.url || '').substring(0, 300),
        initiator: params.initiator ? params.initiator.type : ''
      }),
      risk: 'high'
    });
  }

  _onWSFrameSent(params) {
    var pd = (params.response && params.response.payloadData) || '';
    this.pipeline.push({
      ts: Date.now(),
      cat: 'cdp-websocket',
      api: 'ws.frame.sent',
      source: 'cdp',
      detail: JSON.stringify({
        requestId: params.requestId,
        opcode: params.response ? params.response.opcode : 0,
        payloadSize: pd.length,
        payloadPreview: pd.substring(0, 200)
      }).substring(0, 400),
      risk: 'high'
    });
  }

  _onWSFrameReceived(params) {
    var pd = (params.response && params.response.payloadData) || '';
    this.pipeline.push({
      ts: Date.now(),
      cat: 'cdp-websocket',
      api: 'ws.frame.received',
      source: 'cdp',
      detail: JSON.stringify({
        requestId: params.requestId,
        opcode: params.response ? params.response.opcode : 0,
        payloadSize: pd.length,
        payloadPreview: pd.substring(0, 200)
      }).substring(0, 400),
      risk: 'medium'
    });
  }

  _onWSClosed(params) {
    this.pipeline.push({
      ts: Date.now(),
      cat: 'cdp-websocket',
      api: 'ws.closed',
      source: 'cdp',
      detail: JSON.stringify({ requestId: params.requestId }),
      risk: 'low'
    });
  }

  _onEventSource(params) {
    this.pipeline.push({
      ts: Date.now(),
      cat: 'cdp-eventsource',
      api: 'sse.message',
      source: 'cdp',
      detail: JSON.stringify({
        requestId: params.requestId,
        eventName: params.eventName,
        eventId: params.eventId,
        dataPreview: (params.data || '').substring(0, 200)
      }).substring(0, 400),
      risk: 'medium'
    });
  }

  _classifyRequestRisk(url, type, initiator) {
    var u = (url || '').toLowerCase();
    if (/beacon|collect|track|pixel|analytics|telemetry/.test(u)) return 'high';
    if (type === 'Ping' || type === 'CSPViolationReport') return 'high';
    if (initiator && initiator.type === 'script' && /third.party|cdn|ad/.test(u)) return 'medium';
    return 'low';
  }

  _classifyResponseRisk(resp) {
    if (resp.securityState === 'insecure') return 'critical';
    if (resp.status >= 300 && resp.status < 400) return 'medium';
    return 'low';
  }

  _extractOrigin(url) {
    try { return new URL(url).origin; } catch(e) { return 'unknown'; }
  }
}

module.exports = { CDPNetworkCollector };
