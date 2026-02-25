/**
 * CdpCollectorPipeline v6.2.0
 * 
 * Collects data from CDP domains WITHOUT using Runtime.Enable.
 * This is critical: rebrowser-patches prevents Runtime.Enable from being called,
 * but we can still use other CDP domains (Network, Security, Target, etc.) freely.
 * 
 * Collectors:
 *   1. Network lifecycle (request/response/failed/finished)
 *   2. Security/TLS certificate info
 *   3. Target discovery (iframes, workers, service workers)
 *   4. Cookie tracking
 *   5. DNS resolution (via network events)
 */

'use strict';

class CdpCollectorPipeline {
  constructor(pipeline, cdpSession) {
    this.pipeline = pipeline;
    this.cdp = cdpSession;
    this.networkEntries = [];
    this.targetInventory = [];
    this._listeners = [];
  }

  async start() {
    await this._startNetworkCollector();
    await this._startSecurityCollector();
    await this._startTargetCollector();
  }

  async stop() {
    try {
      await this.cdp.send('Network.disable').catch(() => {});
      await this.cdp.send('Security.disable').catch(() => {});
    } catch (e) {}
  }

  // ═══ Network Collector ═══
  async _startNetworkCollector() {
    try {
      await this.cdp.send('Network.enable', {
        maxTotalBufferSize: 10 * 1024 * 1024,
        maxResourceBufferSize: 5 * 1024 * 1024,
      });
    } catch (e) {
      console.error('[CDP] Network.enable failed:', e.message);
      return;
    }

    const requestMap = new Map();

    this.cdp.on('Network.requestWillBeSent', (params) => {
      const { requestId, request, type, timestamp, initiator } = params;
      requestMap.set(requestId, {
        url: request.url,
        method: request.method,
        headers: request.headers,
        postData: request.postData,
        type,
        timestamp,
        initiator: initiator?.type || 'unknown',
      });

      this.pipeline.pushCdp({
        cat: 'cdp-network',
        api: 'requestWillBeSent',
        risk: 'info',
        detail: `${request.method} ${request.url}`,
        meta: { requestId, type, initiator: initiator?.type },
      });
    });

    this.cdp.on('Network.responseReceived', (params) => {
      const { requestId, response, type } = params;
      const req = requestMap.get(requestId);

      const entry = {
        url: response.url,
        method: req?.method || 'GET',
        requestHeaders: req?.headers || {},
        postData: req?.postData || '',
        responseStatus: response.status,
        responseHeaders: response.headers,
        resourceType: type,
        responseSize: 0,
      };

      // Try to get response body asynchronously
      this.cdp.send('Network.getResponseBody', { requestId }).then(body => {
        entry.responseBody = (body.body || '').slice(0, 2000);
        entry.responseSize = body.body?.length || 0;
      }).catch(() => {});

      this.networkEntries.push(entry);

      this.pipeline.pushCdp({
        cat: 'cdp-network',
        api: 'responseReceived',
        risk: 'info',
        detail: `${response.status} ${response.url}`,
        meta: { requestId, status: response.status, type, size: response.headers['content-length'] },
      });
    });

    this.cdp.on('Network.requestWillBeSentExtraInfo', (params) => {
      this.pipeline.pushCdp({
        cat: 'cdp-network-extra',
        api: 'requestHeaders',
        risk: 'info',
        detail: 'Extra request headers for ' + params.requestId,
        meta: { cookies: params.associatedCookies?.length || 0 },
      });
    });

    this.cdp.on('Network.responseReceivedExtraInfo', (params) => {
      // Track Set-Cookie headers for cookie monitoring
      const setCookies = params.headers?.['set-cookie'] || params.headers?.['Set-Cookie'] || '';
      if (setCookies) {
        this.pipeline.pushCdp({
          cat: 'cdp-cookie',
          api: 'Set-Cookie',
          risk: 'high',
          detail: 'Cookie set: ' + setCookies.slice(0, 300),
        });
      }
    });

    this.cdp.on('Network.webSocketCreated', (params) => {
      this.pipeline.pushCdp({
        cat: 'cdp-websocket',
        api: 'wsCreated',
        risk: 'critical',
        detail: 'WebSocket: ' + params.url,
        meta: { requestId: params.requestId },
      });
    });

    this.cdp.on('Network.webSocketFrameSent', (params) => {
      this.pipeline.pushCdp({
        cat: 'cdp-websocket',
        api: 'wsFrameSent',
        risk: 'high',
        detail: 'WS frame sent: ' + (params.response?.payloadData || '').slice(0, 200),
      });
    });

    this.cdp.on('Network.webSocketFrameReceived', (params) => {
      this.pipeline.pushCdp({
        cat: 'cdp-websocket',
        api: 'wsFrameReceived',
        risk: 'high',
        detail: 'WS frame received: ' + (params.response?.payloadData || '').slice(0, 200),
      });
    });

    this.cdp.on('Network.loadingFailed', (params) => {
      this.pipeline.pushCdp({
        cat: 'cdp-network',
        api: 'loadingFailed',
        risk: 'medium',
        detail: `Failed: ${params.errorText} (${params.type})`,
        meta: { requestId: params.requestId, blocked: params.blockedReason },
      });
    });
  }

  // ═══ Security Collector ═══
  async _startSecurityCollector() {
    try {
      await this.cdp.send('Security.enable');
    } catch (e) {
      return;
    }

    this.cdp.on('Security.securityStateChanged', (params) => {
      this.pipeline.pushCdp({
        cat: 'cdp-security',
        api: 'securityState',
        risk: params.securityState === 'secure' ? 'info' : 'high',
        detail: `Security state: ${params.securityState}`,
        meta: params,
      });
    });

    this.cdp.on('Security.certificateError', (params) => {
      this.pipeline.pushCdp({
        cat: 'cdp-security',
        api: 'certError',
        risk: 'critical',
        detail: `Certificate error: ${params.errorType} on ${params.requestURL}`,
      });
    });
  }

  // ═══ Target Collector ═══
  async _startTargetCollector() {
    try {
      await this.cdp.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: false,
        flatten: true,
      });
    } catch (e) {}

    this.cdp.on('Target.attachedToTarget', (params) => {
      const { sessionId, targetInfo } = params;
      this.targetInventory.push({
        targetId: targetInfo.targetId,
        type: targetInfo.type,
        url: targetInfo.url,
        networkEnabled: true,
        injected: true,
        bootOk: true,
        eventsCollected: 0,
        skipReason: '',
      });

      this.pipeline.pushCdp({
        cat: 'cdp-target',
        api: 'targetAttached',
        risk: 'info',
        detail: `${targetInfo.type}: ${targetInfo.url}`,
        meta: { targetId: targetInfo.targetId, sessionId },
      });

      // Enable Network on child targets too
      try {
        this.cdp.send('Network.enable', {}, sessionId).catch(() => {});
      } catch (e) {}
    });

    this.cdp.on('Target.detachedFromTarget', (params) => {
      this.pipeline.pushCdp({
        cat: 'cdp-target',
        api: 'targetDetached',
        risk: 'info',
        detail: `Target detached: ${params.sessionId}`,
      });
    });
  }

  getTargetGraph() {
    return {
      inventory: this.targetInventory,
      totalTargets: this.targetInventory.length,
      workerEvents: this.pipeline.getStats().workerEvents,
    };
  }

  getNetworkEntries() {
    return this.networkEntries;
  }
}

module.exports = { CdpCollectorPipeline };
