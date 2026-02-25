/**
 * CdpObserverEngine v6.3.0
 * 
 * PURE PASSIVE OBSERVER — no JavaScript injection into any page.
 * All monitoring is done via CDP event subscriptions.
 * 
 * CDP Domains used (all passive — website cannot detect these):
 *   - Network.*        → all HTTP/WS traffic, cookies, headers, bodies
 *   - Security.*       → TLS/certificate state
 *   - Page.*           → frame lifecycle, navigations, scripts loaded
 *   - DOM.*            → document changes (optional, high overhead)
 *   - Performance.*    → metrics timeline
 *   - Console.*        → console.log/warn/error from page
 *   - Audits.*         → mixed content, cookies issues
 *   - Log.*            → browser-level log messages
 * 
 * NONE of these domains inject JS or modify page behavior.
 * The website has ZERO way to detect this observation.
 */

'use strict';

class CdpObserverEngine {
  constructor(pipeline, cdpSession) {
    this.pipeline = pipeline;
    this.cdp = cdpSession;
    this.networkRequests = new Map();
    this.networkEntries = [];
    this._started = false;
  }

  async start() {
    if (this._started) return;
    this._started = true;

    await this._enableNetworkObserver();
    await this._enableSecurityObserver();
    await this._enablePageObserver();
    await this._enablePerformanceObserver();
    await this._enableConsoleObserver();
    await this._enableAuditObserver();
    await this._enableLogObserver();
  }

  async stop() {
    const domains = ['Network', 'Security', 'Page', 'Performance', 'Log'];
    for (const d of domains) {
      try { await this.cdp.send(`${d}.disable`); } catch (e) {}
    }
  }

  // ═══════════════════════════════════════
  // NETWORK OBSERVER — complete HTTP lifecycle
  // ═══════════════════════════════════════
  async _enableNetworkObserver() {
    try {
      await this.cdp.send('Network.enable', {
        maxTotalBufferSize: 10 * 1024 * 1024,
        maxResourceBufferSize: 5 * 1024 * 1024,
      });
    } catch (e) {
      console.error('[CDP] Network.enable failed:', e.message);
      return;
    }

    // --- Request sent ---
    this.cdp.on('Network.requestWillBeSent', (p) => {
      this.networkRequests.set(p.requestId, {
        url: p.request.url,
        method: p.request.method,
        headers: p.request.headers,
        postData: p.request.postData,
        type: p.type,
        initiator: p.initiator,
        timestamp: p.timestamp,
        redirectChain: p.redirectResponse ? true : false,
      });

      const risk = this._classifyNetworkRisk(p.request);
      this.pipeline.pushCdp({
        cat: 'network-request',
        api: p.request.method,
        risk,
        detail: `${p.request.method} ${p.request.url}`,
        meta: {
          requestId: p.requestId,
          type: p.type,
          initiator: p.initiator?.type || 'unknown',
          initiatorUrl: p.initiator?.url || '',
          hasPostData: !!p.request.postData,
        },
      });

      // Detect data exfiltration
      if (p.request.postData || p.request.method === 'POST') {
        this.pipeline.pushCdp({
          cat: 'exfiltration',
          api: 'POST-data',
          risk: 'high',
          detail: `POST ${p.request.url} body=${(p.request.postData || '').slice(0, 500)}`,
          meta: { requestId: p.requestId },
        });
      }
    });

    // --- Response received ---
    this.cdp.on('Network.responseReceived', (p) => {
      const req = this.networkRequests.get(p.requestId);
      const entry = {
        requestId: p.requestId,
        url: p.response.url,
        method: req?.method || 'GET',
        status: p.response.status,
        statusText: p.response.statusText,
        mimeType: p.response.mimeType,
        headers: p.response.headers,
        resourceType: p.type,
        protocol: p.response.protocol,
        securityState: p.response.securityState,
        remoteIP: p.response.remoteIPAddress,
        remotePort: p.response.remotePort,
        encodedDataLength: 0,
        timing: p.response.timing,
      };
      this.networkEntries.push(entry);

      this.pipeline.pushCdp({
        cat: 'network-response',
        api: `${p.response.status}`,
        risk: 'info',
        detail: `${p.response.status} ${p.response.url} [${p.response.mimeType}]`,
        meta: {
          requestId: p.requestId,
          status: p.response.status,
          type: p.type,
          mime: p.response.mimeType,
          size: p.response.headers?.['content-length'] || 0,
          ip: p.response.remoteIPAddress,
          protocol: p.response.protocol,
          security: p.response.securityState,
        },
      });
    });

    // --- Loading finished (with actual transfer size) ---
    this.cdp.on('Network.loadingFinished', (p) => {
      const entry = this.networkEntries.find(e => e.requestId === p.requestId);
      if (entry) entry.encodedDataLength = p.encodedDataLength;

      // Try to get response body for forensic analysis
      this.cdp.send('Network.getResponseBody', { requestId: p.requestId })
        .then(body => {
          if (entry) {
            entry.bodySize = body.body?.length || 0;
            entry.bodyPreview = (body.body || '').slice(0, 1000);
            entry.base64Encoded = body.base64Encoded;
          }
          // Detect known fingerprint libraries by script content
          if (body.body && !body.base64Encoded) {
            this._detectLibraryInScript(body.body, entry?.url || '');
          }
        })
        .catch(() => {});
    });

    // --- Loading failed ---
    this.cdp.on('Network.loadingFailed', (p) => {
      this.pipeline.pushCdp({
        cat: 'network-error',
        api: 'loadingFailed',
        risk: p.blockedReason ? 'high' : 'medium',
        detail: `Failed: ${p.errorText} [${p.type}] ${p.blockedReason || ''}`,
        meta: { requestId: p.requestId, type: p.type, error: p.errorText, blocked: p.blockedReason },
      });
    });

    // --- Extra request info (cookies sent) ---
    this.cdp.on('Network.requestWillBeSentExtraInfo', (p) => {
      if (p.associatedCookies?.length > 0) {
        const cookies = p.associatedCookies
          .filter(c => !c.blockedReasons?.length)
          .map(c => c.cookie?.name)
          .filter(Boolean);
        if (cookies.length > 0) {
          this.pipeline.pushCdp({
            cat: 'cookie-sent',
            api: 'requestCookies',
            risk: 'medium',
            detail: `Cookies sent: ${cookies.join(', ')}`,
            meta: { requestId: p.requestId, count: cookies.length, names: cookies },
          });
        }
      }
    });

    // --- Extra response info (Set-Cookie) ---
    this.cdp.on('Network.responseReceivedExtraInfo', (p) => {
      const sc = p.headers?.['set-cookie'] || p.headers?.['Set-Cookie'];
      if (sc) {
        this.pipeline.pushCdp({
          cat: 'cookie-set',
          api: 'Set-Cookie',
          risk: 'high',
          detail: `Cookie set: ${sc.slice(0, 500)}`,
          meta: { requestId: p.requestId },
        });
      }
    });

    // --- WebSocket lifecycle ---
    this.cdp.on('Network.webSocketCreated', (p) => {
      this.pipeline.pushCdp({
        cat: 'websocket',
        api: 'created',
        risk: 'critical',
        detail: `WebSocket opened: ${p.url}`,
        meta: { requestId: p.requestId, initiator: p.initiator },
      });
    });

    this.cdp.on('Network.webSocketFrameSent', (p) => {
      this.pipeline.pushCdp({
        cat: 'websocket',
        api: 'frameSent',
        risk: 'high',
        detail: `WS→ ${(p.response?.payloadData || '').slice(0, 500)}`,
        meta: { requestId: p.requestId, opcode: p.response?.opcode },
      });
    });

    this.cdp.on('Network.webSocketFrameReceived', (p) => {
      this.pipeline.pushCdp({
        cat: 'websocket',
        api: 'frameReceived',
        risk: 'high',
        detail: `WS← ${(p.response?.payloadData || '').slice(0, 500)}`,
        meta: { requestId: p.requestId, opcode: p.response?.opcode },
      });
    });

    this.cdp.on('Network.webSocketClosed', (p) => {
      this.pipeline.pushCdp({
        cat: 'websocket',
        api: 'closed',
        risk: 'info',
        detail: `WebSocket closed`,
        meta: { requestId: p.requestId },
      });
    });

    // --- Event source ---
    this.cdp.on('Network.eventSourceMessageReceived', (p) => {
      this.pipeline.pushCdp({
        cat: 'eventsource',
        api: 'message',
        risk: 'high',
        detail: `SSE: ${p.eventName} ${(p.data || '').slice(0, 300)}`,
        meta: { requestId: p.requestId },
      });
    });
  }

  // ═══════════════════════════════════════
  // SECURITY OBSERVER — TLS, certs
  // ═══════════════════════════════════════
  async _enableSecurityObserver() {
    try {
      await this.cdp.send('Security.enable');
    } catch (e) { return; }

    this.cdp.on('Security.securityStateChanged', (p) => {
      this.pipeline.pushCdp({
        cat: 'security',
        api: 'stateChanged',
        risk: p.securityState === 'secure' ? 'info' : 'high',
        detail: `Security: ${p.securityState}`,
        meta: p,
      });
    });

    this.cdp.on('Security.visibleSecurityStateChanged', (p) => {
      const state = p.visibleSecurityState;
      if (state?.certificateSecurityState) {
        this.pipeline.pushCdp({
          cat: 'tls-certificate',
          api: 'certInfo',
          risk: 'info',
          detail: `TLS: ${state.certificateSecurityState.protocol} ${state.certificateSecurityState.cipher}`,
          meta: {
            issuer: state.certificateSecurityState.issuer,
            subject: state.certificateSecurityState.subjectName,
            validFrom: state.certificateSecurityState.validFrom,
            validTo: state.certificateSecurityState.validTo,
            protocol: state.certificateSecurityState.protocol,
            cipher: state.certificateSecurityState.cipher,
          },
        });
      }
    });
  }

  // ═══════════════════════════════════════
  // PAGE OBSERVER — scripts, navigation, frames
  // ═══════════════════════════════════════
  async _enablePageObserver() {
    try {
      await this.cdp.send('Page.enable');
    } catch (e) { return; }

    this.cdp.on('Page.frameNavigated', (p) => {
      this.pipeline.pushCdp({
        cat: 'page-navigation',
        api: 'frameNavigated',
        risk: 'info',
        detail: `Frame navigated: ${p.frame.url} [${p.type || 'Navigation'}]`,
        meta: { frameId: p.frame.id, parentId: p.frame.parentId, name: p.frame.name },
      });
    });

    this.cdp.on('Page.frameAttached', (p) => {
      this.pipeline.pushCdp({
        cat: 'frame-lifecycle',
        api: 'frameAttached',
        risk: 'info',
        detail: `Frame attached: ${p.frameId} parent=${p.parentFrameId}`,
        meta: { frameId: p.frameId, parentFrameId: p.parentFrameId },
      });
    });

    this.cdp.on('Page.frameDetached', (p) => {
      this.pipeline.pushCdp({
        cat: 'frame-lifecycle',
        api: 'frameDetached',
        risk: 'info',
        detail: `Frame detached: ${p.frameId} reason=${p.reason}`,
        meta: { frameId: p.frameId, reason: p.reason },
      });
    });

    this.cdp.on('Page.downloadWillBegin', (p) => {
      this.pipeline.pushCdp({
        cat: 'download',
        api: 'downloadBegin',
        risk: 'critical',
        detail: `Download: ${p.url} → ${p.suggestedFilename}`,
        meta: { url: p.url, filename: p.suggestedFilename, frameId: p.frameId },
      });
    });

    this.cdp.on('Page.javascriptDialogOpening', (p) => {
      this.pipeline.pushCdp({
        cat: 'dialog',
        api: p.type,
        risk: 'medium',
        detail: `Dialog (${p.type}): ${p.message.slice(0, 300)}`,
        meta: { type: p.type, url: p.url, hasDefault: p.hasBrowserHandler },
      });
    });

    this.cdp.on('Page.windowOpen', (p) => {
      this.pipeline.pushCdp({
        cat: 'popup',
        api: 'windowOpen',
        risk: 'high',
        detail: `Popup: ${p.url}`,
        meta: { url: p.url, windowName: p.windowName, features: p.windowFeatures },
      });
    });
  }

  // ═══════════════════════════════════════
  // PERFORMANCE OBSERVER
  // ═══════════════════════════════════════
  async _enablePerformanceObserver() {
    try {
      await this.cdp.send('Performance.enable', { timeDomain: 'timeTicks' });
    } catch (e) { return; }

    // We'll collect metrics at the end, not via events
  }

  async collectPerformanceMetrics() {
    try {
      const { metrics } = await this.cdp.send('Performance.getMetrics');
      for (const m of metrics) {
        this.pipeline.pushCdp({
          cat: 'performance',
          api: m.name,
          risk: 'info',
          detail: `${m.name}: ${m.value}`,
          meta: { name: m.name, value: m.value },
        });
      }
      return metrics;
    } catch (e) {
      return [];
    }
  }

  // ═══════════════════════════════════════
  // CONSOLE OBSERVER — page console.log/warn/error
  // ═══════════════════════════════════════
  async _enableConsoleObserver() {
    // Note: Console domain needs Runtime.Enable in vanilla Playwright,
    // but rebrowser-patches makes this work via addBinding approach.
    // If it fails, we gracefully degrade.
    try {
      await this.cdp.send('Runtime.enable');
    } catch (e) {}

    this.cdp.on('Runtime.consoleAPICalled', (p) => {
      const text = (p.args || []).map(a => a.value || a.description || '').join(' ').slice(0, 500);
      this.pipeline.pushCdp({
        cat: 'console',
        api: p.type,
        risk: p.type === 'error' ? 'high' : p.type === 'warning' ? 'medium' : 'info',
        detail: `console.${p.type}: ${text}`,
        meta: { type: p.type, stackTrace: p.stackTrace },
      });
    });

    this.cdp.on('Runtime.exceptionThrown', (p) => {
      const desc = p.exceptionDetails?.exception?.description || p.exceptionDetails?.text || '';
      this.pipeline.pushCdp({
        cat: 'exception',
        api: 'exceptionThrown',
        risk: 'high',
        detail: `Exception: ${desc.slice(0, 500)}`,
        meta: { lineNumber: p.exceptionDetails?.lineNumber, url: p.exceptionDetails?.url },
      });
    });
  }

  // ═══════════════════════════════════════
  // AUDIT OBSERVER — mixed content, etc
  // ═══════════════════════════════════════
  async _enableAuditObserver() {
    try {
      await this.cdp.send('Audits.enable');
    } catch (e) { return; }

    this.cdp.on('Audits.issueAdded', (p) => {
      const issue = p.issue;
      this.pipeline.pushCdp({
        cat: 'audit-issue',
        api: issue.code,
        risk: issue.details?.severity === 'High' ? 'high' : 'medium',
        detail: `Audit: ${issue.code} ${JSON.stringify(issue.details || {}).slice(0, 300)}`,
        meta: issue,
      });
    });
  }

  // ═══════════════════════════════════════
  // LOG OBSERVER
  // ═══════════════════════════════════════
  async _enableLogObserver() {
    try {
      await this.cdp.send('Log.enable');
    } catch (e) { return; }

    this.cdp.on('Log.entryAdded', (p) => {
      this.pipeline.pushCdp({
        cat: 'browser-log',
        api: p.entry.level,
        risk: p.entry.level === 'error' ? 'high' : 'info',
        detail: `[${p.entry.source}] ${(p.entry.text || '').slice(0, 500)}`,
        meta: { source: p.entry.source, level: p.entry.level, url: p.entry.url },
      });
    });
  }

  // ═══════════════════════════════════════
  // Library detection from loaded scripts
  // ═══════════════════════════════════════
  _detectLibraryInScript(body, url) {
    const checks = [
      { name: 'FingerprintJS', patterns: ['FingerprintJS', 'fpjs', 'fingerprintjs', 'getFingerprint'] },
      { name: 'CreepJS', patterns: ['creepjs', 'CreepJS', 'creep.js'] },
      { name: 'BotD', patterns: ['BotD', 'botd', 'bot-detector', 'BotDetect'] },
      { name: 'BrowserScan', patterns: ['browserscan', 'BrowserScan'] },
      { name: 'DataDome', patterns: ['datadome', 'DataDome', 'dd.js'] },
      { name: 'Cloudflare', patterns: ['challenges.cloudflare', 'turnstile', 'cf-challenge'] },
      { name: 'Google Analytics', patterns: ['google-analytics.com', 'gtag', 'GA4'] },
      { name: 'Google reCAPTCHA', patterns: ['recaptcha', 'grecaptcha'] },
      { name: 'hCaptcha', patterns: ['hcaptcha', 'hCaptcha'] },
    ];

    for (const lib of checks) {
      const matched = lib.patterns.filter(p => body.includes(p));
      if (matched.length > 0) {
        this.pipeline.pushCdp({
          cat: 'library-detected',
          api: lib.name,
          risk: 'high',
          detail: `Library "${lib.name}" detected in ${url.slice(0, 200)} (patterns: ${matched.join(', ')})`,
          meta: { library: lib.name, url, patterns: matched },
        });
      }
    }
  }

  _classifyNetworkRisk(request) {
    const url = request.url || '';
    if (url.includes('google-analytics') || url.includes('collect?')) return 'high';
    if (url.includes('fingerprint') || url.includes('fpjs')) return 'critical';
    if (url.includes('datadome') || url.includes('cloudflare')) return 'high';
    if (request.method === 'POST') return 'medium';
    return 'info';
  }

  getNetworkEntries() {
    return this.networkEntries;
  }
}

module.exports = { CdpObserverEngine };
