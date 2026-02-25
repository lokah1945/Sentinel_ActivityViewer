// ═══════════════════════════════════════════════════════════════
//  SENTINEL v6.0.0 — CDP SECURITY COLLECTOR
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v6.0.0 (2026-02-25):
//   - NEW: CDP Security.* domain monitoring
//   - NEW: TLS/certificate state tracking
//   - NEW: Certificate error capture
//
// LAST HISTORY LOG:
//   v6.0.0: Initial creation
// ═══════════════════════════════════════════════════════════════

class CDPSecurityCollector {
  constructor(cdpSession, pipeline, options) {
    this.cdp = cdpSession;
    this.pipeline = pipeline;
    this.verbose = (options && options.verbose) || false;
  }

  async initialize() {
    var self = this;

    await this.cdp.send('Security.enable');

    this.cdp.on('Security.visibleSecurityStateChanged', function(params) {
      var state = params.visibleSecurityState || {};
      var cert = state.certificateSecurityState || {};

      self.pipeline.push({
        ts: Date.now(),
        cat: 'cdp-security',
        api: 'tls-state',
        source: 'cdp',
        detail: JSON.stringify({
          securityState: state.securityState,
          protocol: cert.protocol,
          cipher: cert.cipher,
          issuer: cert.issuer,
          subjectName: cert.subjectName,
          validFrom: cert.validFrom,
          validTo: cert.validTo,
          modernSSL: cert.modernSSL,
          obsoleteProtocol: cert.obsoleteSslProtocol,
          weakSignature: cert.certificateHasWeakSignature,
          sha1Signature: cert.certificateHasSha1Signature,
          safetyTip: state.safetyTipInfo ? state.safetyTipInfo.safetyTipStatus : ''
        }).substring(0, 600),
        risk: state.securityState === 'insecure' ? 'critical' :
              cert.obsoleteSslProtocol ? 'high' : 'low'
      });
    });

    this.cdp.on('Security.certificateError', function(params) {
      self.pipeline.push({
        ts: Date.now(),
        cat: 'cdp-security',
        api: 'cert-error',
        source: 'cdp',
        detail: JSON.stringify({
          errorType: params.errorType,
          requestURL: params.requestURL
        }),
        risk: 'critical'
      });
    });

    if (this.verbose) process.stderr.write('[CDPSecurityCollector] Initialized\n');
  }
}

module.exports = { CDPSecurityCollector };
