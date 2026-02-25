// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — SIGNATURE DATABASE
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - FROM v6.4: Library detection signatures (embedded in observer)
//   - EXTRACTED: Into standalone module for maintainability
//   - ENRICHED: 10 library signatures with additional patterns
//
// LAST HISTORY LOG:
//   v6.4.0: Signatures embedded in cdp-observer-engine.js
//   v7.0.0: Extracted to standalone signature-db.js
// ═══════════════════════════════════════════════════════════════

'use strict';

var SIGNATURES = {
  'fingerprintjs': {
    patterns: ['FingerprintJS', 'fpPromise', 'fp.get', 'requestIdleCallback', 'getVisitorId', '@fingerprintjs'],
    risk: 'critical',
    description: 'FingerprintJS v3/v4 — Commercial browser fingerprinting'
  },
  'creepjs': {
    patterns: ['creepworker', 'getPhantomDark', 'getFingerprint', 'lieDetector', 'getPrototypeLies', 'creep.js'],
    risk: 'critical',
    description: 'CreepJS — Open-source fingerprinting and lie detector'
  },
  'botd': {
    patterns: ['BotD', 'BotdError', 'detect-bot', 'automationTool', 'searchBotDetector', '@fingerprintjs/botd'],
    risk: 'critical',
    description: 'BotD — Bot detection by FingerprintJS'
  },
  'evercookie': {
    patterns: ['evercookie', 'ievercookie', 'userData', 'silverlight'],
    risk: 'high',
    description: 'Evercookie — Persistent cookie mechanism'
  },
  'browserscan': {
    patterns: ['browserscan', 'BrowserScan', '/api/fp', '/api/detect', 'browserscan.net'],
    risk: 'high',
    description: 'BrowserScan — Browser fingerprint analyzer'
  },
  'recaptcha': {
    patterns: ['recaptcha', 'grecaptcha', 'www.google.com/recaptcha', 'recaptcha/api'],
    risk: 'medium',
    description: 'Google reCAPTCHA'
  },
  'hcaptcha': {
    patterns: ['hcaptcha', 'hcaptcha.com', 'hcaptcha-challenge'],
    risk: 'medium',
    description: 'hCaptcha challenge'
  },
  'datadome': {
    patterns: ['datadome', 'DataDome', 'dd.js', '/captcha/', 'datadome.co'],
    risk: 'high',
    description: 'DataDome — Bot detection and protection'
  },
  'cloudflare-turnstile': {
    patterns: ['challenges.cloudflare.com', 'turnstile', 'cf-turnstile'],
    risk: 'medium',
    description: 'Cloudflare Turnstile CAPTCHA'
  },
  'kasada': {
    patterns: ['kasada', 'ct.js', '/149e9513-01fa-4fb0-aad4-566afd725d1b/'],
    risk: 'high',
    description: 'Kasada — Advanced bot detection'
  }
};

function getSignatures() {
  return SIGNATURES;
}

function detectInUrl(url) {
  var urlLower = url.toLowerCase();
  var detected = [];
  Object.keys(SIGNATURES).forEach(function(libName) {
    var sig = SIGNATURES[libName];
    var matched = [];
    for (var i = 0; i < sig.patterns.length; i++) {
      if (urlLower.indexOf(sig.patterns[i].toLowerCase()) !== -1) {
        matched.push(sig.patterns[i]);
      }
    }
    if (matched.length > 0) {
      detected.push({
        name: libName,
        patterns: matched,
        risk: sig.risk,
        description: sig.description,
        confidence: matched.length >= 2 ? 'high' : 'medium'
      });
    }
  });
  return detected;
}

module.exports = { getSignatures: getSignatures, detectInUrl: detectInUrl };
