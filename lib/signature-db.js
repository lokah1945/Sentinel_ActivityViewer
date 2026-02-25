// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — SIGNATURE DATABASE (Library Detection)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - FROM v6.4: Library signature URL matching
//   - Expanded signatures: fingerprinting, analytics, ads, security
// ═══════════════════════════════════════════════════════════════

'use strict';

var SIGNATURES = [
  // Fingerprinting
  { pattern: /fingerprintjs/i, name: 'FingerprintJS', category: 'fingerprinting', version: '3+' },
  { pattern: /fpjs\.io/i, name: 'FingerprintJS Pro', category: 'fingerprinting', version: 'pro' },
  { pattern: /creepjs/i, name: 'CreepJS', category: 'fingerprinting', version: '?' },
  { pattern: /clientjs/i, name: 'ClientJS', category: 'fingerprinting', version: '?' },
  // Bot Detection
  { pattern: /datadome/i, name: 'DataDome', category: 'bot-detection', version: '?' },
  { pattern: /kasada/i, name: 'Kasada', category: 'bot-detection', version: '?' },
  { pattern: /perimeterx|px\.js/i, name: 'PerimeterX', category: 'bot-detection', version: '?' },
  { pattern: /imperva|incapsula/i, name: 'Imperva', category: 'bot-detection', version: '?' },
  { pattern: /akamai.*bot|akam/i, name: 'Akamai Bot Manager', category: 'bot-detection', version: '?' },
  { pattern: /cloudflare.*challenge|cf-challenge/i, name: 'Cloudflare Turnstile', category: 'bot-detection', version: '?' },
  { pattern: /recaptcha|google\.com\/recaptcha/i, name: 'reCAPTCHA', category: 'bot-detection', version: '?' },
  { pattern: /hcaptcha/i, name: 'hCaptcha', category: 'bot-detection', version: '?' },
  // Analytics
  { pattern: /google-analytics|googletagmanager|gtag|ga\.js|analytics\.js/i, name: 'Google Analytics', category: 'analytics', version: '?' },
  { pattern: /facebook.*pixel|fbevents|connect\.facebook/i, name: 'Facebook Pixel', category: 'analytics', version: '?' },
  { pattern: /hotjar/i, name: 'Hotjar', category: 'analytics', version: '?' },
  { pattern: /segment\.com|segment\.io/i, name: 'Segment', category: 'analytics', version: '?' },
  { pattern: /mixpanel/i, name: 'Mixpanel', category: 'analytics', version: '?' },
  { pattern: /amplitude/i, name: 'Amplitude', category: 'analytics', version: '?' },
  // Advertising
  { pattern: /doubleclick|googlesyndication|adsense/i, name: 'Google Ads', category: 'advertising', version: '?' },
  { pattern: /adsbygoogle/i, name: 'AdSense', category: 'advertising', version: '?' },
  // Frameworks
  { pattern: /react.*\.js/i, name: 'React', category: 'framework', version: '?' },
  { pattern: /vue.*\.js/i, name: 'Vue.js', category: 'framework', version: '?' },
  { pattern: /angular.*\.js/i, name: 'Angular', category: 'framework', version: '?' },
  { pattern: /jquery.*\.js|jquery.*\.min/i, name: 'jQuery', category: 'framework', version: '?' },
  { pattern: /next.*\.js|_next\//i, name: 'Next.js', category: 'framework', version: '?' },
  { pattern: /nuxt/i, name: 'Nuxt.js', category: 'framework', version: '?' },
];

function matchUrl(url) {
  if (!url || typeof url !== 'string') return null;
  for (var i = 0; i < SIGNATURES.length; i++) {
    if (SIGNATURES[i].pattern.test(url)) {
      return { name: SIGNATURES[i].name, category: SIGNATURES[i].category, version: SIGNATURES[i].version };
    }
  }
  return null;
}

module.exports = { matchUrl: matchUrl, SIGNATURES: SIGNATURES };
