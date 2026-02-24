// Sentinel v4.4.2 — Signature Database
// Known fingerprinting library patterns

function getSignatures() {
  return [
    {
      name: 'BrowserScan',
      patterns: [
        { type: 'api-set', apis: ['getParameter','getExtension','toDataURL','measureText','getVoices','matchMedia','getTimezoneOffset'], minMatch: 5 },
        { type: 'category-set', categories: ['canvas','webgl','audio','font-detection','screen','fingerprint','math-fingerprint','css-fingerprint','webrtc'], minMatch: 6 }
      ]
    },
    {
      name: 'FingerprintJS v5',
      patterns: [
        { type: 'api-set', apis: ['toDataURL','getParameter','createOscillator','measureText','getTimezoneOffset','hardwareConcurrency','deviceMemory','colorDepth','matchMedia','isPointInPath'], minMatch: 6 },
        { type: 'category-set', categories: ['canvas','webgl','audio','font-detection','screen','fingerprint','math-fingerprint'], minMatch: 5 }
      ]
    },
    {
      name: 'CreepJS',
      patterns: [
        { type: 'api-set', apis: ['toDataURL','getParameter','getVoices','Object.keys','Object.getOwnPropertyNames','OffscreenCanvas'], minMatch: 3 },
        { type: 'category-set', categories: ['canvas','webgl','speech','property-enum','offscreen-canvas'], minMatch: 3 }
      ]
    },
    {
      name: 'BotD',
      patterns: [
        { type: 'api-set', apis: ['webdriver','RTCPeerConnection','permissions.query'], minMatch: 2 },
        { type: 'category-set', categories: ['webrtc','permissions','fingerprint'], minMatch: 2 }
      ]
    },
    {
      name: 'Google Analytics',
      patterns: [
        { type: 'api-set', apis: ['fetch','sendBeacon','cookie.get','cookie.set'], minMatch: 3 },
        { type: 'category-set', categories: ['exfiltration','storage'], minMatch: 2 }
      ]
    }
  ];
}

function getExfilPatterns() {
  return [
    { name: 'FingerprintJS Pro', pattern: /fpjs\.io|fpcdn\.io|cdn\.fpjs\.io/i },
    { name: 'Google Analytics', pattern: /google-analytics\.com|googletagmanager\.com/i },
    { name: 'Facebook Pixel', pattern: /facebook\.com\/tr|connect\.facebook/i },
    { name: 'BrowserScan API', pattern: /browserscan\.net\/api|ip-scan\.browserscan/i },
    { name: 'Data4', pattern: /api\.data4\.net/i },
    { name: 'Generic Tracker', pattern: /collect|beacon|track|telemetry|pixel/i }
  ];
}

module.exports = { getSignatures, getExfilPatterns };
