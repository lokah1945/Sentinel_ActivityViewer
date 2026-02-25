// ═══════════════════════════════════════════════════════════════
//  SENTINEL v5.0.0 — SIGNATURE DATABASE
//  Contract: C-SIG-01 through C-SIG-06
//  Fingerprint library pattern matching
// ═══════════════════════════════════════════════════════════════

var SIGNATURES = {
  'FingerprintJS': {
    categories: ['canvas','webgl','audio','font-detection','math-fingerprint','screen','hardware','storage','client-hints','intl-fingerprint','css-fingerprint','perf-timing'],
    minMatch: 6,
    urlPatterns: ['fpcdn.io', 'fpjs', 'fingerprintjs'],
    confidence: 'high'
  },
  'CreepJS': {
    categories: ['canvas','webgl','audio','font-detection','math-fingerprint','css-fingerprint','speech','intl-fingerprint','webgl','hardware','dom-probe','screen','webrtc'],
    minMatch: 6,
    urlPatterns: ['creepjs', 'abrahamjuliot'],
    confidence: 'high'
  },
  'BotD': {
    categories: ['property-enum','dom-probe','fingerprint','perf-timing'],
    minMatch: 3,
    urlPatterns: ['botd', 'fpjs'],
    confidence: 'medium'
  },
  'BrowserScan': {
    categories: ['canvas','webgl','audio','font-detection','math-fingerprint','webrtc','storage','screen','fingerprint','hardware','client-hints'],
    minMatch: 7,
    urlPatterns: ['browserscan.net', 'ip-scan.browserscan'],
    confidence: 'high'
  },
  'ClientJS': {
    categories: ['canvas','fingerprint','screen','font-detection'],
    minMatch: 3,
    urlPatterns: ['clientjs'],
    confidence: 'medium'
  },
  'Cloudflare Bot Management': {
    categories: ['canvas','webgl','fingerprint','perf-timing','property-enum'],
    minMatch: 4,
    urlPatterns: ['challenges.cloudflare.com', 'cdn-cgi'],
    confidence: 'medium'
  },
  'DataDome': {
    categories: ['canvas','webgl','fingerprint','screen','perf-timing','event-monitoring'],
    minMatch: 4,
    urlPatterns: ['datadome', 'dd.js'],
    confidence: 'medium'
  }
};

var EXFIL_PATTERNS = [
  { pattern: 'fpcdn.io', library: 'FingerprintJS' },
  { pattern: 'google-analytics.com', library: 'Google Analytics' },
  { pattern: 'analytics', library: 'Analytics' },
  { pattern: 'beacon', library: 'Beacon' },
  { pattern: 'collect', library: 'Telemetry' },
  { pattern: 'track', library: 'Tracking' },
  { pattern: 'pixel', library: 'Pixel Tracking' },
  { pattern: 'sendBeacon', library: 'Beacon API' }
];

function matchSignatures(events) {
  var results = [];
  var detectedCats = {};
  var urls = [];

  for (var i = 0; i < events.length; i++) {
    detectedCats[events[i].cat] = (detectedCats[events[i].cat] || 0) + 1;
    if (events[i].val && typeof events[i].val === 'string') {
      urls.push(events[i].val);
    }
    if (events[i].detail && typeof events[i].detail === 'string') {
      urls.push(events[i].detail);
    }
  }

  var detectedCatList = Object.keys(detectedCats);
  var sigNames = Object.keys(SIGNATURES);

  for (var si = 0; si < sigNames.length; si++) {
    var sig = SIGNATURES[sigNames[si]];
    var matchCount = 0;
    for (var ci = 0; ci < sig.categories.length; ci++) {
      if (detectedCats[sig.categories[ci]]) matchCount++;
    }

    var urlMatch = false;
    for (var ui = 0; ui < sig.urlPatterns.length; ui++) {
      for (var uj = 0; uj < urls.length; uj++) {
        if (urls[uj].indexOf(sig.urlPatterns[ui]) >= 0) { urlMatch = true; break; }
      }
      if (urlMatch) break;
    }

    if (matchCount >= sig.minMatch || urlMatch) {
      var confidence = matchCount >= sig.minMatch ? sig.confidence : 'low';
      if (urlMatch && matchCount >= sig.minMatch) confidence = 'high';
      results.push({
        library: sigNames[si],
        matchedCategories: matchCount + '/' + sig.categories.length,
        urlMatch: urlMatch,
        confidence: confidence
      });
    }
  }

  return results;
}

function matchExfiltrationPatterns(url) {
  var matches = [];
  for (var i = 0; i < EXFIL_PATTERNS.length; i++) {
    if (url.indexOf(EXFIL_PATTERNS[i].pattern) >= 0) {
      matches.push(EXFIL_PATTERNS[i]);
    }
  }
  return matches;
}

module.exports = { matchSignatures, matchExfiltrationPatterns, SIGNATURES };
