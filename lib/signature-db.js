/**
 * Sentinel v4.3 — Signature Database
 * Patterns for identifying fingerprinting libraries
 */

var SIGNATURES = {
  fingerprintjs_v5: {
    name: 'FingerprintJS v5',
    patterns: [
      { apis: ['CanvasRenderingContext2D.prototype.fillText', 'HTMLCanvasElement.prototype.toDataURL'], weight: 2 },
      { apis: ['OfflineAudioContext', 'OscillatorNode.prototype.connect', 'DynamicsCompressorNode'], weight: 3 },
      { apis: ['WebGLRenderingContext.prototype.getParameter', 'WebGLRenderingContext.prototype.getExtension'], weight: 2 },
      { apis: ['navigator.hardwareConcurrency', 'navigator.deviceMemory', 'navigator.platform'], weight: 1 },
      { apis: ['screen.width', 'screen.height', 'screen.colorDepth'], weight: 1 },
      { apis: ['navigator.languages', 'Intl.DateTimeFormat.prototype.resolvedOptions'], weight: 1 },
      { apis: ['navigator.maxTouchPoints', 'navigator.vendor'], weight: 1 },
      { apis: ['Math.acos', 'Math.sinh', 'Math.expm1', 'Math.atanh'], weight: 2 },
      { apis: ['speechSynthesis.getVoices'], weight: 2 },
      { apis: ['navigator.userAgentData.getHighEntropyValues'], weight: 3 },
      { apis: ['CSS.supports'], weight: 1 },
      { apis: ['Document.prototype.fonts', 'FontFace'], weight: 2 }
    ],
    burstWindow: 3000,
    minScore: 8,
    description: 'FingerprintJS v5 — commercial fingerprinting service with 40+ entropy sources'
  },

  creepjs: {
    name: 'CreepJS',
    patterns: [
      { apis: ['navigator.connection', 'navigator.getBattery'], weight: 2 },
      { apis: ['Intl.ListFormat', 'Intl.RelativeTimeFormat'], weight: 3 },
      { apis: ['navigator.keyboard.getLayoutMap'], weight: 3 },
      { apis: ['CSS.supports', 'matchMedia'], weight: 1 },
      { apis: ['CanvasRenderingContext2D.prototype.measureText'], weight: 1 },
      { apis: ['WebGLRenderingContext.prototype.getParameter'], weight: 1 },
      { apis: ['navigator.permissions.query'], weight: 2 },
      { apis: ['OfflineAudioContext'], weight: 2 },
      { apis: ['Object.getOwnPropertyNames', 'Object.getOwnPropertyDescriptor'], weight: 2 },
      { apis: ['Error.prototype.stack'], weight: 2 },
      { apis: ['performance.now', 'performance.mark'], weight: 1 }
    ],
    burstWindow: 5000,
    minScore: 7,
    description: 'CreepJS — open-source fingerprinting with deep browser introspection'
  },

  custom_fingerprinter: {
    name: 'Custom Fingerprinter',
    patterns: [
      { apis: ['HTMLCanvasElement.prototype.toDataURL', 'HTMLCanvasElement.prototype.getContext'], weight: 2 },
      { apis: ['WebGLRenderingContext.prototype.getParameter'], weight: 2 },
      { apis: ['OfflineAudioContext'], weight: 2 },
      { apis: ['navigator.hardwareConcurrency'], weight: 1 },
      { apis: ['screen.width', 'screen.height'], weight: 1 }
    ],
    burstWindow: 10000,
    minScore: 5,
    description: 'Custom/unknown fingerprinting script detected by API pattern analysis'
  }
};

function matchSignature(events, windowMs) {
  var results = [];
  var sigKeys = Object.keys(SIGNATURES);

  for (var s = 0; s < sigKeys.length; s++) {
    var sigKey = sigKeys[s];
    var sig = SIGNATURES[sigKey];
    var score = 0;
    var matched = [];

    var apiSet = {};
    for (var i = 0; i < events.length; i++) {
      apiSet[events[i].api] = true;
    }

    for (var p = 0; p < sig.patterns.length; p++) {
      var pattern = sig.patterns[p];
      var allMatch = true;
      for (var a = 0; a < pattern.apis.length; a++) {
        if (!apiSet[pattern.apis[a]]) {
          allMatch = false;
          break;
        }
      }
      if (allMatch) {
        score += pattern.weight;
        matched.push(pattern.apis.join(' + '));
      }
    }

    if (score >= sig.minScore) {
      var maxScore = 0;
      for (var p2 = 0; p2 < sig.patterns.length; p2++) {
        maxScore += sig.patterns[p2].weight;
      }
      results.push({
        library: sig.name,
        confidence: Math.min(100, Math.round((score / maxScore) * 100)),
        matchedPatterns: matched,
        description: sig.description,
        score: score,
        maxScore: maxScore
      });
    }
  }

  return results;
}

module.exports = { SIGNATURES, matchSignature };
