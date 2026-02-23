/**
 * Sentinel v4 — Library Signature Database
 * Known fingerprinting library patterns for attribution
 */

const LIBRARY_SIGNATURES = {
  fingerprintjs: {
    name: 'FingerprintJS',
    patterns: [
      { apis: ['isPointInPath', 'toDataURL'], category: 'canvas', weight: 3 },
      { apis: ['startRendering', 'createOscillator', 'createDynamicsCompressor'], category: 'audio', weight: 3 },
      { apis: ['getParameter', 'getSupportedExtensions', 'getShaderPrecisionFormat'], category: 'webgl', weight: 2 },
      { apis: ['measureText', 'getBoundingClientRect'], category: 'font', weight: 2 },
      { apis: ['Math.acos', 'Math.expm1', 'Math.log1p'], category: 'math', weight: 2 },
    ],
    burstWindow: 5000,
    minScore: 8,
    description: 'Commercial fingerprinting library by FingerprintJS Inc (v3-v5)'
  },
  creepjs: {
    name: 'CreepJS',
    patterns: [
      { apis: ['toString', 'getOwnPropertyDescriptor'], category: 'prototype-probe', weight: 3 },
      { apis: ['HTMLElement.prototype', 'Navigator.prototype'], category: 'lie-detection', weight: 3 },
      { apis: ['OffscreenCanvas', 'getContext'], category: 'offscreen-canvas', weight: 2 },
      { apis: ['speechSynthesis.getVoices'], category: 'speech', weight: 2 },
      { apis: ['Intl.ListFormat', 'Intl.RelativeTimeFormat'], category: 'intl', weight: 2 },
    ],
    burstWindow: 8000,
    minScore: 7,
    description: 'Open-source advanced fingerprinting tool with lie detection'
  },
  botd: {
    name: 'BotD',
    patterns: [
      { apis: ['webdriver', 'languages', 'plugins'], category: 'bot-detection', weight: 2 },
      { apis: ['chrome.runtime', 'chrome.app'], category: 'automation-check', weight: 3 },
      { apis: ['Error.stack', 'Error.prepareStackTrace'], category: 'stack-analysis', weight: 3 },
    ],
    burstWindow: 3000,
    minScore: 5,
    description: 'Bot detection library by FingerprintJS Inc'
  },
  browserscan: {
    name: 'BrowserScan',
    patterns: [
      { apis: ['getParameter', 'toDataURL', 'userAgent'], category: 'full-scan', weight: 1 },
      { apis: ['enumerateDevices', 'RTCPeerConnection'], category: 'media-webrtc', weight: 2 },
      { apis: ['getBattery', 'deviceMemory', 'hardwareConcurrency'], category: 'hardware', weight: 2 },
    ],
    burstWindow: 10000,
    minScore: 4,
    description: 'Browser fingerprint scanning service'
  },
  clientjs: {
    name: 'ClientJS',
    patterns: [
      { apis: ['userAgent', 'plugins', 'mimeTypes'], category: 'legacy-fp', weight: 1 },
      { apis: ['colorDepth', 'screenResolution'], category: 'screen', weight: 1 },
    ],
    burstWindow: 2000,
    minScore: 3,
    description: 'Legacy fingerprinting library'
  }
};

const EXFIL_PATTERNS = {
  fpjsCollector: {
    urlPatterns: [/api\.fpjs\.io/, /fpjs\.pro/, /fingerprint\.com/],
    payloadSignature: 'requestId',
    name: 'FingerprintJS Pro Collector'
  },
  googleAnalytics: {
    urlPatterns: [/google-analytics\.com/, /analytics\.google\.com/, /gtag/],
    payloadSignature: 'tid=',
    name: 'Google Analytics'
  },
  facebook: {
    urlPatterns: [/facebook\.com\/tr/, /connect\.facebook/, /fbevents/],
    payloadSignature: 'fbp',
    name: 'Facebook Pixel'
  },
  generic: {
    urlPatterns: [/collect/, /beacon/, /telemetry/, /track/, /pixel/, /log/],
    payloadSignature: null,
    name: 'Generic Tracker'
  }
};

module.exports = { LIBRARY_SIGNATURES, EXFIL_PATTERNS };
