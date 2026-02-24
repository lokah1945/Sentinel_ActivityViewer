/**
 * Sentinel v4.2 — Library Signature Database (Upgraded)
 * Known fingerprinting library patterns for attribution
 * 
 * UPGRADES from v4:
 * - FingerprintJS v5 full 41-source signature
 * - CreepJS 2024-2026 signature with lie detection
 * - WASM-based fingerprinting patterns
 * - Enhanced exfiltration patterns (Beacon, WebSocket, etc.)
 * - CDN URL patterns for known services
 */

const LIBRARY_SIGNATURES = {
  fingerprintjs_v5: {
    name: 'FingerprintJS v5',
    patterns: [
      { apis: ['isPointInPath', 'toDataURL', 'getImageData', 'fillText'], category: 'canvas', weight: 4 },
      { apis: ['startRendering', 'createOscillator', 'createDynamicsCompressor'], category: 'audio', weight: 4 },
      { apis: ['getParameter', 'getSupportedExtensions', 'getShaderPrecisionFormat'], category: 'webgl', weight: 3 },
      { apis: ['measureText', 'getBoundingClientRect', 'document.fonts.check'], category: 'font', weight: 3 },
      { apis: ['Math.acos', 'Math.expm1', 'Math.log1p', 'Math.atanh'], category: 'math', weight: 3 },
      { apis: ['hardwareConcurrency', 'deviceMemory', 'platform', 'languages'], category: 'navigator', weight: 2 },
      { apis: ['colorDepth', 'width', 'height', 'availWidth'], category: 'screen', weight: 2 },
      { apis: ['matchMedia'], category: 'css-fingerprint', weight: 2 },
      { apis: ['resolvedOptions'], category: 'intl-fingerprint', weight: 2 },
      { apis: ['pdfViewerEnabled', 'cookieEnabled', 'vendor'], category: 'navigator-ext', weight: 1 },
      { apis: ['baseLatency', 'sampleRate'], category: 'audio-advanced', weight: 2 },
    ],
    burstWindow: 15000,
    minScore: 12,
    description: 'Commercial fingerprinting library by FingerprintJS Inc (v5 — 41 entropy sources)'
  },
  fingerprintjs: {
    name: 'FingerprintJS (v3/v4)',
    patterns: [
      { apis: ['isPointInPath', 'toDataURL'], category: 'canvas', weight: 3 },
      { apis: ['startRendering', 'createOscillator', 'createDynamicsCompressor'], category: 'audio', weight: 3 },
      { apis: ['getParameter', 'getSupportedExtensions', 'getShaderPrecisionFormat'], category: 'webgl', weight: 2 },
      { apis: ['measureText', 'getBoundingClientRect'], category: 'font', weight: 2 },
      { apis: ['Math.acos', 'Math.expm1', 'Math.log1p'], category: 'math', weight: 2 },
    ],
    burstWindow: 5000,
    minScore: 8,
    description: 'Commercial fingerprinting library by FingerprintJS Inc (v3/v4)'
  },
  creepjs: {
    name: 'CreepJS',
    patterns: [
      { apis: ['Object.getOwnPropertyNames', 'Object.keys'], category: 'property-enum', weight: 3 },
      { apis: ['speechSynthesis.getVoices'], category: 'speech', weight: 3 },
      { apis: ['OffscreenCanvas.getContext', 'transferToImageBitmap'], category: 'offscreen-canvas', weight: 3 },
      { apis: ['Intl.ListFormat', 'Intl.RelativeTimeFormat', 'Intl.PluralRules'], category: 'intl', weight: 2 },
      { apis: ['CSS.supports'], category: 'css-fingerprint', weight: 2 },
      { apis: ['matchMedia'], category: 'media-query', weight: 2 },
      { apis: ['getHighEntropyValues', 'brands'], category: 'client-hints', weight: 2 },
      { apis: ['toDataURL', 'getParameter'], category: 'core-fp', weight: 1 },
    ],
    burstWindow: 10000,
    minScore: 8,
    description: 'Open-source advanced fingerprinting tool with 40+ categories and lie detection'
  },
  botd: {
    name: 'BotD',
    patterns: [
      { apis: ['webdriver', 'languages', 'plugins'], category: 'bot-detection', weight: 2 },
      { apis: ['chrome.runtime', 'chrome.app'], category: 'automation-check', weight: 3 },
    ],
    burstWindow: 3000,
    minScore: 4,
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
  wasm_fingerprint: {
    name: 'WASM Fingerprinter',
    patterns: [
      { apis: ['WebAssembly.compile', 'WebAssembly.instantiate', 'WebAssembly.compileStreaming'], category: 'webassembly', weight: 5 },
      { apis: ['WebAssembly.Module', 'WebAssembly.Instance'], category: 'wasm-core', weight: 3 },
      { apis: ['WebAssembly.Memory', 'WebAssembly.Table'], category: 'wasm-memory', weight: 2 },
    ],
    burstWindow: 5000,
    minScore: 5,
    description: 'WASM-based fingerprinting — uses WebAssembly execution timing for device identification'
  }
};

const EXFIL_PATTERNS = {
  fpjsCollector: {
    urlPatterns: [/api\.fpjs\.io/, /fpjs\.pro/, /fingerprint\.com/, /fpcdn\.io/, /cdn\.fpjs\.io/],
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
  tiktok: {
    urlPatterns: [/analytics\.tiktok\.com/, /tiktok\.com\/i18n/],
    payloadSignature: null,
    name: 'TikTok Pixel'
  },
  generic: {
    urlPatterns: [/collect/, /beacon/, /telemetry/, /track/, /pixel/, /log/, /ingest/],
    payloadSignature: null,
    name: 'Generic Tracker'
  }
};

module.exports = { LIBRARY_SIGNATURES, EXFIL_PATTERNS };
