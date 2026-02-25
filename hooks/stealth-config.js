// ═══════════════════════════════════════════════════════════════
//  SENTINEL v7.0.0 — STEALTH CONFIGURATION (MINIMAL)
// ═══════════════════════════════════════════════════════════════
// CHANGE LOG v7.0.0 (2026-02-26):
//   - PURE NEW: Minimal stealth config, REG-009 compliant (< 100 lines)
//   - FROM v6.4: puppeteer-extra-plugin-stealth with all evasions
//   - REMOVED: Extra stealth script (getExtraStealthScript removed)
//   - REMOVED: All spoofing code (ZERO SPOOF policy)
//   - NOTE: REG-008 compliant (no perms query wrapper)
//   - NOTE: Runs on OS-native browser, no cross-platform, no spoof UA,
//           no spoof TLS fingerprinting
//
// LAST HISTORY LOG:
//   v6.4.0: stealth-config.js with extra stealth script (spoofing)
//   v6.1.0: Similar stealth config
//   v7.0.0: Stripped to minimum — stealth plugin only, ZERO spoofing
// ═══════════════════════════════════════════════════════════════

'use strict';

var StealthPlugin = require('puppeteer-extra-plugin-stealth');

function createStealthPlugin() {
  var stealth = StealthPlugin();
  return stealth;
}

module.exports = { createStealthPlugin };
