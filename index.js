#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║   SENTINEL v4.2.1 — FORENSIC MALING CATCHER                   ║
 * ║   ZERO ESCAPE ARCHITECTURE                                   ║
 * ║   7-Layer | 37 Categories | 1H5W | Triple Injection          ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * UPGRADES from v4:
 * [BUG-04] Default timeout 60s, adaptive up to 120s
 * [BUG-05] Enhanced dedup: ts-api-frameId-argHash-seqCounter
 * [BUG-06] CDP Target.setAutoAttach for cross-origin iframes + workers
 * [BUG-07] Final flush mechanism before browser close
 * [ARCH-01] Triple injection (CDP primary + addInitScript + per-target)
 * [ARCH-03] Adaptive timeout (+15s if activity in last 5s, max 120s)
 * [ARCH-04] Sliding window dedup (50ms window)
 *
 * LAYER 1: CDP Injection (Page.addScriptToEvaluateOnNewDocument)
 * LAYER 2: addInitScript Backup
 * LAYER 3: Per-Target CDP Injection (cross-origin + workers)
 * LAYER 4: Anti-Detection Shield
 * LAYER 5: Core + Extended Hooks (37 categories)
 * LAYER 6: Behavior Correlation
 * LAYER 7: 1H5W Forensic Reporting
 *
 * Usage:
 *   node index.js                        — Interactive mode
 *   node index.js <url>                  — Quick scan (stealth default)
 *   node index.js <url> --stealth        — Stealth mode (default)
 *   node index.js <url> --observe        — Observe mode (no stealth)
 *   node index.js <url> --dual-mode      — Run BOTH modes & compare
 *   node index.js <url> --timeout=60000  — Custom timeout (ms)
 *   node index.js <url> --headless       — Headless mode
 *   node index.js <url> --cdp            — Force CDP injection (recommended)
 */

const { createStealthPlugin, getExtraStealthScript } = require('./hooks/stealth-config');
const { getAntiDetectionScript } = require('./hooks/anti-detection-shield');
const { getInterceptorScript } = require('./hooks/api-interceptor');
const { generateReport } = require('./reporters/report-generator');
const readline = require('readline');
const path = require('path');

// ── Parse CLI arguments ──
const args = process.argv.slice(2);
const flags = {};
let targetUrl = null;

for (const arg of args) {
  if (arg.startsWith('--')) {
    const [key, val] = arg.slice(2).split('=');
    flags[key] = val || true;
  } else if (!targetUrl) {
    targetUrl = arg;
  }
}

// [BUG-04 FIX] Default timeout 60000ms (was 30000ms)
const BASE_TIMEOUT = parseInt(flags.timeout) || 60000;
const MAX_TIMEOUT = 120000; // Hard cap for adaptive timeout
const ADAPTIVE_EXTEND = 15000; // Extend by 15s if activity detected
const ACTIVITY_CHECK_INTERVAL = 5000; // Check every 5s
const GRACE_PERIOD = 3000; // Final grace period before close

const HEADLESS = flags.headless === true || flags.headless === 'true';
const DUAL_MODE = flags['dual-mode'] === true;
const STEALTH_MODE = flags.observe ? false : true;
const USE_CDP = flags.cdp !== false; // CDP injection enabled by default

// Global sequence counter for dedup
let globalSeqCounter = 0;

function normalizeUrl(input) {
  input = input.trim();
  if (!input.match(/^https?:\/\//i)) {
    input = 'https://' + input;
  }
  return input;
}

async function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(function(resolve) {
    rl.question(question, function(answer) {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * [ARCH-01] Triple Injection System
 * Layer 1: CDP Page.addScriptToEvaluateOnNewDocument (primary)
 * Layer 2: page.addInitScript (backup)
 * Layer 3: Per-target CDP injection (cross-origin iframes + workers)
 */
async function setupTripleInjection(page, scripts, options) {
  const result = {
    cdpSession: null,
    pushEvents: [],
    attachedTargets: [],
    injectionFlags: { L1: false, L2: false, L3: false }
  };

  try {
    // ═══ LAYER 1: CDP Primary Injection ═══
    const cdpSession = await page.context().newCDPSession(page);
    result.cdpSession = cdpSession;

    for (const script of scripts) {
      await cdpSession.send('Page.addScriptToEvaluateOnNewDocument', {
        source: '/* SENTINEL_L1 */ window.__SENTINEL_L1__ = true;\n' + script
      });
    }
    result.injectionFlags.L1 = true;
    console.log('  ✅ Layer 1 (CDP) — Scripts injected into MAIN world');

    // Setup Runtime.addBinding for push-based telemetry
    try {
      await cdpSession.send('Runtime.addBinding', { name: '__SENTINEL_PUSH__' });
    } catch(e) { /* Binding may already exist */ }

    // Listen for push telemetry
    cdpSession.on('Runtime.bindingCalled', function(params) {
      if (params.name === '__SENTINEL_PUSH__') {
        try {
          const data = JSON.parse(params.payload);
          if (data.type === 'event_batch' && Array.isArray(data.events)) {
            data.events.forEach(function(evt) {
              evt._seqId = globalSeqCounter++;
              evt._source = 'push';
            });
            result.pushEvents.push.apply(result.pushEvents, data.events);
          }
        } catch(e) {}
      }
    });

    // ═══ LAYER 3: CDP Target.setAutoAttach for cross-origin + workers ═══
    // [BUG-06 FIX] + [ARCH-02]
    try {
      await cdpSession.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: false,
        flatten: true
      });

      cdpSession.on('Target.attachedToTarget', async function(params) {
        const targetInfo = params.targetInfo;
        result.attachedTargets.push({
          targetId: targetInfo.targetId,
          type: targetInfo.type,
          url: targetInfo.url
        });
        result.injectionFlags.L3 = true;
        // Note: scripts injected via Page.addScriptToEvaluateOnNewDocument 
        // on the parent session automatically apply to child frames.
        // waitForDebuggerOnStart is false, so targets run normally.
      });

      console.log('  ✅ Layer 3 (Per-Target) — Auto-attach active for iframes + workers');
    } catch(e) {
      console.warn('  ⚠️  Layer 3 setup failed:', e.message);
    }

  } catch(err) {
    console.warn('  ⚠️  CDP injection setup failed:', err.message);
  }

  // ═══ LAYER 2: addInitScript Backup ═══
  // [ARCH-01] Belt-and-suspenders — always inject as backup
  try {
    for (const script of scripts) {
      await page.addInitScript('/* SENTINEL_L2 */ window.__SENTINEL_L2__ = true;\n' + script);
    }
    result.injectionFlags.L2 = true;
    console.log('  ✅ Layer 2 (addInitScript) — Backup injection active');
  } catch(e) {
    console.warn('  ⚠️  Layer 2 addInitScript failed:', e.message);
  }

  return result;
}

/**
 * [ARCH-04] Enhanced Deduplication Engine
 * Multi-factor dedup key with sliding window
 */
function deduplicateEvents(events) {
  const DEDUP_WINDOW_MS = 50; // Only dedup within 50ms window
  const sorted = events.slice().sort(function(a, b) { return (a.ts || 0) - (b.ts || 0); });
  const kept = [];
  const stats = { totalReceived: events.length, deduplicated: 0, kept: 0 };

  for (let i = 0; i < sorted.length; i++) {
    const evt = sorted[i];
    // Build dedup key: ts + api + frameId + argFingerprint
    const argHash = evt.valueHash || evt.argHash || '';
    const dedupKey = (evt.ts || 0) + '-' + (evt.api || '') + '-' + (evt.frameId || '') + '-' + argHash;

    // Check sliding window: only compare against events within DEDUP_WINDOW_MS
    let isDupe = false;
    for (let j = kept.length - 1; j >= 0; j--) {
      const prev = kept[j];
      if ((evt.ts || 0) - (prev.ts || 0) > DEDUP_WINDOW_MS) break;
      const prevKey = (prev.ts || 0) + '-' + (prev.api || '') + '-' + (prev.frameId || '') + '-' + (prev.valueHash || prev.argHash || '');
      if (dedupKey === prevKey) {
        isDupe = true;
        break;
      }
    }

    if (!isDupe) {
      evt._seqId = evt._seqId || globalSeqCounter++;
      kept.push(evt);
    } else {
      stats.deduplicated++;
    }
  }

  stats.kept = kept.length;
  return { events: kept, stats: stats };
}

/**
 * [BUG-07 FIX] Final flush mechanism
 * Forces one last push of pending events before scan ends
 */
async function finalFlush(page) {
  try {
    return await page.evaluate(function() {
      if (window.__SENTINEL_DATA__ && typeof window.__SENTINEL_FLUSH__ === 'function') {
        window.__SENTINEL_FLUSH__();
      }
      return {
        events: (window.__SENTINEL_DATA__ && window.__SENTINEL_DATA__.events) ? window.__SENTINEL_DATA__.events : [],
        bootOk: window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.bootOk : false,
        frameId: window.__SENTINEL_DATA__ ? window.__SENTINEL_DATA__.frameId : '',
        injectionFlags: {
          L1: !!window.__SENTINEL_L1__,
          L2: !!window.__SENTINEL_L2__,
          L3: !!window.__SENTINEL_L3__
        }
      };
    });
  } catch(e) {
    return { events: [], bootOk: false, frameId: '', injectionFlags: {} };
  }
}

async function runScan(url, options) {
  options = options || {};
  const stealthEnabled = options.stealth !== false;
  const label = stealthEnabled ? '🥷 STEALTH' : '👁️ OBSERVE';

  console.log('\n' + '═'.repeat(65));
  console.log('  ' + label + ' MODE — Sentinel v4.2.1 Forensic Scan');
  console.log('  Target: ' + url);
  console.log('  Timeout: ' + (BASE_TIMEOUT / 1000) + 's (adaptive up to ' + (MAX_TIMEOUT / 1000) + 's) | Headless: ' + HEADLESS + ' | CDP: ' + USE_CDP);
  console.log('═'.repeat(65) + '\n');

  let browser, page, injectionResult = null;
  let lastEventTimestamp = Date.now();
  let currentTimeout = BASE_TIMEOUT;
  let timeoutExtended = false;
  let finalTimeout = BASE_TIMEOUT;

  try {
    // ── Launch browser ──
    if (stealthEnabled) {
      const { chromium } = require('playwright-extra');
      const stealthPlugin = createStealthPlugin();
      chromium.use(stealthPlugin);

      browser = await chromium.launch({
        headless: HEADLESS,
        args: [
          '--disable-blink-features=AutomationControlled',
          '--disable-features=IsolateOrigins,site-per-process',
          '--disable-web-security',
          '--no-first-run',
          '--no-default-browser-check',
        ]
      });

      const context = await browser.newContext({
        viewport: { width: 1920, height: 1080 },
        locale: 'en-US',
        timezoneId: 'Asia/Jakarta',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        permissions: [],
        colorScheme: 'light',
      });

      page = await context.newPage();
    } else {
      const { chromium } = require('playwright');

      browser = await chromium.launch({ headless: HEADLESS });
      const context = await browser.newContext({
        viewport: { width: 1920, height: 1080 },
      });
      page = await context.newPage();
    }

    // ── [ARCH-01] Triple Injection Setup ──
    const scripts = [
      getAntiDetectionScript(),
      getInterceptorScript({ timeout: currentTimeout })
    ];

    if (stealthEnabled) {
      scripts.push(getExtraStealthScript());
    }

    console.log('💉 Setting up Triple Injection...');
    injectionResult = await setupTripleInjection(page, scripts, { stealth: stealthEnabled });

    // ── Frame monitoring: safe fallback for late-attached frames ──
    page.on('frameattached', async function(frame) {
      try {
        await frame.evaluate(
          getAntiDetectionScript() + ';\n' +
          getInterceptorScript({ timeout: currentTimeout })
        );
      } catch (e) {
        // Cross-origin frames handled by Layer 3 CDP auto-attach
      }
    });

    // ── Navigate ──
    console.log('🌐 Navigating to target...');
    await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: currentTimeout
    });

    // ── [ARCH-03] Adaptive Timeout System ──
    console.log('⏳ Observing activity (adaptive timeout)...');

    const scanStartTime = Date.now();
    let totalElapsed = 0;

    // Track push events to detect ongoing activity
    const activityChecker = setInterval(function() {
      totalElapsed = Date.now() - scanStartTime;
      const pushCount = injectionResult ? injectionResult.pushEvents.length : 0;

      // Update lastEventTimestamp if new push events arrived
      if (pushCount > 0) {
        const lastPush = injectionResult.pushEvents[pushCount - 1];
        if (lastPush && lastPush.ts) {
          lastEventTimestamp = Date.now();
        }
      }

      // Adaptive extension: if activity in last 5s AND we haven't hit max
      const timeSinceLastEvent = Date.now() - lastEventTimestamp;
      if (timeSinceLastEvent < ACTIVITY_CHECK_INTERVAL && currentTimeout < MAX_TIMEOUT) {
        const newTimeout = Math.min(currentTimeout + ADAPTIVE_EXTEND, MAX_TIMEOUT);
        if (newTimeout > currentTimeout) {
          console.log('  🔄 Activity detected — extending timeout to ' + (newTimeout / 1000) + 's');
          currentTimeout = newTimeout;
          timeoutExtended = true;
        }
      }
    }, ACTIVITY_CHECK_INTERVAL);

    // Main observation loop
    const observeTime = Math.max(BASE_TIMEOUT - 8000, 15000);
    await page.waitForTimeout(observeTime);

    // Check if we should extend
    let additionalWait = currentTimeout - BASE_TIMEOUT;
    if (additionalWait > 0) {
      console.log('  ⏱️  Extended observation: +' + (additionalWait / 1000) + 's');
      await page.waitForTimeout(Math.min(additionalWait, MAX_TIMEOUT - BASE_TIMEOUT));
    }

    clearInterval(activityChecker);
    finalTimeout = currentTimeout;

    // ── Trigger lazy-loaded fingerprinting via scroll ──
    try {
      await page.evaluate(function() { window.scrollTo(0, document.body.scrollHeight / 2); });
      await page.waitForTimeout(1500);
      await page.evaluate(function() { window.scrollTo(0, document.body.scrollHeight); });
      await page.waitForTimeout(1500);
    } catch(e) {}

    // ── [BUG-07 FIX] Final Flush ──
    console.log('🔄 Final flush...');
    let sentinelData = await finalFlush(page);

    // ── Grace Period ──
    console.log('⏳ Grace period (' + (GRACE_PERIOD / 1000) + 's)...');
    await page.waitForTimeout(GRACE_PERIOD);

    // Second flush after grace period
    let graceData;
    try {
      graceData = await page.evaluate(function() {
        return {
          events: (window.__SENTINEL_DATA__ && window.__SENTINEL_DATA__.events) ? window.__SENTINEL_DATA__.events : [],
          injectionFlags: {
            L1: !!window.__SENTINEL_L1__,
            L2: !!window.__SENTINEL_L2__,
            L3: !!window.__SENTINEL_L3__
          }
        };
      });
    } catch(e) {
      graceData = { events: [] };
    }

    // ── Merge push telemetry (fallback only if page eval returned nothing) ──
    var pageEventCount = (sentinelData.events || []).length;
    var pushEventCount = injectionResult ? injectionResult.pushEvents.length : 0;

    if (pageEventCount === 0 && pushEventCount > 0) {
      // Page eval failed but push telemetry worked — use push events
      console.log('  📡 Using push telemetry (page eval empty): ' + pushEventCount + ' events');
      sentinelData.events = injectionResult.pushEvents;
    } else if (pageEventCount > 0 && pushEventCount > 0) {
      console.log('  📡 Page eval: ' + pageEventCount + ' events | Push: ' + pushEventCount + ' events (using page eval as primary)');
      // Don't merge — page eval has the complete set since push is non-destructive
    } else if (pageEventCount > 0) {
      console.log('  📊 Page eval: ' + pageEventCount + ' events');
    }

    // Grace period: only merge truly new events (different frameId or new events)
    if (graceData && graceData.events && graceData.events.length > pageEventCount) {
      var newGraceEvents = graceData.events.slice(pageEventCount);
      if (newGraceEvents.length > 0) {
        console.log('  ⏳ Grace period added: ' + newGraceEvents.length + ' new events');
        sentinelData.events = (sentinelData.events || []).concat(newGraceEvents);
      }
    }

    // Merge injection flags
    if (graceData && graceData.injectionFlags) {
      sentinelData.injectionFlags = sentinelData.injectionFlags || {};
      sentinelData.injectionFlags.L1 = sentinelData.injectionFlags.L1 || graceData.injectionFlags.L1;
      sentinelData.injectionFlags.L2 = sentinelData.injectionFlags.L2 || graceData.injectionFlags.L2;
      sentinelData.injectionFlags.L3 = sentinelData.injectionFlags.L3 || graceData.injectionFlags.L3;
    }

    // Also merge injection flags from setupTripleInjection
    if (injectionResult) {
      sentinelData.injectionFlags = sentinelData.injectionFlags || {};
      sentinelData.injectionFlags.L1 = sentinelData.injectionFlags.L1 || injectionResult.injectionFlags.L1;
      sentinelData.injectionFlags.L2 = sentinelData.injectionFlags.L2 || injectionResult.injectionFlags.L2;
      sentinelData.injectionFlags.L3 = sentinelData.injectionFlags.L3 || injectionResult.injectionFlags.L3;
    }

    // ── Collect from child frames ──
    console.log('📊 Collecting forensic data from all frames...');
    const frames = page.frames();
    const frameContextMap = [];

    for (const frame of frames) {
      try {
        const frameData = await frame.evaluate(function() {
          if (window.__SENTINEL_DATA__) {
            return {
              events: window.__SENTINEL_DATA__.events || [],
              bootOk: window.__SENTINEL_DATA__.bootOk || false,
              frameId: window.__SENTINEL_DATA__.frameId || '',
              url: location.href,
              origin: location.origin,
              injL1: !!window.__SENTINEL_L1__,
              injL2: !!window.__SENTINEL_L2__,
              injL3: !!window.__SENTINEL_L3__
            };
          }
          return null;
        });

        if (frameData) {
          frameContextMap.push({
            type: 'frame',
            url: frameData.url,
            origin: frameData.origin,
            frameId: frameData.frameId,
            bootOk: frameData.bootOk,
            eventCount: frameData.events.length,
            injectionLayers: { L1: frameData.injL1, L2: frameData.injL2, L3: frameData.injL3 }
          });

          // Merge frame events (avoid duplicates from top frame)
          if (frameData.frameId !== sentinelData.frameId && frameData.events.length > 0) {
            sentinelData.events = sentinelData.events.concat(frameData.events);
          }
        }
      } catch(e) {
        frameContextMap.push({
          type: 'frame',
          url: frame.url(),
          origin: (function() { try { return new URL(frame.url() || 'about:blank').origin; } catch(x) { return 'unknown'; } })(),
          bootOk: false,
          eventCount: 0,
          error: 'cross-origin-access-denied'
        });
      }
    }

    // Also include auto-attached targets
    if (injectionResult && injectionResult.attachedTargets) {
      injectionResult.attachedTargets.forEach(function(t) {
        if (!frameContextMap.some(function(f) { return f.url === t.url; })) {
          frameContextMap.push({
            type: t.type,
            url: t.url,
            origin: (function() { try { return new URL(t.url || 'about:blank').origin; } catch(x) { return 'unknown'; } })(),
            bootOk: false,
            eventCount: 0,
            note: 'auto-attached-target'
          });
        }
      });
    }

    // Get page-level context map
    let pageContextMap = [];
    try {
      pageContextMap = await page.evaluate(function() {
        return window.__SENTINEL_CONTEXT_MAP__ || [];
      });
    } catch(e) {}

    const fullContextMap = pageContextMap.concat(frameContextMap);

    // ── [ARCH-04] Enhanced Deduplication ──
    console.log('🔄 Deduplicating events...');
    const dedupResult = deduplicateEvents(sentinelData.events || []);
    sentinelData.events = dedupResult.events;
    sentinelData.dedupStats = dedupResult.stats;

    const eventCount = sentinelData.events.length;
    console.log('\n✅ Scan complete! ' + eventCount + ' unique forensic events from ' + frameContextMap.length + ' frames');
    console.log('   (Dedup: ' + dedupResult.stats.totalReceived + ' received, ' + dedupResult.stats.deduplicated + ' dupes removed)');

    // ── Verify injection ──
    const bootOkCount = sentinelData.events.filter(function(e) { return e.api === 'BOOT_OK'; }).length;
    const l1Count = sentinelData.events.filter(function(e) { return e.api === 'SENTINEL_L1_OK'; }).length;
    if (bootOkCount === 0 && l1Count === 0) {
      console.log('⚠️  WARNING: No BOOT_OK / L1_OK received — injection may have failed!');
    } else {
      console.log('✅ Injection verified: ' + bootOkCount + ' BOOT_OK + ' + l1Count + ' L1_OK');
    }

    // ── Generate forensic report ──
    const reportResult = generateReport(sentinelData, fullContextMap, url, {
      stealthEnabled: stealthEnabled,
      prefix: 'sentinel_' + (stealthEnabled ? 'stealth' : 'observe') + '_' + Date.now(),
      timeoutExtended: timeoutExtended,
      finalTimeout: finalTimeout
    });

    // ── Print forensic summary ──
    const r = reportResult.reportJson;

    console.log('┌──────────────────────────────────────────────────────┐');
    console.log('│  🛡️ SENTINEL v4.2.1 FORENSIC SUMMARY                   │');
    console.log('├──────────────────────────────────────────────────────┤');
    console.log('│  Risk Score: ' + String(r.riskScore + '/100').padEnd(12) + ' ' + r.riskLevel.padEnd(20) + '│');
    console.log('│  Events: ' + String(r.totalEvents).padEnd(12) + ' Categories: ' + String(r.categoriesDetected + '/' + r.categoriesMonitored).padEnd(8) + '│');
    console.log('│  Origins: ' + String(r.uniqueOrigins.length).padEnd(11) + ' Threats: ' + String(r.threats.length).padEnd(10) + '│');
    console.log('│  Frames: ' + String((r.uniqueFrames || []).length).padEnd(12) + ' Coverage: ' + String((r.coverageProof ? r.coverageProof.coverage : 0) + '%').padEnd(8) + '│');
    console.log('│  Injection: ' + String(r.injectionStatus ? r.injectionStatus.verdict : 'UNKNOWN').padEnd(40) + '│');
    console.log('│  Timeout: ' + String(finalTimeout / 1000 + 's' + (timeoutExtended ? ' (extended)' : '')).padEnd(42) + '│');
    console.log('└──────────────────────────────────────────────────────┘');

    // 1H5W Summary
    if (r.forensic1H5W) {
      console.log('\n🔍 FORENSIC 1H5W:');
      console.log('  👤 WHO:   ' + r.forensic1H5W.WHO);
      console.log('  📋 WHAT:  ' + r.forensic1H5W.WHAT);
      console.log('  ⏱️  WHEN:  ' + r.forensic1H5W.WHEN);
      console.log('  📍 WHERE: ' + r.forensic1H5W.WHERE);
      console.log('  ❓ WHY:   ' + r.forensic1H5W.WHY);
      console.log('  🔧 HOW:   ' + r.forensic1H5W.HOW);
    }

    // Alerts
    if (r.alerts && r.alerts.length > 0) {
      console.log('\n⚠️  ALERTS:');
      r.alerts.forEach(function(a) {
        const icon = a.level === 'CRITICAL' ? '🔴' : a.level === 'HIGH' ? '🟡' : '🔵';
        console.log('  ' + icon + ' [' + a.type + '] ' + a.message);
      });
    }

    // Threats
    if (r.threats.length > 0) {
      console.log('\n🚨 THREATS (' + r.threats.length + '):');
      r.threats.forEach(function(t) {
        const icon = t.severity === 'CRITICAL' ? '🔴' : t.severity === 'HIGH' ? '🟡' : '🔵';
        console.log('  ' + icon + ' [' + t.severity + '] ' + t.type);
        if (t.who) console.log('     WHO: ' + t.who);
        console.log('     └─ ' + t.detail);
      });
    }

    // Coverage Matrix summary
    if (r.coverageMatrix) {
      const active = r.coverageMatrix.filter(function(c) { return c.status === 'ACTIVE'; });
      const silent = r.coverageMatrix.filter(function(c) { return c.status === 'SILENT'; });
      console.log('\n📊 DETECTION COVERAGE: ' + active.length + '/' + r.categoriesMonitored + ' (' + r.coveragePercent + '%)');
      if (silent.length > 0 && silent.length <= 10) {
        console.log('   Silent: ' + silent.map(function(c) { return c.category; }).join(', '));
      }
    }

    console.log('\n📁 Reports saved:');
    console.log('   JSON: ' + reportResult.jsonPath);
    console.log('   HTML: ' + reportResult.htmlPath);
    console.log('   CTX:  ' + reportResult.ctxPath);

    return reportResult;

  } catch (err) {
    console.error('❌ Scan error:', err.message);
    if (err.stack) console.error(err.stack.split('\n').slice(0, 5).join('\n'));
    throw err;
  } finally {
    if (injectionResult && injectionResult.cdpSession) {
      try { await injectionResult.cdpSession.detach(); } catch(e) {}
    }
    if (browser) {
      await browser.close();
      console.log('🔒 Browser closed.\n');
    }
  }
}

async function runDualMode(url) {
  console.log('\n🔄 DUAL MODE — Running both STEALTH and OBSERVE scans...\n');

  let stealthResult, observeResult;

  try {
    stealthResult = await runScan(url, { stealth: true });
  } catch (e) {
    console.error('Stealth scan failed:', e.message);
  }

  try {
    observeResult = await runScan(url, { stealth: false });
  } catch (e) {
    console.error('Observe scan failed:', e.message);
  }

  if (stealthResult && observeResult) {
    const s = stealthResult.reportJson;
    const o = observeResult.reportJson;

    console.log('\n' + '═'.repeat(65));
    console.log('  📊 DUAL MODE FORENSIC COMPARISON');
    console.log('═'.repeat(65));
    console.log('  ' + 'Metric'.padEnd(25) + ' ' + 'STEALTH'.padEnd(15) + ' ' + 'OBSERVE'.padEnd(15));
    console.log('  ' + '─'.repeat(55));
    console.log('  ' + 'Risk Score'.padEnd(25) + ' ' + String(s.riskScore).padEnd(15) + ' ' + String(o.riskScore).padEnd(15));
    console.log('  ' + 'Total Events'.padEnd(25) + ' ' + String(s.totalEvents).padEnd(15) + ' ' + String(o.totalEvents).padEnd(15));
    console.log('  ' + 'Categories'.padEnd(25) + ' ' + String(s.categoriesDetected + '/' + s.categoriesMonitored).padEnd(15) + ' ' + String(o.categoriesDetected + '/' + o.categoriesMonitored).padEnd(15));
    console.log('  ' + 'Origins'.padEnd(25) + ' ' + String(s.uniqueOrigins.length).padEnd(15) + ' ' + String(o.uniqueOrigins.length).padEnd(15));
    console.log('  ' + 'Threats'.padEnd(25) + ' ' + String(s.threats.length).padEnd(15) + ' ' + String(o.threats.length).padEnd(15));
    console.log('  ' + 'Coverage %'.padEnd(25) + ' ' + String(s.coveragePercent + '%').padEnd(15) + ' ' + String(o.coveragePercent + '%').padEnd(15));
    console.log('  ' + 'FP Bursts'.padEnd(25) + ' ' + String(s.correlation ? s.correlation.summary.fingerprintBursts : 0).padEnd(15) + ' ' + String(o.correlation ? o.correlation.summary.fingerprintBursts : 0).padEnd(15));
    console.log('  ' + 'Injection'.padEnd(25) + ' ' + String(s.injectionStatus ? s.injectionStatus.verdict : '?').padEnd(15) + ' ' + String(o.injectionStatus ? o.injectionStatus.verdict : '?').padEnd(15));

    const sCats = new Set(Object.keys(s.byCategory));
    const oCats = new Set(Object.keys(o.byCategory));
    const onlyInStealth = Array.from(sCats).filter(function(c) { return !oCats.has(c); });
    const onlyInObserve = Array.from(oCats).filter(function(c) { return !sCats.has(c); });

    if (onlyInStealth.length > 0) {
      console.log('\n  📌 Only in STEALTH: ' + onlyInStealth.join(', '));
    }
    if (onlyInObserve.length > 0) {
      console.log('  📌 Only in OBSERVE: ' + onlyInObserve.join(', '));
    }

    const delta = s.totalEvents - o.totalEvents;
    if (Math.abs(delta) > 50) {
      console.log('\n  ⚠️  Significant delta: ' + (delta > 0 ? '+' : '') + delta + ' events');
      console.log('     Website likely behaves differently based on automation detection.');
    }

    console.log('\n' + '═'.repeat(65));
  }
}

// ── Main ──
(async function() {
  console.log('\n  ╔══════════════════════════════════════════════════════════════╗');
  console.log('  ║   🛡️  SENTINEL v4.2.1 — FORENSIC MALING CATCHER               ║');
  console.log('  ║   Zero Escape Architecture | 37 API Categories               ║');
  console.log('  ║   Triple Injection | Adaptive Timeout | Enhanced Dedup        ║');
  console.log('  ║   FPv5 + CreepJS + WASM Detection | 1H5W Framework           ║');
  console.log('  ╚══════════════════════════════════════════════════════════════╝\n');

  if (!targetUrl) {
    targetUrl = await prompt('🎯 Target website (e.g. browserscan.net): ');
  }

  if (!targetUrl) {
    console.log('No target specified. Exiting.');
    process.exit(1);
  }

  const url = normalizeUrl(targetUrl);

  if (DUAL_MODE) {
    await runDualMode(url);
  } else {
    await runScan(url, { stealth: STEALTH_MODE });
  }
})();
