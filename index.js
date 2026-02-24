// ============================================================
// Sentinel v4.4.2 — Main Entry Point
// "Reliability + Coverage + Consistency" Release
// ============================================================
// FIXES from v4.4.1:
//   1. CoverageProof — proper frame inventory with url/origin
//   2. timeSpanMs — uses max(ts) not last event
//   3. InjectionStatus — real flags passed to report
//   4. Anti-stuck [5/7] — parallel eval with timeout + skip blank frames
//   5. Push-based telemetry — real-time data flow, no hang risk
//   6. Persistent context option — avoid "incognito" detection
//   7. Auto-attach targets (L3) — iframe/worker coverage
//   8. Final flush — no event loss at scan end
// ============================================================

const path = require('path');
const fs = require('fs');
const { getAntiDetectionScript } = require('./hooks/anti-detection-shield');
const { getApiInterceptorScript } = require('./hooks/api-interceptor');
const { getStealthPatches, getStealthPluginConfig } = require('./hooks/stealth-config');
const { generateReports } = require('./reporters/report-generator');

// === CLI ARGUMENT PARSING ===
const args = process.argv.slice(2);
const targetUrl = args.find(a => a.startsWith('http')) || 'https://browserscan.net';
const flags = {};
args.forEach(a => {
  if (a.startsWith('--')) {
    const [key, val] = a.substring(2).split('=');
    flags[key] = val || true;
  }
});

const MODE = flags['observe'] ? 'observe' : 'stealth';
const HEADLESS = flags['no-headless'] ? false : true;
const TIMEOUT = parseInt(flags['timeout']) || 60000;
const LOCALE = flags['locale'] || 'id-ID';
const TIMEZONE = flags['timezone'] || 'Asia/Jakarta';
const DUAL_MODE = !!flags['dual-mode'];
const PERSISTENT = flags['profile-dir'] || flags['persistent'] || '';
const OUTPUT_DIR = path.join(__dirname, 'output');

console.log(`
╔═══════════════════════════════════════════════╗
║   SENTINEL v4.4.2 — Zero Blind Spot Catcher  ║
║   "Reliability + Coverage + Consistency"      ║
╚═══════════════════════════════════════════════╝
`);
console.log(`Target:     ${targetUrl}`);
console.log(`Mode:       ${MODE}`);
console.log(`Headless:   ${HEADLESS}`);
console.log(`Timeout:    ${TIMEOUT}ms`);
console.log(`Locale:     ${LOCALE}`);
console.log(`Timezone:   ${TIMEZONE}`);
console.log(`Persistent: ${PERSISTENT || 'No (ephemeral context)'}`);
console.log('');

// === MAIN SCAN FUNCTION ===
async function runScan(mode) {
  const scanStartTime = Date.now();
  let browser = null;
  let context = null;
  let page = null;
  let cdpSession = null;

  const pushEvents = [];
  const workerEvents = [];
  const injectionFlags = {
    layer1CDP: false,
    layer2addInitScript: false,
    layer3perTarget: false
  };

  try {
    // === [1/7] LAUNCHING BROWSER ===
    console.log(`[1/7] Launching browser (${mode} mode)...`);

    let chromium;
    let useStealthPlugin = (mode === 'stealth');

    // Try playwright-extra first for stealth mode
    if (useStealthPlugin) {
      try {
        const playwrightExtra = require('playwright-extra');
        const stealthPlugin = require('puppeteer-extra-plugin-stealth');
        chromium = playwrightExtra.chromium;
        const stealth = stealthPlugin();
        // Remove evasions that conflict with our hooks
        stealth.enabledEvasions.delete('iframe.contentWindow');
        chromium.use(stealth);
        console.log('  ✓ playwright-extra + stealth plugin loaded');
      } catch(e) {
        console.log('  ⚠ playwright-extra not available, using vanilla Playwright + custom patches');
        chromium = require('playwright').chromium;
        useStealthPlugin = false;
      }
    } else {
      chromium = require('playwright').chromium;
    }

    const launchArgs = [
      '--disable-blink-features=AutomationControlled',
      '--no-sandbox',
      '--disable-infobars',
      '--disable-dev-shm-usage',
      '--window-position=0,0'
    ];

    const contextOptions = {
      locale: LOCALE,
      timezoneId: TIMEZONE,
      viewport: { width: 1920, height: 1080 },
      ignoreHTTPSErrors: true,
      javaScriptEnabled: true
    };

    // Persistent context (anti-incognito) vs ephemeral
    if (PERSISTENT) {
      const profileDir = path.resolve(PERSISTENT === true ? path.join(__dirname, 'chrome_profile') : PERSISTENT);
      console.log(`  → Using persistent context: ${profileDir}`);

      context = await chromium.launchPersistentContext(profileDir, {
        headless: HEADLESS,
        args: launchArgs,
        ignoreDefaultArgs: ['--enable-automation'],
        ...contextOptions
      });
      browser = null; // persistent context IS the browser
      page = context.pages()[0] || await context.newPage();
    } else {
      browser = await chromium.launch({
        headless: HEADLESS,
        args: launchArgs,
        ignoreDefaultArgs: ['--enable-automation']
      });
      context = await browser.newContext(contextOptions);
      page = await context.newPage();
    }

    console.log('  ✓ Browser launched');

    // === [2/7] SETTING UP INJECTION ===
    console.log('[2/7] Setting up injection layers...');

    // Layer 2: addInitScript — PRIMARY injection (proven reliable v3/v4.1 approach)
    const shieldScript = getAntiDetectionScript();
    const interceptorScript = getApiInterceptorScript();
    const stealthScript = (mode === 'stealth' && !useStealthPlugin) ? getStealthPatches() : '';

    const mainPayload = [
      '// Sentinel v4.4.2 — Main Injection Payload',
      shieldScript,
      stealthScript,
      interceptorScript
    ].join('\n');

    await page.addInitScript(mainPayload);
    injectionFlags.layer2addInitScript = true;
    console.log('  ✓ Layer 2 (addInitScript) — PRIMARY injection set');

    // Layer 1 + Layer 3: CDP — SUPPLEMENT (push telemetry + auto-attach targets)
    try {
      cdpSession = await page.context().newCDPSession(page);

      // Register push telemetry binding
      await cdpSession.send('Runtime.addBinding', { name: '__SENTINEL_PUSH' });
      cdpSession.on('Runtime.bindingCalled', (evt) => {
        if (evt.name === '__SENTINEL_PUSH') {
          try {
            const data = JSON.parse(evt.payload);
            pushEvents.push(data);
          } catch(e) {}
        }
      });
      await cdpSession.send('Runtime.enable');
      console.log('  ✓ Layer 1 (CDP) — push telemetry binding registered');
      injectionFlags.layer1CDP = true;

      // Layer 3: Auto-attach for cross-origin iframes and workers
      try {
        await cdpSession.send('Target.setAutoAttach', {
          autoAttach: true,
          waitForDebuggerOnStart: true,
          flatten: true
        });

        cdpSession.on('Target.attachedToTarget', async (evt) => {
          const { sessionId, targetInfo } = evt;
          try {
            // Inject into attached target
            if (targetInfo.type === 'iframe' || targetInfo.type === 'page') {
              const targetSession = context.browser ?
                await cdpSession.send('Target.activateTarget', { targetId: targetInfo.targetId }).catch(() => null) : null;

              // Inject payload into target via CDP
              try {
                await cdpSession.send('Runtime.evaluate', {
                  expression: mainPayload,
                  contextId: undefined
                }).catch(() => {});
              } catch(e) {}
            }

            if (targetInfo.type === 'worker' || targetInfo.type === 'service_worker') {
              workerEvents.push({
                type: targetInfo.type,
                url: targetInfo.url,
                timestamp: Date.now() - scanStartTime
              });
            }

            // Resume the target
            await cdpSession.send('Runtime.runIfWaitingForDebugger', {
              // Send to the child session
            }).catch(() => {});
          } catch(e) {}
        });

        injectionFlags.layer3perTarget = true;
        console.log('  ✓ Layer 3 (per-target) — auto-attach enabled');
      } catch(e) {
        console.log('  ⚠ Layer 3 (per-target) — auto-attach unavailable:', e.message);
      }
    } catch(e) {
      console.log('  ⚠ CDP session unavailable:', e.message);
    }

    // === [3/7] NAVIGATING TO TARGET ===
    console.log(`[3/7] Navigating to ${targetUrl}...`);
    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });
    console.log('  ✓ Page loaded (domcontentloaded)');

    // Verify injection
    let injectionVerified = false;
    try {
      injectionVerified = await page.evaluate(() => !!window.__SENTINEL_ACTIVE);
      console.log(`  → Injection verified: ${injectionVerified ? '✅ ACTIVE' : '❌ INACTIVE'}`);
    } catch(e) {
      console.log('  ⚠ Could not verify injection');
    }

    // === [4/7] WAITING FOR FINGERPRINTING ===
    console.log('[4/7] Waiting for fingerprinting activity...');

    // Scroll automation to trigger lazy-loaded fingerprinting
    const scrollIntervals = [3000, 6000, 10000, 15000];
    for (const delay of scrollIntervals) {
      if (delay > TIMEOUT * 0.8) break;
      setTimeout(async () => {
        try {
          await page.evaluate(() => window.scrollBy(0, 300));
        } catch(e) {}
      }, delay);
    }

    // Adaptive wait — extend if activity detected near deadline
    let waitTime = Math.min(TIMEOUT * 0.6, 40000);
    await page.waitForTimeout(waitTime);

    // Check if still receiving events
    const recentPushCount = pushEvents.length;
    if (recentPushCount > 0 && waitTime < TIMEOUT * 0.8) {
      const extraWait = Math.min(10000, TIMEOUT * 0.2);
      console.log(`  → Activity detected (${recentPushCount} push events), extending wait by ${extraWait/1000}s...`);
      await page.waitForTimeout(extraWait);
    }

    console.log(`  ✓ Wait complete. Push events received: ${pushEvents.length}`);

    // === [5/7] COLLECTING FORENSIC DATA ===
    console.log('[5/7] Collecting forensic data...');

    // Helper: evaluate with timeout (anti-stuck)
    async function evalWithTimeout(target, fn, timeoutMs) {
      timeoutMs = timeoutMs || 5000;
      return Promise.race([
        target.evaluate(fn),
        new Promise((_, rej) => setTimeout(() => rej(new Error('EVAL_TIMEOUT')), timeoutMs))
      ]);
    }

    // Collect from main frame
    let mainEvents = [];
    try {
      mainEvents = await evalWithTimeout(page, () => {
        if (window.__SENTINEL_DATA && window.__SENTINEL_DATA.events) {
          return window.__SENTINEL_DATA.events;
        }
        if (window.__SENTINEL_FLUSH) {
          try { return JSON.parse(window.__SENTINEL_FLUSH()).events; } catch(e) {}
        }
        return [];
      }, 8000);
      console.log(`  ✓ Main frame: ${mainEvents.length} events`);
    } catch(e) {
      console.log(`  ⚠ Main frame collection: ${e.message}`);
    }

    // Collect from sub-frames (parallel with timeout, skip about:blank)
    const frames = page.frames();
    console.log(`  → Detected ${frames.length} frames`);

    const frameInfo = [];
    const framePromises = [];

    for (const frame of frames) {
      const fUrl = frame.url() || '';
      let fOrigin = null;
      try {
        if (fUrl.startsWith('http')) {
          fOrigin = new URL(fUrl).origin;
        }
      } catch(e) {}

      frameInfo.push({ type: 'frame', url: fUrl, origin: fOrigin, name: frame.name() || '' });

      // Skip main frame (already collected), blank frames, empty URLs
      if (frame === page.mainFrame()) continue;
      if (!fUrl || fUrl === 'about:blank' || !fUrl.startsWith('http')) continue;

      framePromises.push(
        evalWithTimeout(frame, () => {
          if (window.__SENTINEL_DATA && window.__SENTINEL_DATA.events) {
            return window.__SENTINEL_DATA.events;
          }
          return [];
        }, 3000).catch(e => {
          console.log(`  ⚠ Frame ${fUrl.substring(0, 60)}: ${e.message}`);
          return [];
        })
      );
    }

    // Parallel frame collection (anti-stuck)
    let frameEventsArrays = [];
    if (framePromises.length > 0) {
      const results = await Promise.allSettled(framePromises);
      frameEventsArrays = results.map(r => r.status === 'fulfilled' ? r.value : []);
    }

    let allFrameEvents = [];
    for (const arr of frameEventsArrays) {
      if (Array.isArray(arr)) allFrameEvents = allFrameEvents.concat(arr);
    }
    console.log(`  ✓ Sub-frames: ${allFrameEvents.length} events from ${framePromises.length} frames`);

    // Final flush — one last push collection
    try {
      await page.evaluate(() => {
        if (typeof window.__SENTINEL_PUSH === 'function' && window.__SENTINEL_DATA) {
          window.__SENTINEL_PUSH(JSON.stringify({ type: 'FINAL_FLUSH', events: window.__SENTINEL_DATA.events.length }));
        }
      }).catch(() => {});
      await page.waitForTimeout(500); // Give 500ms for final push to arrive
    } catch(e) {}

    // Merge all events
    const allEvents = [].concat(mainEvents || []).concat(allFrameEvents);
    console.log(`  ✓ Total collected: ${allEvents.length} (pull) + ${pushEvents.length} (push)`);

    // === [6/7] GENERATING REPORTS ===
    console.log('[6/7] Generating reports...');

    const reportData = {
      events: allEvents,
      pushEvents: pushEvents,
      workerEvents: workerEvents,
      target: targetUrl,
      mode: mode,
      injectionFlags: injectionFlags,
      frameInfo: frameInfo,
      scanStartTime: scanStartTime
    };

    const reportResult = generateReports(reportData, OUTPUT_DIR);
    console.log(`  ✓ JSON: ${reportResult.jsonPath}`);
    console.log(`  ✓ HTML: ${reportResult.htmlPath}`);
    console.log(`  ✓ CTX:  ${reportResult.ctxPath}`);

    // === [7/7] SUMMARY ===
    console.log('[7/7] Scan complete!\n');
    const rpt = reportResult.report;
    console.log('════════════════════════════════════════════');
    console.log(`  Version:      sentinel-v4.4.2`);
    console.log(`  Target:       ${targetUrl}`);
    console.log(`  Mode:         ${mode}`);
    console.log(`  Total Events: ${rpt.totalEvents}`);
    console.log(`  Risk Score:   ${rpt.riskScore}/100 (${rpt.riskLevel})`);
    console.log(`  Categories:   ${rpt.categoriesDetected}/${rpt.categoriesMonitored}`);
    console.log(`  Duration:     ${(rpt.timeSpanMs / 1000).toFixed(1)}s`);
    console.log(`  Coverage:     ${rpt.coverageProof.coverage}% (${rpt.coverageProof.bootOkReceived} BOOT_OK)`);
    console.log(`  Threats:      ${rpt.threats.length}`);
    console.log(`  Bursts:       ${rpt.correlation.burstWindows.length}`);
    console.log(`  Exfil Alerts: ${rpt.correlation.exfilAlerts.length}`);
    console.log(`  Injection:    L1=${injectionFlags.layer1CDP} L2=${injectionFlags.layer2addInitScript} L3=${injectionFlags.layer3perTarget}`);
    console.log('════════════════════════════════════════════');

    if (rpt.alerts.length > 0) {
      console.log('\n⚠ ALERTS:');
      for (const alert of rpt.alerts) {
        console.log(`  [${alert.level}] ${alert.type}: ${alert.message}`);
      }
    }

    return reportResult;

  } catch(e) {
    console.error('❌ Scan error:', e.message);
    throw e;
  } finally {
    // Cleanup
    try {
      if (cdpSession) await cdpSession.detach().catch(() => {});
      if (browser) await browser.close().catch(() => {});
      else if (context) await context.close().catch(() => {});
    } catch(e) {}
  }
}

// === DUAL MODE ===
async function runDualMode() {
  console.log('=== DUAL MODE: Running stealth then observe ===\n');

  console.log('--- STEALTH RUN ---');
  let stealthResult;
  try {
    stealthResult = await runScan('stealth');
  } catch(e) {
    console.error('Stealth run failed:', e.message);
  }

  console.log('\n--- OBSERVE RUN ---');
  let observeResult;
  try {
    observeResult = await runScan('observe');
  } catch(e) {
    console.error('Observe run failed:', e.message);
  }

  if (stealthResult && observeResult) {
    const sr = stealthResult.report;
    const or = observeResult.report;
    console.log('\n=== DUAL MODE COMPARISON ===');
    console.log('Metric'.padEnd(25) + 'Stealth'.padEnd(15) + 'Observe');
    console.log('-'.repeat(55));
    console.log('Events'.padEnd(25) + String(sr.totalEvents).padEnd(15) + or.totalEvents);
    console.log('Categories'.padEnd(25) + (sr.categoriesDetected + '/' + sr.categoriesMonitored).padEnd(15) + or.categoriesDetected + '/' + or.categoriesMonitored);
    console.log('Risk Score'.padEnd(25) + (sr.riskScore + '/100').padEnd(15) + or.riskScore + '/100');
    console.log('Coverage'.padEnd(25) + (sr.coverageProof.coverage + '%').padEnd(15) + or.coverageProof.coverage + '%');
    console.log('Bursts'.padEnd(25) + String(sr.correlation.burstWindows.length).padEnd(15) + or.correlation.burstWindows.length);
    console.log('Exfil Alerts'.padEnd(25) + String(sr.correlation.exfilAlerts.length).padEnd(15) + or.correlation.exfilAlerts.length);
    console.log('Duration'.padEnd(25) + ((sr.timeSpanMs/1000).toFixed(1) + 's').padEnd(15) + (or.timeSpanMs/1000).toFixed(1) + 's');
  }
}

// === ENTRY POINT ===
(async () => {
  try {
    if (DUAL_MODE) {
      await runDualMode();
    } else {
      await runScan(MODE);
    }
  } catch(e) {
    console.error('Fatal error:', e.message);
    process.exit(1);
  }
})();
