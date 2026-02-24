/**
 * Sentinel Activity Viewer — V4.3
 * Zero Escape Architecture — Forensic Browser Fingerprint Detector
 *
 * ARCHITECTURE:
 *   Layer 1: Injection (CDP-primary, addInitScript-fallback — NOT both)
 *   Layer 2: Anti-Detection Shield (WeakMap descriptor cache)
 *   Layer 3: API Interceptor (200+ hooks, 37 categories)
 *   Layer 4: Stealth Config (counter-fingerprinting)
 *   Layer 5: Correlation Engine (burst/slow-probe/attribution)
 *   Layer 6: Signature DB (FPv5, CreepJS detection)
 *   Layer 7: Report Generator (JSON + HTML + 1H5W)
 *
 * CRITICAL FIX from v4.2.1:
 *   - Bug #8: Descriptor cache now target-qualified (WeakMap)
 *   - CDP + addInitScript are either/or (not both)
 *   - Error.prepareStackTrace cleanup restored
 *   - Object.getOwnPropertyDescriptors protection restored
 */

var playwright = require('playwright');
var path = require('path');
var stealthConfig = require('./hooks/stealth-config');
var antiDetectionShield = require('./hooks/anti-detection-shield');
var apiInterceptor = require('./hooks/api-interceptor');
var reportGenerator = require('./reporters/report-generator');

// ── CLI Argument Parsing ──
function parseArgs() {
  var args = process.argv.slice(2);
  var config = {
    url: '',
    mode: 'observe',
    timeout: 60000,
    maxTimeout: 120000,
    outputDir: path.join(__dirname, 'output'),
    headless: true
  };

  for (var i = 0; i < args.length; i++) {
    if (args[i] === '--url' && args[i + 1]) config.url = args[++i];
    else if (args[i] === '--mode' && args[i + 1]) config.mode = args[++i];
    else if (args[i] === '--timeout' && args[i + 1]) config.timeout = parseInt(args[++i], 10);
    else if (args[i] === '--max-timeout' && args[i + 1]) config.maxTimeout = parseInt(args[++i], 10);
    else if (args[i] === '--output' && args[i + 1]) config.outputDir = args[++i];
    else if (args[i] === '--headless') config.headless = args[i + 1] !== 'false';
    else if (args[i] === '--no-headless') config.headless = false;
  }

  config.stealthEnabled = config.mode === 'stealth';
  return config;
}

// ── Build combined injection script ──
function buildInjectionPayload(stealthEnabled) {
  var parts = [];

  // Anti-detection shield (always first)
  var shieldFn = antiDetectionShield.getAntiDetectionShield();
  parts.push('(' + shieldFn.toString() + ')();');

  // API interceptor
  var interceptorScript = apiInterceptor.getInterceptorScript({
    stealthEnabled: stealthEnabled
  });
  parts.push(interceptorScript);

  return parts.join('\n\n');
}

// ── Build stealth-only script (for addInitScript) ──
function buildStealthPayload() {
  return stealthConfig.getExtraStealthScript();
}

// ── Adaptive Timeout Logic ──
function AdaptiveTimeout(baseMs, maxMs) {
  this.baseMs = baseMs;
  this.maxMs = maxMs;
  this.lastEventCount = 0;
  this.extensions = 0;
  this.maxExtensions = 3;
  this.extensionMs = 15000;
  this.extended = false;
  this.finalTimeout = baseMs;
}

AdaptiveTimeout.prototype.checkAndExtend = function(currentEventCount) {
  if (this.extensions >= this.maxExtensions) return false;
  if (currentEventCount > this.lastEventCount + 20) {
    this.extensions++;
    this.finalTimeout = Math.min(this.finalTimeout + this.extensionMs, this.maxMs);
    this.lastEventCount = currentEventCount;
    this.extended = true;
    console.log('  [ADAPTIVE] Timeout extended to ' + (this.finalTimeout / 1000) + 's (extension ' + this.extensions + '/' + this.maxExtensions + ')');
    return true;
  }
  return false;
};

// ── Main Execution ──
async function main() {
  var config = parseArgs();

  if (!config.url) {
    console.log('Usage: node index.js --url <target-url> [--mode observe|stealth] [--timeout ms]');
    console.log('');
    console.log('Options:');
    console.log('  --url          Target URL to analyze (required)');
    console.log('  --mode         observe or stealth (default: observe)');
    console.log('  --timeout      Base timeout in ms (default: 60000)');
    console.log('  --max-timeout  Max adaptive timeout (default: 120000)');
    console.log('  --output       Output directory (default: ./output)');
    console.log('  --headless     Run headless (default: true)');
    console.log('  --no-headless  Show browser window');
    process.exit(1);
  }

  console.log('');
  console.log('=================================================');
  console.log('  Sentinel Activity Viewer v4.3');
  console.log('  Zero Escape Architecture — 37 Categories');
  console.log('=================================================');
  console.log('');
  console.log('  Target:   ' + config.url);
  console.log('  Mode:     ' + config.mode.toUpperCase());
  console.log('  Timeout:  ' + (config.timeout / 1000) + 's (max ' + (config.maxTimeout / 1000) + 's)');
  console.log('  Headless: ' + config.headless);
  console.log('  Output:   ' + config.outputDir);
  console.log('');

  var browser = null;
  var contextMap = [];

  try {
    // ── Launch Browser ──
    console.log('[1/7] Launching browser...');
    browser = await playwright.chromium.launch({
      headless: config.headless,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--disable-features=IsolateOrigins,site-per-process',
        '--disable-site-isolation-trials',
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage'
      ]
    });

    var context = await browser.newContext({
      viewport: { width: 1920, height: 1080 },
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      locale: 'en-US',
      timezoneId: 'America/New_York',
      permissions: [],
      javaScriptEnabled: true,
      ignoreHTTPSErrors: true
    });

    var page = await context.newPage();

    // ── Build Injection Payloads ──
    console.log('[2/7] Building injection payloads...');
    var mainPayload = buildInjectionPayload(config.stealthEnabled);
    var stealthPayload = config.stealthEnabled ? buildStealthPayload() : '';

    // ── Layer 1: Try CDP injection (primary) ──
    console.log('[3/7] Injecting via CDP (primary)...');
    var cdpSession = null;
    var cdpSuccess = false;
    var injectionFlags = { L1: false, L2: false, L3: false };

    try {
      cdpSession = await page.context().newCDPSession(page);

      // Enable Target domain for auto-attach
      await cdpSession.send('Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: false,
        flatten: true
      });

      // Inject main payload via CDP
      await cdpSession.send('Page.addScriptToEvaluateOnNewDocument', {
        source: mainPayload,
        runImmediately: false
      });

      cdpSuccess = true;
      injectionFlags.L1 = true;
      console.log('  [CDP] Main payload injected successfully');

      // Handle auto-attached targets (iframes, workers)
      cdpSession.on('Target.attachedToTarget', async function(params) {
        var sessionId = params.sessionId;
        var targetInfo = params.targetInfo;

        if (targetInfo.type === 'iframe' || targetInfo.type === 'page') {
          contextMap.push({
            type: targetInfo.type,
            url: targetInfo.url,
            origin: targetInfo.url ? new URL(targetInfo.url).origin : 'unknown',
            sessionId: sessionId
          });

          try {
            await cdpSession.send('Page.addScriptToEvaluateOnNewDocument', {
              source: mainPayload,
              runImmediately: false
            }, sessionId);
            injectionFlags.L3 = true;
            console.log('  [CDP] Per-target injection: ' + targetInfo.url.slice(0, 60));
          } catch (e) {
            console.log('  [CDP] Per-target injection failed for: ' + targetInfo.url.slice(0, 60));
          }
        }

        // Resume target
        try {
          await cdpSession.send('Runtime.runIfWaitingForDebugger', {}, sessionId);
        } catch (e) {}
      });

    } catch (cdpErr) {
      console.log('  [CDP] Failed: ' + cdpErr.message.slice(0, 80));
      console.log('  [CDP] Falling back to addInitScript...');
    }

    // ── Layer 2: Fallback to addInitScript (ONLY if CDP failed) ──
    if (!cdpSuccess) {
      console.log('[3/7] Injecting via addInitScript (fallback)...');
      await page.addInitScript(mainPayload);
      injectionFlags.L2 = true;
      console.log('  [addInitScript] Main payload injected');
    }

    // ── Stealth scripts always via addInitScript (separate from main payload) ──
    if (config.stealthEnabled && stealthPayload) {
      await page.addInitScript(stealthPayload);
      console.log('  [addInitScript] Stealth payload injected');
    }

    // ── Navigate to target ──
    console.log('[4/7] Navigating to target...');
    try {
      await page.goto(config.url, {
        waitUntil: 'networkidle',
        timeout: 30000
      });
    } catch (navErr) {
      console.log('  [NAV] Initial load timeout, continuing with domcontentloaded...');
      try {
        await page.goto(config.url, {
          waitUntil: 'domcontentloaded',
          timeout: 15000
        });
      } catch (navErr2) {
        console.log('  [NAV] Fallback navigation also failed: ' + navErr2.message.slice(0, 60));
      }
    }

    console.log('  Page loaded: ' + page.url());

    // ── Adaptive Timeout: Observe Activity ──
    console.log('[5/7] Observing activity (timeout: ' + (config.timeout / 1000) + 's)...');
    var adaptiveTimeout = new AdaptiveTimeout(config.timeout, config.maxTimeout);

    var checkInterval = 5000;
    var elapsed = 0;

    while (elapsed < adaptiveTimeout.finalTimeout) {
      await new Promise(function(resolve) { setTimeout(resolve, checkInterval); });
      elapsed += checkInterval;

      // Check event count for adaptive extension
      try {
        var countResult = await page.evaluate(function() {
          if (typeof window.__SENTINEL_FLUSH__ === 'function') {
            var data = JSON.parse(window.__SENTINEL_FLUSH__());
            return data.events.length;
          }
          return 0;
        });
        adaptiveTimeout.checkAndExtend(countResult);

        if (elapsed % 15000 < checkInterval) {
          console.log('  [' + (elapsed / 1000) + 's] Events: ' + countResult);
        }
      } catch (e) {}
    }

    // ── Collect Results ──
    console.log('[6/7] Collecting results...');
    var sentinelData = { events: [], injectionFlags: injectionFlags, dedupStats: null };

    try {
      var flushResult = await page.evaluate(function() {
        if (typeof window.__SENTINEL_FLUSH__ === 'function') {
          return window.__SENTINEL_FLUSH__();
        }
        return JSON.stringify({ events: [], dedupStats: { totalReceived: 0, deduplicated: 0, kept: 0 } });
      });

      var parsed = JSON.parse(flushResult);
      sentinelData.events = parsed.events || [];
      sentinelData.dedupStats = parsed.dedupStats || null;
    } catch (e) {
      console.log('  [FLUSH] Error collecting from main frame: ' + e.message.slice(0, 80));
    }

    // Collect from child frames
    var frames = page.frames();
    for (var fi = 0; fi < frames.length; fi++) {
      var frame = frames[fi];
      if (frame === page.mainFrame()) continue;

      try {
        var frameResult = await frame.evaluate(function() {
          if (typeof window.__SENTINEL_FLUSH__ === 'function') {
            return window.__SENTINEL_FLUSH__();
          }
          return null;
        });

        if (frameResult) {
          var frameParsed = JSON.parse(frameResult);
          var frameEvents = frameParsed.events || [];

          // Tag events with frame info
          for (var fe = 0; fe < frameEvents.length; fe++) {
            frameEvents[fe].frameId = 'frame_' + fi;
            frameEvents[fe].frameUrl = frame.url();
          }

          // Non-destructive: push each event individually
          for (var fe2 = 0; fe2 < frameEvents.length; fe2++) {
            sentinelData.events.push(frameEvents[fe2]);
          }

          contextMap.push({
            type: 'iframe',
            url: frame.url(),
            origin: frame.url() ? new URL(frame.url()).origin : 'unknown',
            eventCount: frameEvents.length
          });

          console.log('  [FRAME] ' + frame.url().slice(0, 60) + ' — ' + frameEvents.length + ' events');
        }
      } catch (e) {}
    }

    // Sort all events by timestamp
    sentinelData.events.sort(function(a, b) { return a.ts - b.ts; });

    console.log('');
    console.log('  Total events collected: ' + sentinelData.events.length);
    console.log('  Frames detected: ' + contextMap.length);
    console.log('');

    // ── Generate Report ──
    console.log('[7/7] Generating forensic report...');
    var reportResult = reportGenerator.generateReport(
      sentinelData,
      contextMap,
      config.url,
      {
        stealthEnabled: config.stealthEnabled,
        outputDir: config.outputDir,
        timeoutExtended: adaptiveTimeout.extended,
        finalTimeout: adaptiveTimeout.finalTimeout
      }
    );

    console.log('');
    console.log('=================================================');
    console.log('  SCAN COMPLETE');
    console.log('=================================================');
    console.log('  Events:     ' + sentinelData.events.length);
    console.log('  Risk Score: ' + reportResult.reportJson.riskScore + '/100 ' + reportResult.reportJson.riskLevel);
    console.log('  Threats:    ' + reportResult.reportJson.threats.length);
    console.log('  Categories: ' + reportResult.reportJson.categoriesDetected + '/' + reportResult.reportJson.categoriesMonitored);
    console.log('  Coverage:   ' + reportResult.reportJson.coveragePercent + '%');
    console.log('');
    console.log('  Reports:');
    console.log('    JSON: ' + reportResult.jsonPath);
    console.log('    HTML: ' + reportResult.htmlPath);
    console.log('    CTX:  ' + reportResult.ctxPath);
    console.log('=================================================');

  } catch (err) {
    console.error('FATAL ERROR: ' + err.message);
    console.error(err.stack);
    process.exit(1);
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

main().catch(function(err) {
  console.error('Unhandled error: ' + err.message);
  process.exit(1);
});
