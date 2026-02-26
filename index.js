#!/usr/bin/env node
/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                         CHANGE LOG                                       ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ v6.4.0-fp2 (2026-02-26)                                                 ║
 * ║   [CHG] Removed geolocation spoofing — now native (real IP-based loc)    ║
 * ║   [CHG] Removed locale spoofing — now native (OS locale)                 ║
 * ║   [CHG] Removed timezone spoofing — now native (OS timezone)             ║
 * ║   [CHG] Removed navigator.languages/language spoofing — now native       ║
 * ║   [CHG] userAgent remains native (already was, confirmed no change)      ║
 * ║   [CHG] Removed CDP Emulation.setTimezoneOverride call                   ║
 * ║   [CHG] Removed CDP Emulation.setLocaleOverride call                     ║
 * ║   [CHG] Removed CDP Emulation.setGeolocationOverride call                ║
 * ║   [CHG] Removed navigator.languages/language from buildSpoofScript()     ║
 * ║   [CHG] Banner output updated — native fields show "native" label        ║
 * ║   [NOTE] Fields from fingerprint.json that ARE used:                     ║
 * ║          webgl (vendor, renderer, extensions, parameters),               ║
 * ║          hardware (cores, memory), screen, viewport, deviceScaleFactor,  ║
 * ║          hasTouch, navigator.platform, audio, canvas, fonts              ║
 * ║   [NOTE] Fields from fingerprint.json that are IGNORED (native):         ║
 * ║          userAgent, locale, timezone, languages, geolocation,            ║
 * ║          _meta.ua_mode                                                    ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ PREVIOUS LOG (v6.4.0-fp1, 2026-02-26)                                    ║
 * ║   [NEW] fingerprint.json integration — all spoof data from external file ║
 * ║   [NEW] SPOOF_CONFIG replaced by loadFingerprint() from fingerprint.json ║
 * ║   [NEW] WebGL extensions spoofing (getSupportedExtensions override)      ║
 * ║   [NEW] WebGL parameters spoofing (getParameter override per GL const)   ║
 * ║   [NEW] Audio context properties spoofing (sampleRate, channelCount)     ║
 * ║   [NEW] Canvas capabilities spoofing (isPointInStroke)                   ║
 * ║   [NEW] Font enumeration defense (offsetWidth measurement override)      ║
 * ║   [NEW] navigator.languages spoofing from fingerprint.json               ║
 * ║   [NEW] Timezone spoofing via CDP Emulation.setTimezoneOverride          ║
 * ║   [NEW] Locale spoofing via CDP Emulation.setLocaleOverride              ║
 * ║   [NEW] Geolocation spoofing via CDP Emulation.setGeolocationOverride    ║
 * ║   [CHG] buildSpoofScript() accepts full fingerprint data object          ║
 * ║   [CHG] createChromiumForMode() reads webgl/hwc from fingerprint data    ║
 * ║   [FIX] Removed SPOOF_CONFIG hardcoded object (replaced by JSON file)    ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ PREVIOUS LOG (v6.4.0 CustomUpdate_Basisv6.4StealthMode)                  ║
 * ║   [NEW] SPOOF_CONFIG object for manual fingerprint configuration         ║
 * ║   [NEW] WebGL vendor/renderer spoof via stealth plugin custom opts       ║
 * ║   [NEW] hardwareConcurrency spoof via stealth plugin custom opts         ║
 * ║   [NEW] Screen/deviceMemory/platform/touch spoof via addInitScript       ║
 * ║   [NEW] CDP Emulation.setDeviceMetricsOverride for screen metrics        ║
 * ║   [FIX] Stealth plugin now isolated per scan mode (dual-mode safe)       ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ PREVIOUS LOG (v6.4.0 base)                                               ║
 * ║   [NEW] launchPersistentContext() always — no incognito detection         ║
 * ║   [NEW] Auto-generated temp profile directories                          ║
 * ║   [NEW] Auto-cleanup of temp profiles after scan                         ║
 * ║   [NEW] Graceful SIGINT/SIGTERM cleanup                                  ║
 * ║   [NEW] rebrowser-playwright-core Runtime.Enable patch (addBinding)       ║
 * ║   [NEW] CDP Observer Engine (passive network/DOM/console/performance)     ║
 * ║   [NEW] Frame Tree Watcher (recursive auto-attach)                       ║
 * ║   [NEW] Page Scope Watcher (new tab detection)                           ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * Sentinel v6.4.0-fp2 — Pure Observer CCTV with Fingerprint Profile
 *
 * NATIVE (tidak di-spoof, ikut browser/OS asli):
 *   User-Agent, Locale, Timezone, Languages, Geolocation
 *
 * SPOOFED (dari fingerprint.json):
 *   WebGL, Screen, Viewport, Hardware, Audio, Canvas, Fonts, Platform, Touch
 *
 * STACK:
 *   rebrowser-playwright-core (aliased as playwright-core) → Runtime.Enable fix
 *   playwright-extra → plugin framework
 *   stealth plugin → removes Chromium automation artifacts
 *   CDP collectors → passive observation of ALL browser activity
 *   fingerprint.json → external fingerprint profile (hardware/visual spoof data)
 */

'use strict';

process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE = process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE || 'addBinding';
process.env.REBROWSER_PATCHES_SOURCE_URL = process.env.REBROWSER_PATCHES_SOURCE_URL || 'analytics.js';

const { addExtra } = require('playwright-extra');
const playwrightCore = require('playwright-core');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { CdpObserverEngine } = require('./lib/cdp-observer-engine');
const { FrameTreeWatcher } = require('./lib/frame-tree-watcher');
const { EventPipeline } = require('./lib/event-pipeline');
const { ForensicEngine } = require('./lib/forensic-engine');
const { ReportGenerator } = require('./lib/report-generator');
const { PageScopeWatcher } = require('./lib/page-scope-watcher');

const VERSION = 'sentinel-v6.4.0-fp2';

// ╔═══════════════════════════════════════════════════════════════╗
// ║  📁 FINGERPRINT FILE PATH — change this if file is elsewhere ║
// ╚═══════════════════════════════════════════════════════════════╝
const FINGERPRINT_PATH = path.join(__dirname, 'fingerprint.json');

// ╔═══════════════════════════════════════════════════════════════╗
// ║  🖥️  CHROME EXECUTABLE PATH — real Chrome, not Chromium       ║
// ║  Ubah sesuai lokasi chrome.exe di sistem kamu.                ║
// ╚═══════════════════════════════════════════════════════════════╝
const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

// ─── Load Fingerprint Data ───
function loadFingerprint() {
  if (!fs.existsSync(FINGERPRINT_PATH)) {
    console.error(`[Sentinel] FATAL: fingerprint.json not found at: ${FINGERPRINT_PATH}`);
    console.error(`[Sentinel] Place your fingerprint.json in the same directory as index.js`);
    process.exit(1);
  }
  const raw = fs.readFileSync(FINGERPRINT_PATH, 'utf-8');
  const fp = JSON.parse(raw);
  console.log(`[Sentinel] Loaded fingerprint: ${fp._id || 'unknown'}`);
  return fp;
}

const FP = loadFingerprint();

// ─── Temp Profile Cleanup Registry ───
const tempDirsToCleanup = new Set();

function cleanupTempDirs() {
  for (const dir of tempDirsToCleanup) {
    try {
      if (fs.existsSync(dir)) {
        console.log(`[Sentinel] Cleaning up temp profile: ${dir}`);
        fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      }
      tempDirsToCleanup.delete(dir);
    } catch (err) {
      console.warn(`[Sentinel] Failed to cleanup ${dir}: ${err.message}`);
    }
  }
}

// ─── Graceful shutdown on SIGINT/SIGTERM ───
process.on('SIGINT', () => {
  console.log('\n[Sentinel] Received SIGINT, cleaning up...');
  cleanupTempDirs();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n[Sentinel] Received SIGTERM, cleaning up...');
  cleanupTempDirs();
  process.exit(0);
});

// ─── CLI ───
const args = process.argv.slice(2);
const target = args.find(a => a.startsWith('http'));
const dualMode = args.includes('--dual-mode');
const headless = !args.includes('--no-headless');
const timeout = parseInt(args.find(a => a.startsWith('--timeout='))?.split('=')[1] || '60000');
const waitTime = parseInt(args.find(a => a.startsWith('--wait='))?.split('=')[1] || '30000');
const userPersistDir = args.find(a => a.startsWith('--persist='))?.split('=')[1] || '';
const stealthEnabled = !args.includes('--no-stealth');

if (!target) {
  console.log(`
🛡️  ${VERSION} — Pure Observer CCTV with Fingerprint Profile

Usage: node index.js <URL> [options]

Options:
  --dual-mode        Run both observe and stealth passes
  --no-headless      Visible browser
  --no-stealth       Disable stealth plugin (for comparison)
  --timeout=<ms>     Navigation timeout (default: 60000)
  --wait=<ms>        Post-load wait time (default: 30000)
  --persist=<dir>    Persistent browser profile directory (optional)
                     If not specified, auto-generates temp profile and cleans up after scan

Examples:
  node index.js https://browserscan.net --dual-mode --no-headless
  node index.js https://example.com --persist=./profiles/session1 --no-headless
  node index.js https://example.com --no-headless
    (auto-generates temp profile, always appears non-incognito, auto-cleanup)
`);
  process.exit(0);
}

// ─── Helper: create a fresh chromium instance with plugins for a given mode ───
function createChromiumForMode(mode) {
  const chromium = addExtra(playwrightCore.chromium);

  const useStealth = stealthEnabled && (mode === 'stealth');

  if (useStealth) {
    const stealth = StealthPlugin();

    stealth.enabledEvasions.delete('webgl.vendor');
    stealth.enabledEvasions.delete('navigator.hardwareConcurrency');
    chromium.use(stealth);

    const webglVendorPlugin = require('puppeteer-extra-plugin-stealth/evasions/webgl.vendor');
    chromium.use(webglVendorPlugin({
      vendor: FP.webgl.vendor,
      renderer: FP.webgl.renderer,
    }));

    const hwcPlugin = require('puppeteer-extra-plugin-stealth/evasions/navigator.hardwareConcurrency');
    chromium.use(hwcPlugin({
      hardwareConcurrency: FP.navigator.hardwareConcurrency,
    }));

    console.log(`[Sentinel] Stealth ON`);
    console.log(`   Fingerprint: ${FP._id}`);
    console.log(`   WebGL:       ${FP.webgl.vendor} / ${FP.webgl.renderer}`);
    console.log(`   CPU:         ${FP.navigator.hardwareConcurrency} cores`);
    console.log(`   RAM:         ${FP.navigator.deviceMemory} GB`);
    console.log(`   Screen:      ${FP.screen.width}x${FP.screen.height}`);
    console.log(`   Platform:    ${FP.navigator.platform}`);
    console.log(`   Fonts:       ${FP.fonts.list.length} fonts (${FP.fonts.persona})`);
    console.log(`   UA:          native (no spoof)`);
    console.log(`   Locale:      native (no spoof)`);
    console.log(`   Timezone:    native (no spoof)`);
    console.log(`   Languages:   native (no spoof)`);
    console.log(`   Geolocation: native (no spoof)`);
  } else {
    console.log(`[Sentinel] Stealth OFF (mode: ${mode})`);
  }

  return { chromium, useStealth };
}

// ─── Build the spoof script injected via addInitScript ───
// Handles: screen, deviceMemory, platform, touch, webgl extensions,
//          webgl parameters, audio, canvas, fonts
// Does NOT handle (native): UA, locale, timezone, languages, geolocation
function buildSpoofScript(fp) {
  const extensionsJSON = JSON.stringify(fp.webgl.extensions);
  const paramsJSON = JSON.stringify(fp.webgl.parameters);
  const fontsJSON = JSON.stringify(fp.fonts.list);

  return `
    (function() {
      // ─── Screen Resolution Spoof ───
      Object.defineProperty(screen, 'width',       { get: () => ${fp.screen.width} });
      Object.defineProperty(screen, 'height',      { get: () => ${fp.screen.height} });
      Object.defineProperty(screen, 'availWidth',  { get: () => ${fp.screen.width} });
      Object.defineProperty(screen, 'availHeight', { get: () => ${fp.screen.height} });
      Object.defineProperty(screen, 'colorDepth',  { get: () => ${fp.screen.colorDepth} });
      Object.defineProperty(screen, 'pixelDepth',  { get: () => ${fp.screen.pixelDepth} });

      // ─── Navigator Properties Spoof (hardware only, NOT regional) ───
      Object.defineProperty(navigator, 'deviceMemory',    { get: () => ${fp.navigator.deviceMemory} });
      Object.defineProperty(navigator, 'maxTouchPoints',  { get: () => ${fp.hasTouch ? 10 : 0} });
      Object.defineProperty(navigator, 'platform',        { get: () => '${fp.navigator.platform}' });

      // ─── WebGL Extensions Spoof ───
      const _fpExtensions = ${extensionsJSON};
      const _origGetSupportedExtensions = WebGLRenderingContext.prototype.getSupportedExtensions;
      WebGLRenderingContext.prototype.getSupportedExtensions = function() {
        return _fpExtensions.slice();
      };

      // ─── WebGL Parameters Spoof ───
      const _fpParams = ${paramsJSON};
      const _glParamMap = {
        max_texture_size: 0x0D33,
        max_viewport_dims: 0x0D3A,
        max_renderbuffer_size: 0x84E8,
        max_combined_texture_image_units: 0x8B4D,
        max_cube_map_texture_size: 0x851C,
        max_fragment_uniform_vectors: 0x8DFD,
        max_varying_vectors: 0x8DFC,
        max_vertex_attribs: 0x8869,
        max_vertex_texture_image_units: 0x8B4C,
        max_vertex_uniform_vectors: 0x8DFB,
        aliased_line_width_range: 0x846E,
        aliased_point_size_range: 0x8700,
      };
      const _origGetParameter = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(param) {
        for (const [key, glConst] of Object.entries(_glParamMap)) {
          if (param === glConst && _fpParams[key] !== undefined) {
            const val = _fpParams[key];
            if (Array.isArray(val)) {
              return new Float32Array(val);
            }
            return val;
          }
        }
        return _origGetParameter.call(this, param);
      };

      // ─── Audio Context Spoof ───
      const _origAudioContext = window.AudioContext || window.webkitAudioContext;
      if (_origAudioContext) {
        Object.defineProperty(_origAudioContext.prototype, 'sampleRate', {
          get: function() { return ${fp.audio.capabilities.sample_rate}; }
        });
      }

      // ─── Canvas isPointInStroke Spoof ───
      if (${fp.canvas.capabilities.geometry.isPointInStroke === false ? 'true' : 'false'}) {
        CanvasRenderingContext2D.prototype.isPointInStroke = function() {
          return false;
        };
      }

      // ─── Font Enumeration Defense ───
      const _fpFonts = ${fontsJSON};
      const _fpFontSet = new Set(_fpFonts.map(f => f.toLowerCase()));

      const _origOffsetWidthGetter = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth').get;
      const _origOffsetHeightGetter = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight').get;

      Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
        get: function() {
          const style = this.style;
          if (style && style.fontFamily) {
            const families = style.fontFamily.split(',').map(f => f.trim().replace(/['"]/g, '').toLowerCase());
            const testFont = families.find(f => !['monospace', 'sans-serif', 'serif'].includes(f));
            if (testFont && !_fpFontSet.has(testFont)) {
              const fallback = families.find(f => ['monospace', 'sans-serif', 'serif'].includes(f));
              if (fallback) {
                this.style.fontFamily = fallback;
                const w = _origOffsetWidthGetter.call(this);
                this.style.fontFamily = style.fontFamily;
                return w;
              }
            }
          }
          return _origOffsetWidthGetter.call(this);
        }
      });

      Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
        get: function() {
          const style = this.style;
          if (style && style.fontFamily) {
            const families = style.fontFamily.split(',').map(f => f.trim().replace(/['"]/g, '').toLowerCase());
            const testFont = families.find(f => !['monospace', 'sans-serif', 'serif'].includes(f));
            if (testFont && !_fpFontSet.has(testFont)) {
              const fallback = families.find(f => ['monospace', 'sans-serif', 'serif'].includes(f));
              if (fallback) {
                this.style.fontFamily = fallback;
                const h = _origOffsetHeightGetter.call(this);
                this.style.fontFamily = style.fontFamily;
                return h;
              }
            }
          }
          return _origOffsetHeightGetter.call(this);
        }
      });

    })();
  `;
}

async function runScan(mode) {
  const ts = Date.now();
  const pipeline = new EventPipeline();
  const forensic = new ForensicEngine(VERSION);

  const { chromium, useStealth } = createChromiumForMode(mode);

  // ─── Determine profile directory ───
  let persistDir;
  let isAutoGenerated = false;

  if (userPersistDir) {
    persistDir = path.resolve(userPersistDir);
    console.log(`[Sentinel] Using user-specified profile: ${persistDir}`);
  } else {
    const tempPrefix = path.join(os.tmpdir(), `sentinel-profile-${mode}-`);
    persistDir = fs.mkdtempSync(tempPrefix);
    isAutoGenerated = true;
    tempDirsToCleanup.add(persistDir);
    console.log(`[Sentinel] Auto-generated temp profile: ${persistDir}`);
  }

  console.log(`[Sentinel] Launching browser (mode: ${mode})...`);

  const launchArgs = [
    '--disable-blink-features=AutomationControlled',
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-infobars',
    '--disable-background-timer-throttling',
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding',
    '--disable-ipc-flooding-protection',
    '--enable-features=NetworkService,NetworkServiceInProcess',
  ];

  if (useStealth) {
    launchArgs.push(`--window-size=${FP.viewport.width},${FP.viewport.height}`);
  }

  const launchOpts = {
    headless: mode === 'stealth' ? headless : false,
    args: launchArgs,
    ignoreDefaultArgs: ['--enable-automation'],
    viewport: null,
    executablePath: CHROME_PATH,
  };

  let context;
  try {
    context = await chromium.launchPersistentContext(persistDir, launchOpts);
  } catch (err) {
    console.error(`[Sentinel] Failed to launch browser: ${err.message}`);
    if (isAutoGenerated && fs.existsSync(persistDir)) {
      fs.rmSync(persistDir, { recursive: true, force: true });
      tempDirsToCleanup.delete(persistDir);
    }
    throw err;
  }

  if (useStealth) {
    await context.addInitScript({ content: buildSpoofScript(FP) });
    console.log(`[Sentinel] Spoof script injected (screen, memory, platform, webgl-params, audio, canvas, fonts)`);
  }

  const page = await context.newPage();

  // ─── CDP session for this page ───
  const cdpSession = await page.context().newCDPSession(page);

  // ─── CDP Emulation overrides (stealth mode only) ───
  // Only screen/viewport metrics — NO timezone, locale, geolocation (all native)
  if (useStealth) {
    try {
      await cdpSession.send('Emulation.setDeviceMetricsOverride', {
        width: FP.viewport.width,
        height: FP.viewport.height,
        deviceScaleFactor: FP.deviceScaleFactor,
        mobile: FP.isMobile,
        screenWidth: FP.screen.width,
        screenHeight: FP.screen.height,
      });
    } catch (e) {
      console.warn(`[Sentinel] CDP screen override warning: ${e.message}`);
    }

    if (FP.hasTouch) {
      try {
        await cdpSession.send('Emulation.setTouchEmulationEnabled', {
          enabled: true,
          maxTouchPoints: 10,
        });
      } catch (e) {
        console.warn(`[Sentinel] CDP touch override warning: ${e.message}`);
      }
    }
  }

  const injectionStatus = {
    version: VERSION,
    mode,
    fingerprintId: FP._id,
    rebrowserPatched: true,
    runtimeFixMode: process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE,
    stealthPlugin: useStealth,
    nativeFields: ['userAgent', 'locale', 'timezone', 'languages', 'geolocation'],
    zeroInjection: !useStealth,
    persistentContext: true,
    profileDirectory: persistDir,
    autoGenerated: isAutoGenerated,
  };

  // ─── Layer 1: CDP Observer Engine (PASSIVE — no JS injection) ───
  const cdpObserver = new CdpObserverEngine(pipeline, cdpSession);
  await cdpObserver.start();
  injectionStatus.cdpNetworkCollector = true;
  injectionStatus.cdpSecurityCollector = true;
  injectionStatus.cdpDOMCollector = true;
  injectionStatus.cdpConsoleCollector = true;
  injectionStatus.cdpPerformanceCollector = true;

  // ─── Layer 2: Frame Tree Watcher (CDP Target.setAutoAttach) ───
  const frameWatcher = new FrameTreeWatcher(pipeline, cdpSession, context);
  await frameWatcher.start();
  injectionStatus.frameTreeWatcher = true;
  injectionStatus.recursiveAutoAttach = true;

  // ─── Layer 3: Page Scope Watcher (new tabs/pages in context) ───
  const pageWatcher = new PageScopeWatcher(pipeline, context);
  await pageWatcher.start();
  injectionStatus.pageScopeWatcher = true;

  // ─── Navigate ───
  console.log(`[Sentinel] Navigating to ${target}...`);
  try {
    await page.goto(target, { waitUntil: 'domcontentloaded', timeout });
  } catch (e) {
    console.error(`[Sentinel] Navigation warning: ${e.message}`);
  }

  // ─── Wait for activity ───
  console.log(`[Sentinel] Observing for ${waitTime / 1000}s...`);
  await page.waitForTimeout(waitTime);

  // ─── Collect frame tree from Playwright ───
  const frames = page.frames().map(f => ({
    url: f.url(),
    name: f.name(),
    detached: f.isDetached(),
  }));

  // ─── Gather all events ───
  const allEvents = pipeline.drain();
  const stats = pipeline.getStats();
  const frameStats = frameWatcher.getStats();

  injectionStatus.subFramesDiscovered = frameStats.discovered;
  injectionStatus.subFramesAttached = frameStats.attached;
  injectionStatus.totalCdpEvents = stats.cdpEvents;
  injectionStatus.networkEntries = stats.networkEntries;
  injectionStatus.consoleEvents = stats.consoleEvents;
  injectionStatus.domEvents = stats.domEvents;
  injectionStatus.totalDeduped = allEvents.length;

  // ─── Forensic analysis ───
  const analysis = forensic.analyze(allEvents, frames, injectionStatus);

  // ─── Coverage ───
  const targetGraph = frameWatcher.getTargetInventory();
  const coverageProof = {
    targetGraph,
    frameCoverage: frameStats.discovered > 0
      ? `${Math.round(frameStats.attached / frameStats.discovered * 100)}%`
      : 'N/A',
    categoryCoverage: `${Math.round(analysis.categories.length / 30 * 100 * 10) / 10}%`,
  };

  // ─── Reports ───
  const contextData = {
    version: VERSION,
    target,
    scanDate: new Date(ts).toISOString(),
    mode,
    fingerprintId: FP._id,
    frames,
    injectionStatus,
    targetGraph,
    coverageProof,
  };

  const report = new ReportGenerator(VERSION);
  const reportPath = report.save(mode, ts, allEvents, analysis, contextData);

  console.log(
    `[Sentinel] Scan complete: ${allEvents.length} CDP events, ` +
    `${analysis.categories.length} categories, ` +
    `${frameStats.discovered} frames discovered, ` +
    `${frameStats.attached} frames attached, ` +
    `${stats.networkEntries} network entries, ` +
    `${stats.consoleEvents} console events`
  );
  console.log(`[Sentinel] Reports: ${reportPath.json}`);
  console.log(`[Sentinel] HTML: ${reportPath.html}`);

  // ─── Cleanup ───
  await cdpObserver.stop();
  await context.close();

  // ─── Remove temp profile if auto-generated ───
  if (isAutoGenerated) {
    try {
      if (fs.existsSync(persistDir)) {
        console.log(`[Sentinel] Removing auto-generated temp profile: ${persistDir}`);
        fs.rmSync(persistDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      }
      tempDirsToCleanup.delete(persistDir);
    } catch (err) {
      console.warn(`[Sentinel] Failed to remove temp profile ${persistDir}: ${err.message}`);
    }
  }

  return { reportPath, stats: analysis };
}

// ─── Main ───
(async () => {
  console.log(`
🛡️  ${VERSION} — Pure Observer CCTV with Fingerprint Profile
   rebrowser-playwright-core: Runtime.Enable PATCHED (${process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE})
   Stealth Plugin: ${stealthEnabled ? 'ON' : 'OFF'}
   ALWAYS Persistent Context (No Incognito Detection)
   Target: ${target}
   Mode: ${dualMode ? 'DUAL (observe → stealth)' : 'stealth'}
   Headless: ${headless}
   Timeout: ${timeout}ms | Wait: ${waitTime}ms
   Persist: ${userPersistDir || 'auto-generated temp (with cleanup)'}
   Chrome:  ${CHROME_PATH}

   ─── Fingerprint Profile (from fingerprint.json) ───
   ID:         ${FP._id}
   GPU:        ${FP.webgl.vendor} / ${FP.webgl.renderer}
   WebGL Ext:  ${FP.webgl.extensions.length} extensions
   CPU:        ${FP.navigator.hardwareConcurrency} cores
   RAM:        ${FP.navigator.deviceMemory} GB
   Screen:     ${FP.screen.width}x${FP.screen.height} (${FP.screen.colorDepth}-bit)
   Viewport:   ${FP.viewport.width}x${FP.viewport.height}
   Scale:      ${FP.deviceScaleFactor}x
   Touch:      ${FP.hasTouch ? 'supported' : 'not support'}
   Platform:   ${FP.navigator.platform}
   Audio:      ${FP.audio.capabilities.sample_rate}Hz / ${FP.audio.capabilities.channel_count}ch
   Fonts:      ${FP.fonts.list.length} fonts (${FP.fonts.persona} / ${FP.fonts.os})

   ─── Native (NOT spoofed, from browser/OS) ───
   UA:         native
   Locale:     native
   Timezone:   native
   Languages:  native
   Geolocation: native
`);

  try {
    if (dualMode) {
      console.log('═══ PASS 1: OBSERVE MODE (no stealth, raw fingerprint) ═══');
      await runScan('observe');
      console.log('\n═══ PASS 2: STEALTH MODE (spoofed fingerprint) ═══');
      await runScan('stealth');
      console.log('\n✅ Dual-mode scan complete.');
    } else {
      await runScan('stealth');
      console.log('\n✅ Scan complete.');
    }

    cleanupTempDirs();
  } catch (err) {
    console.error('❌ Fatal error:', err);
    cleanupTempDirs();
    process.exit(1);
  }
})();
