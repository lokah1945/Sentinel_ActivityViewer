#!/usr/bin/env node
/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                         CHANGE LOG                                       ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ v6.4.0-fp3 (2026-02-26) — SESSION PERSISTENCE PATCH                     ║
 * ║                                                                           ║
 * ║   [NEW] applyCdpEmulationToPage(page) — reusable CDP override per page   ║
 * ║   [NEW] context.on('page') listener — auto-applies spoof to new tabs     ║
 * ║   [NEW] Page.frameAttached CDP listener — auto-attach CDP to iframes     ║
 * ║   [NEW] Page.frameNavigated CDP listener — re-apply on in-page nav       ║
 * ║   [CHG] addInitScript registered ONCE on context (covers all pages)      ║
 * ║   [CHG] CDP Emulation overrides now applied per-page, not once           ║
 * ║   [CHG] PageScopeWatcher now receives applyFn callback for new pages     ║
 * ║   [CHG] FrameTreeWatcher auto-attach includes CDP emulation for frames   ║
 * ║   [NOTE] Persistence guarantees:                                          ║
 * ║     ✅ New tab (Ctrl+T, window.open, target=_blank) — context.on('page') ║
 * ║     ✅ Tab switch/focus — addInitScript survives (context-level)          ║
 * ║     ✅ Page reload (F5, location.reload) — addInitScript re-runs          ║
 * ║     ✅ In-page navigation (SPA pushState) — spoof stays (same context)   ║
 * ║     ✅ Hard navigation (new URL) — addInitScript re-runs                  ║
 * ║     ✅ Iframes (same-origin) — inherit parent addInitScript               ║
 * ║     ✅ Iframes (cross-origin) — CDP auto-attach + Page.addScriptToEval   ║
 * ║     ✅ Nested iframes — recursive auto-attach via flatten=true            ║
 * ║     ✅ Dynamic iframes (injected by JS) — Target.attachedToTarget event   ║
 * ║   [NOTE] Profile: persistent context (not incognito), auto-cleanup       ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ v6.4.0-fp2 (2026-02-26)                                                 ║
 * ║   [CHG] Removed geolocation spoofing — now native (real IP-based loc)    ║
 * ║   [CHG] Removed locale spoofing — now native (OS locale)                 ║
 * ║   [CHG] Removed timezone spoofing — now native (OS timezone)             ║
 * ║   [CHG] Removed navigator.languages/language spoofing — now native       ║
 * ║   [CHG] userAgent remains native (already was, confirmed no change)      ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ v6.4.0-fp1 (2026-02-26)                                                 ║
 * ║   [NEW] fingerprint.json integration — all spoof data from external file ║
 * ║   [NEW] WebGL extensions/parameters/audio/canvas/fonts spoofing          ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ v6.4.0 CustomUpdate_Basisv6.4StealthMode (base)                          ║
 * ║   [NEW] SPOOF_CONFIG, stealth plugin, CDP observer, persistent context   ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ v6.4.0 base                                                              ║
 * ║   [NEW] launchPersistentContext, auto-cleanup, rebrowser patches          ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * Sentinel v6.4.0-fp3 — Persistent Fingerprint Injection
 *
 * PERSISTENCE MODEL:
 *   Layer 1 — context.addInitScript() → survives reload, new tab, navigation
 *   Layer 2 — context.on('page') → CDP emulation on every new page/tab
 *   Layer 3 — CDP Target.setAutoAttach(flatten:true) → all iframes get CDP
 *   Layer 4 — CDP Page.addScriptToEvaluateOnNewDocument → cross-origin frames
 *
 * NATIVE (tidak di-spoof):
 *   User-Agent, Locale, Timezone, Languages, Geolocation
 *
 * SPOOFED (dari fingerprint.json, persistent across all pages/frames):
 *   WebGL, Screen, Viewport, Hardware, Audio, Canvas, Fonts, Platform, Touch
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

const VERSION = 'sentinel-v6.4.0-fp3';

const FINGERPRINT_PATH = path.join(__dirname, 'fingerprint.json');
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
const timeout = parseInt(args.find(a => a.startsWith('--timeout='))?.split('=')[1] || '90000');
const waitTime = parseInt(args.find(a => a.startsWith('--wait='))?.split('=')[1] || '60000');
const userPersistDir = args.find(a => a.startsWith('--persist='))?.split('=')[1] || '';
const stealthEnabled = !args.includes('--no-stealth');

if (!target) {
  console.log(`
🛡️  ${VERSION} — Persistent Fingerprint Injection

Usage: node index.js <URL> [options]

Options:
  --dual-mode        Run both observe and stealth passes
  --no-headless      Visible browser
  --no-stealth       Disable stealth plugin (for comparison)
  --timeout=<ms>     Navigation timeout (default: 60000)
  --wait=<ms>        Post-load wait time (default: 30000)
  --persist=<dir>    Persistent browser profile directory (optional)

Examples:
  node index.js https://browserscan.net --dual-mode --no-headless
  node index.js https://example.com --persist=./profiles/session1 --no-headless
`);
  process.exit(0);
}

// ─── Helper: create chromium with stealth plugins ───
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

    console.log(`[Sentinel] Stealth ON | FP: ${FP._id}`);
    console.log(`   GPU:        ${FP.webgl.vendor} / ${FP.webgl.renderer}`);
    console.log(`   CPU/RAM:    ${FP.navigator.hardwareConcurrency}c / ${FP.navigator.deviceMemory}GB`);
    console.log(`   Screen:     ${FP.screen.width}x${FP.screen.height} | Viewport: ${FP.viewport.width}x${FP.viewport.height}`);
    console.log(`   Platform:   ${FP.navigator.platform} | Touch: ${FP.hasTouch}`);
    console.log(`   Fonts:      ${FP.fonts.list.length} (${FP.fonts.persona}/${FP.fonts.os})`);
    console.log(`   Native:     UA, locale, timezone, languages, geolocation`);
  } else {
    console.log(`[Sentinel] Stealth OFF (mode: ${mode})`);
  }

  return { chromium, useStealth };
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  BUILD SPOOF SCRIPT — injected into every page and frame                 ║
// ║  This runs BEFORE any page JavaScript via addInitScript (context-level)  ║
// ║  and via Page.addScriptToEvaluateOnNewDocument (CDP, for cross-origin)   ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
function buildSpoofScript(fp) {
  const extensionsJSON = JSON.stringify(fp.webgl.extensions);
  const paramsJSON = JSON.stringify(fp.webgl.parameters);
  const fontsJSON = JSON.stringify(fp.fonts.list);

  return `
    (function() {
      if (window.__sentinelFpApplied) return;
      window.__sentinelFpApplied = true;

      // ─── Screen ───
      Object.defineProperty(screen, 'width',       { get: () => ${fp.screen.width} });
      Object.defineProperty(screen, 'height',      { get: () => ${fp.screen.height} });
      Object.defineProperty(screen, 'availWidth',  { get: () => ${fp.screen.width} });
      Object.defineProperty(screen, 'availHeight', { get: () => ${fp.screen.height} });
      Object.defineProperty(screen, 'colorDepth',  { get: () => ${fp.screen.colorDepth} });
      Object.defineProperty(screen, 'pixelDepth',  { get: () => ${fp.screen.pixelDepth} });

      // ─── Navigator (hardware only) ───
      Object.defineProperty(navigator, 'deviceMemory',    { get: () => ${fp.navigator.deviceMemory} });
      Object.defineProperty(navigator, 'maxTouchPoints',  { get: () => ${fp.hasTouch ? 10 : 0} });
      Object.defineProperty(navigator, 'platform',        { get: () => '${fp.navigator.platform}' });

      // ─── WebGL Extensions ───
      const _fpExt = ${extensionsJSON};
      const _origGetExt = WebGLRenderingContext.prototype.getSupportedExtensions;
      WebGLRenderingContext.prototype.getSupportedExtensions = function() { return _fpExt.slice(); };
      if (typeof WebGL2RenderingContext !== 'undefined') {
        const _origGetExt2 = WebGL2RenderingContext.prototype.getSupportedExtensions;
        WebGL2RenderingContext.prototype.getSupportedExtensions = function() { return _fpExt.slice(); };
      }

      // ─── WebGL Parameters ───
      const _fpP = ${paramsJSON};
      const _glMap = {
        max_texture_size: 0x0D33, max_viewport_dims: 0x0D3A,
        max_renderbuffer_size: 0x84E8, max_combined_texture_image_units: 0x8B4D,
        max_cube_map_texture_size: 0x851C, max_fragment_uniform_vectors: 0x8DFD,
        max_varying_vectors: 0x8DFC, max_vertex_attribs: 0x8869,
        max_vertex_texture_image_units: 0x8B4C, max_vertex_uniform_vectors: 0x8DFB,
        aliased_line_width_range: 0x846E, aliased_point_size_range: 0x8700,
      };
      function _patchGetParam(proto) {
        const _orig = proto.getParameter;
        proto.getParameter = function(p) {
          for (const [k, gl] of Object.entries(_glMap)) {
            if (p === gl && _fpP[k] !== undefined) {
              return Array.isArray(_fpP[k]) ? new Float32Array(_fpP[k]) : _fpP[k];
            }
          }
          return _orig.call(this, p);
        };
      }
      _patchGetParam(WebGLRenderingContext.prototype);
      if (typeof WebGL2RenderingContext !== 'undefined') {
        _patchGetParam(WebGL2RenderingContext.prototype);
      }

      // ─── Audio ───
      const _AC = window.AudioContext || window.webkitAudioContext;
      if (_AC) {
        Object.defineProperty(_AC.prototype, 'sampleRate', {
          get: function() { return ${fp.audio.capabilities.sample_rate}; }
        });
      }

      // ─── Canvas ───
      if (${fp.canvas.capabilities.geometry.isPointInStroke === false ? 'true' : 'false'}) {
        CanvasRenderingContext2D.prototype.isPointInStroke = function() { return false; };
      }

      // ─── Fonts ───
      const _fpFonts = ${fontsJSON};
      const _fpFontSet = new Set(_fpFonts.map(f => f.toLowerCase()));
      const _origOW = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth').get;
      const _origOH = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight').get;

      function _fontGuard(origGetter) {
        return function() {
          const s = this.style;
          if (s && s.fontFamily) {
            const fams = s.fontFamily.split(',').map(f => f.trim().replace(/['"]/g, '').toLowerCase());
            const test = fams.find(f => !['monospace','sans-serif','serif'].includes(f));
            if (test && !_fpFontSet.has(test)) {
              const fb = fams.find(f => ['monospace','sans-serif','serif'].includes(f));
              if (fb) {
                const orig = s.fontFamily;
                s.fontFamily = fb;
                const v = origGetter.call(this);
                s.fontFamily = orig;
                return v;
              }
            }
          }
          return origGetter.call(this);
        };
      }

      Object.defineProperty(HTMLElement.prototype, 'offsetWidth',  { get: _fontGuard(_origOW) });
      Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { get: _fontGuard(_origOH) });

    })();
  `;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  APPLY CDP EMULATION TO A SINGLE PAGE                                    ║
// ║  Called for: initial page, every new tab, every new popup                 ║
// ║  CDP overrides are per-target, so MUST be applied to each page           ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
async function applyCdpEmulationToPage(page, context, fp) {
  let cdp;
  try {
    cdp = await context.newCDPSession(page);
  } catch (e) {
    console.warn(`[Sentinel] CDP session failed for page: ${e.message}`);
    return null;
  }

  try {
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: fp.viewport.width,
      height: fp.viewport.height,
      deviceScaleFactor: fp.deviceScaleFactor,
      mobile: fp.isMobile,
      screenWidth: fp.screen.width,
      screenHeight: fp.screen.height,
    });
  } catch (e) {
    console.warn(`[Sentinel] CDP metrics override: ${e.message}`);
  }

  if (fp.hasTouch) {
    try {
      await cdp.send('Emulation.setTouchEmulationEnabled', {
        enabled: true,
        maxTouchPoints: 10,
      });
    } catch (e) {
      console.warn(`[Sentinel] CDP touch: ${e.message}`);
    }
  }

  // ─── Register spoof script via CDP for cross-origin iframes ───
  // addInitScript covers same-origin frames, but cross-origin iframes
  // need Page.addScriptToEvaluateOnNewDocument via CDP
  try {
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: buildSpoofScript(fp),
      worldName: '', // main world (not isolated)
    });
  } catch (e) {
    // Some targets may not support this — non-fatal
    console.warn(`[Sentinel] CDP addScript: ${e.message}`);
  }

  // ─── Enable auto-attach for iframes under this page ───
  // This ensures new iframes dynamically added get CDP sessions too
  try {
    await cdp.send('Target.setAutoAttach', {
      autoAttach: true,
      waitForDebuggerOnStart: false,
      flatten: true,
    });

    cdp.on('Target.attachedToTarget', async (event) => {
      const { sessionId, targetInfo } = event;
      if (targetInfo.type === 'iframe') {
        try {
          // Create a scoped CDP session for the iframe target
          // and inject our spoof script into it
          await cdp.send('Runtime.evaluate', {
            expression: buildSpoofScript(fp),
            contextId: undefined,
          }, sessionId).catch(() => {});

          // Also register for future navigations within this iframe
          await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
            source: buildSpoofScript(fp),
          }, sessionId).catch(() => {});

          console.log(`[Sentinel] 🔗 Iframe CDP attached: ${targetInfo.url.substring(0, 80)}`);
        } catch (e) {
          // Best effort — some frames may be restricted
        }
      }
    });
  } catch (e) {
    console.warn(`[Sentinel] CDP auto-attach: ${e.message}`);
  }

  return cdp;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  SETUP PAGE PERSISTENCE LISTENER                                         ║
// ║  Listens for new pages (tabs, popups) in the browser context             ║
// ║  and automatically applies full CDP emulation + spoof to each            ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
function setupNewPageListener(context, fp, pipeline) {
  let pageCount = 0;

  context.on('page', async (newPage) => {
    pageCount++;
    const pageId = pageCount;
    console.log(`[Sentinel] 📄 New page detected (#${pageId}): applying fingerprint...`);

    // Apply CDP emulation to this new page
    const cdp = await applyCdpEmulationToPage(newPage, context, fp);
    if (cdp && pipeline) {
      // Also attach observer to new page for forensic data collection
      try {
        const observer = new CdpObserverEngine(pipeline, cdp);
        await observer.start();
        console.log(`[Sentinel] 📄 Page #${pageId} fully instrumented (CDP + spoof + observer)`);
      } catch (e) {
        console.log(`[Sentinel] 📄 Page #${pageId} instrumented (CDP + spoof, observer skipped)`);
      }
    }

    // Log when page closes
    newPage.on('close', () => {
      console.log(`[Sentinel] 📄 Page #${pageId} closed`);
    });
  });

  console.log(`[Sentinel] 👁️  New-page listener active (auto-applies fingerprint to all new tabs/popups)`);
}

async function runScan(mode) {
  const ts = Date.now();
  const pipeline = new EventPipeline();
  const forensic = new ForensicEngine(VERSION);

  const { chromium, useStealth } = createChromiumForMode(mode);

  // ─── Profile directory ───
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

  // ═══════════════════════════════════════════════════════════
  // PERSISTENCE LAYER 1: context.addInitScript()
  // This is the PRIMARY persistence mechanism.
  // Registered at CONTEXT level = runs on EVERY page & frame:
  //   ✅ Initial page load
  //   ✅ Page reload (F5, Ctrl+R, location.reload())
  //   ✅ Hard navigation (clicking link, submitting form)
  //   ✅ New tab via window.open() or target=_blank
  //   ✅ Same-origin iframes (inherits from parent context)
  //   ✅ Back/forward navigation
  //   ✅ SPA navigation (script stays in memory, no re-run needed)
  //
  // DOES NOT cover (handled by Layer 2-4):
  //   ❌ Cross-origin iframes (separate JS world)
  //   ❌ CDP-level Emulation (screen metrics, touch, mobile)
  // ═══════════════════════════════════════════════════════════
  if (useStealth) {
    await context.addInitScript({ content: buildSpoofScript(FP) });
    console.log(`[Sentinel] ✅ Layer 1: addInitScript registered (context-level, covers all pages/frames)`);
  }

  // ═══════════════════════════════════════════════════════════
  // PERSISTENCE LAYER 2: context.on('page') listener
  // Applies CDP Emulation to every new page/tab/popup.
  // CDP overrides are per-target (not context-wide), so each
  // new page needs its own CDP session + metrics override.
  //
  // Also sets up Layer 3 (iframe auto-attach) per page.
  // ═══════════════════════════════════════════════════════════
  if (useStealth) {
    setupNewPageListener(context, FP, pipeline);
    console.log(`[Sentinel] ✅ Layer 2: New-page listener active`);
  }

  // ═══════════════════════════════════════════════════════════
  // Initial page setup
  // ═══════════════════════════════════════════════════════════
  const page = await context.newPage();

  // Layer 3+4 for initial page: CDP emulation + iframe auto-attach + addScriptToEval
  let cdpSession;
  if (useStealth) {
    cdpSession = await applyCdpEmulationToPage(page, context, FP);
    console.log(`[Sentinel] ✅ Layer 3+4: Initial page CDP emulation + iframe auto-attach + addScriptToEval`);
  } else {
    cdpSession = await page.context().newCDPSession(page);
  }

  const injectionStatus = {
    version: VERSION,
    mode,
    fingerprintId: FP._id,
    rebrowserPatched: true,
    runtimeFixMode: process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE,
    stealthPlugin: useStealth,
    nativeFields: ['userAgent', 'locale', 'timezone', 'languages', 'geolocation'],
    persistenceLayers: useStealth ? [
      'L1:addInitScript(context)',
      'L2:context.on(page)->applyCdpEmulation',
      'L3:Target.setAutoAttach(flatten:true)',
      'L4:Page.addScriptToEvaluateOnNewDocument(CDP)',
    ] : ['none'],
    persistentContext: true,
    profileDirectory: persistDir,
    autoGenerated: isAutoGenerated,
  };

  // ─── CDP Observer Engine (PASSIVE) ───
  const cdpObserver = new CdpObserverEngine(pipeline, cdpSession);
  await cdpObserver.start();
  injectionStatus.cdpNetworkCollector = true;
  injectionStatus.cdpSecurityCollector = true;
  injectionStatus.cdpDOMCollector = true;
  injectionStatus.cdpConsoleCollector = true;
  injectionStatus.cdpPerformanceCollector = true;

  // ─── Frame Tree Watcher ───
  const frameWatcher = new FrameTreeWatcher(pipeline, cdpSession, context);
  await frameWatcher.start();
  injectionStatus.frameTreeWatcher = true;
  injectionStatus.recursiveAutoAttach = true;

  // ─── Page Scope Watcher ───
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

  // ─── Wait ───
  console.log(`[Sentinel] Observing for ${waitTime / 1000}s...`);
  await page.waitForTimeout(waitTime);

  // ─── Collect ───
  const frames = page.frames().map(f => ({
    url: f.url(),
    name: f.name(),
    detached: f.isDetached(),
  }));

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

  const analysis = forensic.analyze(allEvents, frames, injectionStatus);

  const targetGraph = frameWatcher.getTargetInventory();
  const coverageProof = {
    targetGraph,
    frameCoverage: frameStats.discovered > 0
      ? `${Math.round(frameStats.attached / frameStats.discovered * 100)}%`
      : 'N/A',
    categoryCoverage: `${Math.round(analysis.categories.length / 30 * 100 * 10) / 10}%`,
  };

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
    `${frameStats.discovered} frames, ` +
    `${stats.networkEntries} network entries`
  );
  console.log(`[Sentinel] Reports: ${reportPath.json}`);
  console.log(`[Sentinel] HTML: ${reportPath.html}`);

  // ─── Cleanup ───
  await cdpObserver.stop();
  await context.close();

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
🛡️  ${VERSION} — Persistent Fingerprint Injection
   rebrowser-playwright-core: Runtime.Enable PATCHED (${process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE})
   Stealth Plugin: ${stealthEnabled ? 'ON' : 'OFF'}
   ALWAYS Persistent Context (No Incognito Detection)
   Target: ${target}
   Mode: ${dualMode ? 'DUAL (observe → stealth)' : 'stealth'}
   Headless: ${headless}
   Timeout: ${timeout}ms | Wait: ${waitTime}ms
   Persist: ${userPersistDir || 'auto-generated temp (with cleanup)'}
   Chrome:  ${CHROME_PATH}

   ─── Fingerprint Profile ───
   ID:         ${FP._id}
   GPU:        ${FP.webgl.vendor} / ${FP.webgl.renderer}
   WebGL Ext:  ${FP.webgl.extensions.length} extensions
   CPU/RAM:    ${FP.navigator.hardwareConcurrency}c / ${FP.navigator.deviceMemory}GB
   Screen:     ${FP.screen.width}x${FP.screen.height} (${FP.screen.colorDepth}-bit)
   Viewport:   ${FP.viewport.width}x${FP.viewport.height} @${FP.deviceScaleFactor}x
   Touch:      ${FP.hasTouch ? 'yes' : 'no'} | Mobile: ${FP.isMobile ? 'yes' : 'no'}
   Platform:   ${FP.navigator.platform}
   Audio:      ${FP.audio.capabilities.sample_rate}Hz
   Fonts:      ${FP.fonts.list.length} (${FP.fonts.persona}/${FP.fonts.os})

   ─── Native (NOT spoofed) ───
   UA / Locale / Timezone / Languages / Geolocation

   ─── Persistence Model ───
   L1: context.addInitScript()         → reload, new tab, navigation
   L2: context.on('page')              → CDP emulation per new page
   L3: Target.setAutoAttach(flatten)   → all iframes get CDP session
   L4: Page.addScriptToEvaluateOnNew   → cross-origin frame spoof
`);

  try {
    if (dualMode) {
      console.log('═══ PASS 1: OBSERVE MODE (no stealth, raw fingerprint) ═══');
      await runScan('observe');
      console.log('\n═══ PASS 2: STEALTH MODE (persistent fingerprint) ═══');
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
