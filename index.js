#!/usr/bin/env node
"use strict";

const { chromium } = require("playwright");
const readline = require("readline");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

// --- Config ---
const MODE = (process.env.SENTINEL_MODE || "audit").toLowerCase();
const WAIT_MS = parseInt(process.env.WAIT_MS || "30000", 10);
const STACK_RATE = parseFloat(process.env.STACK_RATE || "1");
const OUTPUT_DIR = path.resolve(process.argv[2] || "./output");

// --- Helpers ---
function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }

function normaliseUrl(raw) {
  raw = raw.trim();
  if (!raw) return null;
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
  return raw;
}

function askQuestion(prompt) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(prompt, (ans) => { rl.close(); resolve(ans); }));
}

function sha256Short(s) { return crypto.createHash("sha256").update(s).digest("hex").slice(0, 12); }

// --- JSONL Sink (deduped) ---
class Sink {
  constructor(filePath) {
    ensureDir(path.dirname(filePath));
    this.stream = fs.createWriteStream(filePath, { flags: "a" });
    this.seen = new Set();
    this.count = 0;
  }
  write(ev) {
    const key = sha256Short(JSON.stringify(ev));
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.stream.write(JSON.stringify({ ...ev, _ts: Date.now() }) + "\n");
    this.count++;
  }
  close() { this.stream.end(); }
}

// --- Bootstrap Script (injected into every frame) ---
function buildBootstrap(mode, stackRate) {
  return `(function(){
"use strict";
if(window.__sentinel_hooked) return;
window.__sentinel_hooked=true;

var MODE="${mode}";
var SR=${stackRate};
var Q=[];
var flushing=false;

function uid(){return Math.random().toString(36).slice(2,10)+Date.now().toString(36)}
function stk(){if(Math.random()>SR)return"";try{throw new Error()}catch(e){return(e.stack||"").split("\\n").slice(3,8).join(" <- ")}}
function emit(cat,api,detail,risk){
  Q.push({id:uid(),cat:cat,api:api,detail:typeof detail==="object"?JSON.stringify(detail):String(detail||""),risk:risk||"low",stack:stk(),href:location.href,origin:location.origin,frame:window!==top?"child":"top"});
  if(!flushing){flushing=true;Promise.resolve().then(flush)}
}
function flush(){
  while(Q.length){var batch=Q.splice(0,50);console.debug("__sentinel__"+JSON.stringify(batch))}
  flushing=false;
}
function block(cat,api,detail){
  emit(cat,api,detail,"critical");
  if(MODE==="lockdown") throw new Error("[Sentinel] Blocked: "+api);
}

function pm(obj,name,cat,rk,xform){
  if(!obj||typeof obj[name]!=="function")return;
  var orig=obj[name];
  obj[name]=function(){
    var d=xform?xform(arguments):Array.from(arguments).map(function(a){return typeof a==="object"?"[obj]":String(a)}).join(", ");
    emit(cat,name,d,rk);
    return orig.apply(this,arguments);
  };
}
function pg(obj,prop,cat,rk){
  if(!obj)return;
  var desc=Object.getOwnPropertyDescriptor(obj,prop)||Object.getOwnPropertyDescriptor(Object.getPrototypeOf(obj),prop);
  if(!desc||!desc.get)return;
  var orig=desc.get;
  Object.defineProperty(obj,prop,{get:function(){emit(cat,prop,"read",rk);return orig.call(this)},configurable:true});
}

// 1. Fingerprinting: navigator
["userAgent","platform","hardwareConcurrency","deviceMemory","languages","vendor","maxTouchPoints"].forEach(function(p){pg(navigator,p,"fingerprint","medium")});
if(navigator.userAgentData&&navigator.userAgentData.getHighEntropyValues){pm(navigator.userAgentData,"getHighEntropyValues","fingerprint","high")}

// 2. Canvas / WebGL / AudioContext
pm(HTMLCanvasElement.prototype,"toDataURL","canvas","high");
pm(HTMLCanvasElement.prototype,"toBlob","canvas","high");
if(typeof CanvasRenderingContext2D!=="undefined"){
  ["fillText","strokeText","measureText","getImageData"].forEach(function(m){pm(CanvasRenderingContext2D.prototype,m,"canvas","medium")});
}
if(typeof WebGLRenderingContext!=="undefined"){
  pm(WebGLRenderingContext.prototype,"getParameter","webgl","high",function(a){return"param="+a[0]});
  pm(WebGLRenderingContext.prototype,"getExtension","webgl","medium",function(a){return a[0]});
}
if(typeof WebGL2RenderingContext!=="undefined"){
  pm(WebGL2RenderingContext.prototype,"getParameter","webgl","high",function(a){return"param="+a[0]});
}
if(typeof AudioContext!=="undefined"||typeof webkitAudioContext!=="undefined"){
  var AC=typeof AudioContext!=="undefined"?AudioContext:webkitAudioContext;
  pm(AC.prototype,"createOscillator","audio-fp","high");
  pm(AC.prototype,"createDynamicsCompressor","audio-fp","high");
  pm(AC.prototype,"createAnalyser","audio-fp","medium");
}

// 3. Screen properties
["width","height","availWidth","availHeight","colorDepth","pixelDepth"].forEach(function(p){pg(screen,p,"screen","low")});

// 4. Font detection
if(document.fonts&&document.fonts.check){pm(document.fonts,"check","font","high")}

// 5. Permissions API
if(navigator.permissions){pm(navigator.permissions,"query","permissions","medium",function(a){return a[0]&&a[0].name||""})}

// 6. Geolocation
if(navigator.geolocation){
  pm(navigator.geolocation,"getCurrentPosition","geolocation","critical");
  pm(navigator.geolocation,"watchPosition","geolocation","critical");
}

// 7. Media devices
if(navigator.mediaDevices){
  pm(navigator.mediaDevices,"enumerateDevices","media","high");
  pm(navigator.mediaDevices,"getUserMedia","media","critical",function(a){return JSON.stringify(a[0])});
  if(navigator.mediaDevices.getDisplayMedia){pm(navigator.mediaDevices,"getDisplayMedia","media","critical")}
}

// 8. Clipboard
if(navigator.clipboard){
  pm(navigator.clipboard,"readText","clipboard","critical");
  pm(navigator.clipboard,"read","clipboard","critical");
  pm(navigator.clipboard,"writeText","clipboard","high");
  pm(navigator.clipboard,"write","clipboard","high");
}

// 9. File pickers
if(typeof showOpenFilePicker==="function") pm(window,"showOpenFilePicker","file-picker","critical");
if(typeof showSaveFilePicker==="function") pm(window,"showSaveFilePicker","file-picker","critical");
if(typeof showDirectoryPicker==="function") pm(window,"showDirectoryPicker","file-picker","critical");

// 10. Hardware APIs
if(navigator.bluetooth) pm(navigator.bluetooth,"requestDevice","hardware","critical");
if(navigator.usb) pm(navigator.usb,"requestDevice","hardware","critical");
if(navigator.hid) pm(navigator.hid,"requestDevice","hardware","critical");
if(navigator.serial) pm(navigator.serial,"requestPort","hardware","critical");
if(navigator.gpu) pm(navigator.gpu,"requestAdapter","hardware","high");

// 11. WebAuthn / Credentials
if(navigator.credentials){
  pm(navigator.credentials,"create","webauthn","high");
  pm(navigator.credentials,"get","webauthn","high");
}

// 12. Payment + WebRTC
if(typeof PaymentRequest!=="undefined"){
  var origPR=PaymentRequest;
  window.PaymentRequest=function(){emit("payment","PaymentRequest","constructor","critical");return new origPR(...arguments)};
}
if(typeof RTCPeerConnection!=="undefined"){
  var origRTC=RTCPeerConnection;
  window.RTCPeerConnection=function(){emit("webrtc","RTCPeerConnection","constructor","high");return new origRTC(...arguments)};
}

// 13. Network: fetch, XHR, WebSocket, EventSource
var origFetch=window.fetch;
window.fetch=function(){
  var url=typeof arguments[0]==="string"?arguments[0]:(arguments[0]&&arguments[0].url||"");
  var method=(arguments[1]&&arguments[1].method)||"GET";
  emit("network","fetch",method+" "+url,"medium");
  return origFetch.apply(this,arguments);
};
var origXHR=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){emit("network","xhr.open",m+" "+u,"medium");return origXHR.apply(this,arguments)};
if(typeof WebSocket!=="undefined"){
  var origWS=WebSocket;
  window.WebSocket=function(url,proto){emit("network","WebSocket",url,"high");return new origWS(url,proto)};
  window.WebSocket.prototype=origWS.prototype;
}
if(typeof EventSource!=="undefined"){
  var origES=EventSource;
  window.EventSource=function(url,cfg){emit("network","EventSource",url,"medium");return new origES(url,cfg)};
  window.EventSource.prototype=origES.prototype;
}

// 14. Storage: cookies, localStorage, sessionStorage, IndexedDB, Cache
try{
  var cdesc=Object.getOwnPropertyDescriptor(Document.prototype,"cookie")||Object.getOwnPropertyDescriptor(HTMLDocument.prototype,"cookie");
  if(cdesc){
    Object.defineProperty(document,"cookie",{
      get:function(){emit("storage","cookie.get","read","low");return cdesc.get.call(this)},
      set:function(v){emit("storage","cookie.set",v.slice(0,120),"medium");return cdesc.set.call(this,v)},
      configurable:true
    });
  }
}catch(e){}
["localStorage","sessionStorage"].forEach(function(sn){
  var s=window[sn];if(!s)return;
  ["getItem","setItem","removeItem"].forEach(function(m){
    pm(s,m,"storage","low",function(a){return sn+"."+m+"("+a[0]+")"});
  });
});
if(typeof indexedDB!=="undefined"){pm(indexedDB,"open","storage","medium",function(a){return"idb:"+a[0]})}
if(typeof caches!=="undefined"){
  pm(caches,"open","storage","medium",function(a){return"cache:"+a[0]});
  pm(caches,"delete","storage","medium",function(a){return"cache-del:"+a[0]});
}

// 15. Service Worker
if(navigator.serviceWorker){pm(navigator.serviceWorker,"register","sw","high",function(a){return a[0]})}

// 16. Sensors
["Accelerometer","Gyroscope","Magnetometer","AmbientLightSensor","LinearAccelerationSensor","GravitySensor","AbsoluteOrientationSensor","RelativeOrientationSensor"].forEach(function(sn){
  if(typeof window[sn]==="function"){
    var Orig=window[sn];
    window[sn]=function(){emit("sensor",sn,"constructor","high");return new Orig(...arguments)};
    window[sn].prototype=Orig.prototype;
  }
});

// 17. Performance timing (side-channel)
if(performance&&performance.getEntriesByType){pm(performance,"getEntriesByType","perf-timing","low")}
if(performance&&performance.now){
  var origNow=performance.now.bind(performance);
  var nowCount=0;
  performance.now=function(){
    nowCount++;
    if(nowCount%500===0) emit("perf-timing","performance.now","calls="+nowCount,"medium");
    return origNow();
  };
}

// 18. Wake Lock / Fullscreen
if(navigator.wakeLock){pm(navigator.wakeLock,"request","wakelock","medium")}
if(document.documentElement&&document.documentElement.requestFullscreen){pm(document.documentElement,"requestFullscreen","fullscreen","medium")}

// Anti-evasion: WASM
if(typeof WebAssembly!=="undefined"){
  ["compile","instantiate","compileStreaming","instantiateStreaming"].forEach(function(m){
    if(WebAssembly[m]) pm(WebAssembly,m,"wasm","high");
  });
}

// Anti-evasion: Blob URL tracking
var origCreateURL=URL.createObjectURL;
URL.createObjectURL=function(blob){
  var u=origCreateURL.apply(this,arguments);
  emit("blob","createObjectURL","type="+(blob&&blob.type||"?")+" size="+(blob&&blob.size||"?"),"medium");
  return u;
};

// Anti-evasion: Worker constructor proxy
if(typeof Worker!=="undefined"){
  var OrigWorker=Worker;
  window.Worker=function(url,opts){
    var s=String(url);
    var risk=(s.startsWith("blob:")||s.startsWith("data:"))?"high":"medium";
    emit("worker","Worker",s.slice(0,200),risk);
    return new OrigWorker(url,opts);
  };
  window.Worker.prototype=OrigWorker.prototype;
}

// Anti-evasion: MutationObserver for dynamic iframes/scripts
var mo=new MutationObserver(function(muts){
  muts.forEach(function(m){
    m.addedNodes.forEach(function(n){
      if(n.nodeName==="IFRAME"){
        var src=n.src||n.srcdoc||"";
        var flags=[];
        if(!n.offsetWidth&&!n.offsetHeight) flags.push("hidden");
        if(n.width==="0"||n.height==="0") flags.push("zeroSize");
        if(n.srcdoc) flags.push("srcdoc");
        if(src.startsWith("blob:")||src.startsWith("data:")) flags.push("suspicious-src");
        emit("dom-inject","iframe",src.slice(0,200)+" ["+flags.join(",")+"]",flags.length?"high":"medium");
      }
      if(n.nodeName==="SCRIPT"){
        emit("dom-inject","script",(n.src||"inline").slice(0,200),"medium");
      }
    });
  });
});
if(document.documentElement) mo.observe(document.documentElement,{childList:true,subtree:true});

console.debug("__sentinel_ready__");
})();`;
}

// --- Build bootstrap string ---
var BOOTSTRAP = buildBootstrap(MODE, STACK_RATE);

// --- Report generator ---
var { generateReport } = require("./report");

// --- Context map tracker ---
class ContextMap {
  constructor() { this.contexts = []; }
  add(type, url, parentId) {
    this.contexts.push({ type, url: url || "", parentId: parentId || null, ts: Date.now() });
  }
  save(filePath) {
    fs.writeFileSync(filePath, JSON.stringify(this.contexts, null, 2));
  }
}

// --- Pretty console ---
var C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", yellow: "\x1b[33m", red: "\x1b[31m",
  cyan: "\x1b[36m", magenta: "\x1b[35m", blue: "\x1b[34m",
};

function banner() {
  console.log(
    "\n" + C.cyan + C.bold +
    "  +===============================================+\n" +
    "  |   Sentinel Owner Mode v2.0                    |\n" +
    "  |   Zero-Trust Browser Security Observatory     |\n" +
    "  +===============================================+" + C.reset + "\n" +
    "  " + C.dim + "Mode: " + MODE.toUpperCase() + " | Wait: " + (WAIT_MS/1000) + "s | Stack Rate: " + STACK_RATE + C.reset + "\n"
  );
}

function logEvent(ev) {
  var colors = { critical: C.red, high: C.yellow, medium: C.blue, low: C.dim };
  var c = colors[ev.risk] || C.dim;
  var tag = "[" + ev.risk.toUpperCase() + "]";
  while(tag.length < 10) tag += " ";
  console.log("  " + c + tag + C.reset + " " + C.bold + ev.cat + C.reset + " -> " + ev.api + " " + C.dim + (ev.detail||"").slice(0,80) + C.reset);
}

// --- Main ---
async function main() {
  banner();

  var rawTarget = await askQuestion("  " + C.green + C.bold + "Enter target website: " + C.reset);
  var targetUrl = normaliseUrl(rawTarget);
  if (!targetUrl) {
    console.log("\n  " + C.red + "No URL provided. Exiting." + C.reset);
    process.exit(1);
  }
  console.log("\n  " + C.cyan + "Target: " + targetUrl + C.reset);
  console.log("  " + C.dim + "Launching headful browser..." + C.reset + "\n");

  ensureDir(OUTPUT_DIR);

  var sink = new Sink(path.join(OUTPUT_DIR, "events.jsonl"));
  var ctxMap = new ContextMap();

  var browser = await chromium.launch({
    headless: false,
    args: [
      "--disable-blink-features=AutomationControlled",
      "--start-maximized",
    ],
  });

  var context = await browser.newContext({
    viewport: null,
    recordHar: { path: path.join(OUTPUT_DIR, "session.har"), content: "embed" },
  });

  await context.tracing.start({ screenshots: true, snapshots: true, sources: true });

  // Layer A: addInitScript
  await context.addInitScript(BOOTSTRAP);

  // Layer C: Route-based script rewriting
  await context.route("**/*.js", async (route) => {
    try {
      var resp = await route.fetch();
      var body = await resp.text();
      body = BOOTSTRAP + ";" + body;
      await route.fulfill({ response: resp, body: body });
    } catch {
      await route.continue().catch(function(){});
    }
  });

  var eventCount = 0;
  var riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };

  function handlePage(page, label) {
    ctxMap.add("page", page.url(), null);

    page.on("console", function(msg) {
      if (msg.type() !== "debug") return;
      var text = msg.text();
      if (text === "__sentinel_ready__") {
        console.log("  " + C.green + "Bootstrap injected: " + label + C.reset);
        return;
      }
      if (!text.startsWith("__sentinel__")) return;
      try {
        var batch = JSON.parse(text.slice(12));
        for (var ev of batch) {
          sink.write(ev);
          logEvent(ev);
          eventCount++;
          if (ev.risk) riskCounts[ev.risk] = (riskCounts[ev.risk] || 0) + 1;
        }
      } catch(e) {}
    });

    page.on("frameattached", function(frame) {
      ctxMap.add("frame", frame.url(), label);
    });

    page.on("popup", function(popup) {
      ctxMap.add("popup", popup.url(), label);
      handlePage(popup, popup.url().slice(0, 60));
    });

    page.on("worker", function(worker) {
      ctxMap.add("worker", worker.url(), label);
      console.log("  " + C.magenta + "Worker detected: " + worker.url().slice(0,80) + C.reset);
    });
  }

  context.on("page", function(page) {
    handlePage(page, page.url().slice(0, 60));
  });

  var page = await context.newPage();
  handlePage(page, "main");

  console.log("  " + C.cyan + "Navigating to " + targetUrl + "..." + C.reset + "\n");

  try {
    await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
    console.log("  " + C.green + "Page loaded: " + await page.title() + C.reset + "\n");
  } catch (err) {
    console.log("  " + C.yellow + "Navigation note: " + err.message.slice(0, 100) + C.reset);
    console.log("  " + C.dim + "(Continuing observation anyway...)" + C.reset + "\n");
  }

  console.log("  " + C.dim + "=================================================" + C.reset);
  console.log("  " + C.bold + "Observing for " + (WAIT_MS/1000) + " seconds..." + C.reset);
  console.log("  " + C.dim + "=================================================" + C.reset + "\n");

  var totalSteps = 30;
  var stepMs = WAIT_MS / totalSteps;
  for (var i = 0; i <= totalSteps; i++) {
    if (i > 0) await new Promise(function(r){ setTimeout(r, stepMs) });
    var pct = Math.round((i / totalSteps) * 100);
    var filled = "";
    for(var j=0;j<i;j++) filled+="#";
    var empty = "";
    for(var j=0;j<totalSteps-i;j++) empty+="-";
    process.stdout.write("\r  " + C.cyan + "[" + filled + empty + "] " + pct + "%" + C.reset + "  Events: " + eventCount + "  ");
  }

  console.log("\n\n  " + C.dim + "=================================================" + C.reset);
  console.log("  " + C.bold + "Observation complete. Closing browser..." + C.reset + "\n");

  await context.tracing.stop({ path: path.join(OUTPUT_DIR, "trace.zip") });
  await context.close();
  await browser.close();
  sink.close();

  ctxMap.save(path.join(OUTPUT_DIR, "context-map.json"));

  console.log("  " + C.cyan + "Generating reports..." + C.reset);
  var report = generateReport(path.join(OUTPUT_DIR, "events.jsonl"), OUTPUT_DIR);

  console.log(
    "\n" + C.green + C.bold +
    "  +===============================================+\n" +
    "  |   Sentinel Scan Complete                      |\n" +
    "  +===============================================+" + C.reset + "\n\n" +
    "  " + C.bold + "Target:     " + C.reset + targetUrl + "\n" +
    "  " + C.bold + "Events:     " + C.reset + eventCount + "\n" +
    "  " + C.bold + "Risk Score: " + C.reset + (report ? report.riskScore + "/100" : "N/A") + "\n\n" +
    "  " + C.bold + "Breakdown:" + C.reset + "\n" +
    "    " + C.red + "Critical: " + riskCounts.critical + C.reset + "\n" +
    "    " + C.yellow + "High:     " + riskCounts.high + C.reset + "\n" +
    "    " + C.blue + "Medium:   " + riskCounts.medium + C.reset + "\n" +
    "    " + C.dim + "Low:      " + riskCounts.low + C.reset + "\n\n" +
    "  " + C.bold + "Output saved to: " + C.reset + OUTPUT_DIR + "/\n" +
    "    - events.jsonl     Raw telemetry\n" +
    "    - report.json      Machine-readable report\n" +
    "    - report.html      Visual dashboard\n" +
    "    - context-map.json Frame/worker hierarchy\n" +
    "    - session.har      Network recording\n" +
    "    - trace.zip        Playwright trace\n\n" +
    "  " + C.dim + "View trace:  npx playwright show-trace " + OUTPUT_DIR + "/trace.zip" + C.reset + "\n" +
    "  " + C.dim + "View report: open " + OUTPUT_DIR + "/report.html" + C.reset + "\n"
  );
}

main().catch(function(err) {
  console.error("\n  " + C.red + "Fatal: " + err.message + C.reset);
  console.error(err.stack);
  process.exit(1);
});
