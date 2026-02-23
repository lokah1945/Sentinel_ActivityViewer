import fs from "node:fs";
import path from "node:path";
import type { ContextMap } from "./frameguard.js";

export function buildReport(
  eventsPath: string,
  targetUrl: string,
  startTime: string,
  mode: string,
  contextMap: ContextMap
) {
  const txt = fs.existsSync(eventsPath) ? fs.readFileSync(eventsPath, "utf8") : "";
  const lines = txt.split("\n").filter(Boolean);
  const finishedAt = new Date().toISOString();
  const startMs = new Date(startTime).getTime();
  const endMs = new Date(finishedAt).getTime();

  const typeCounts: Record<string, number> = {};
  const apiCounts: Record<string, number> = {};
  const intentCounts: Record<string, number> = {};
  const denyCounts: Record<string, number> = {};
  const contextKinds: Record<string, number> = {};
  const fpApis: Record<string, { count: number; contexts: Set<string> }> = {};
  const netDomains = new Set<string>();
  let netTotal = 0, swRequests = 0;
  let cookieAccess = 0, lsOps = 0, ssOps = 0, idbOps = 0, cacheOps = 0;
  const wasmEvents: any[] = [];
  let pmCount = 0, mpCount = 0;
  const bcChannels = new Set<string>();
  let blobUrls = 0, dataUrls = 0, srcdocFrames = 0, hiddenFrames = 0;
  let zeroSizeFrames = 0, dynamicIframes = 0;
  const capabilities: any[] = [];
  const timeline: Record<number, number> = {};

  for (const line of lines) {
    let ev: any;
    try { ev = JSON.parse(line); } catch { continue; }
    const t = ev.type || "";
    typeCounts[t] = (typeCounts[t] || 0) + 1;
    if (ev.api) apiCounts[ev.api] = (apiCounts[ev.api] || 0) + 1;
    if (ev.intent) intentCounts[ev.intent] = (intentCounts[ev.intent] || 0) + 1;
    if (ev.context?.kind) contextKinds[ev.context.kind] = (contextKinds[ev.context.kind] || 0) + 1;
    if (ev.ts) {
      const minute = Math.floor((new Date(ev.ts).getTime() - startMs) / 60000);
      timeline[minute] = (timeline[minute] || 0) + 1;
    }
    if (t === "policy:deny") denyCounts[ev.api || "unknown"] = (denyCounts[ev.api || "unknown"] || 0) + 1;
    if (t === "browser:access" && ev.intent === "fingerprinting") {
      if (!fpApis[ev.api]) fpApis[ev.api] = { count: 0, contexts: new Set() };
      fpApis[ev.api].count++;
      if (ev.context?.url) fpApis[ev.api].contexts.add(ev.context.url);
    }
    if (t === "net:request") {
      netTotal++;
      if (ev.viaServiceWorker) swRequests++;
      try { netDomains.add(new URL(ev.url).hostname); } catch {}
    }
    if (ev.api?.includes("cookie")) cookieAccess++;
    if (ev.api?.startsWith("localStorage")) lsOps++;
    if (ev.api?.startsWith("sessionStorage")) ssOps++;
    if (ev.api?.startsWith("indexedDB")) idbOps++;
    if (ev.api?.startsWith("caches")) cacheOps++;
    if (t.startsWith("wasm:")) wasmEvents.push({ ts: ev.ts, api: ev.api, bytes: ev.bytes });
    if (t === "comms:send" && ev.channel === "postMessage") pmCount++;
    if ((t === "comms:open" || t === "comms:send") && ev.channel === "BroadcastChannel")
      bcChannels.add(ev.name || "default");
    if (ev.api === "MessagePort.postMessage") mpCount++;
    if (t === "evasion:blob_create") blobUrls++;
    if (t === "frameguard:set_src" && ev.isData) dataUrls++;
    if (t === "frameguard:set_srcdoc") srcdocFrames++;
    if (t === "frameguard:iframe_added") {
      dynamicIframes++;
      if (ev.hidden) hiddenFrames++;
      if (ev.zeroSize) zeroSizeFrames++;
    }
    if (t === "browser:capability") capabilities.push(ev.caps);
  }

  const top = (m: Record<string, number>, n = 30) =>
    Object.entries(m)
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([k, v]) => ({ name: k, count: v }));

  let targetDomain = "";
  try { targetDomain = new URL(targetUrl).hostname.split(".").slice(-2).join("."); } catch {}
  const thirdParty = Array.from(netDomains).filter((d) => !d.endsWith(targetDomain));

  const fpApiList = Object.entries(fpApis).map(([name, v]) => ({
    name,
    count: v.count,
    contexts: Array.from(v.contexts),
  }));
  const fpRisk = Math.min(
    100,
    Math.round(
      (fpApiList.length / 30) * 40 +
        (fpApiList.some((a) => a.name.includes("Canvas")) ? 20 : 0) +
        (fpApiList.some((a) => a.name.includes("WebGL")) ? 15 : 0) +
        (fpApiList.some((a) => a.name.includes("Audio")) ? 15 : 0) +
        (fpApiList.filter((a) => a.contexts.length > 1).length > 0 ? 10 : 0)
    )
  );

  return {
    meta: {
      url: targetUrl,
      mode,
      startedAt: startTime,
      finishedAt,
      totalEvents: lines.length,
      duration: `${((endMs - startMs) / 1000).toFixed(1)}s`,
    },
    eventTypes: top(typeCounts, 50),
    topApis: top(apiCounts),
    topIntents: top(intentCounts),
    policyDenied: top(denyCounts),
    contextDistribution: contextKinds,
    fingerprinting: { detected: fpApiList.length > 0, apis: fpApiList.slice(0, 50), riskScore: fpRisk },
    networkSummary: {
      totalRequests: netTotal,
      uniqueDomains: Array.from(netDomains).sort(),
      thirdPartyDomains: thirdParty.sort(),
      serviceWorkerRequests: swRequests,
    },
    storageSummary: { cookieAccess, localStorageOps: lsOps, sessionStorageOps: ssOps, indexedDBOps: idbOps, cacheOps },
    wasmUsage: wasmEvents.slice(0, 100),
    communications: {
      postMessageCount: pmCount,
      broadcastChannels: Array.from(bcChannels),
      messagePortCount: mpCount,
    },
    evasionIndicators: {
      blobUrls,
      dataUrls,
      srcdocFrames,
      hiddenFrames,
      zeroSizeFrames,
      dynamicIframes,
      nestedIframeMaxDepth: contextMap.getMaxDepth(),
    },
    capabilities,
    timeline: Object.entries(timeline)
      .sort(([a], [b]) => Number(a) - Number(b))
      .map(([min, count]) => ({ minute: Number(min), count })),
  };
}

export function saveReport(outDir: string, report: any) {
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "report.json"), JSON.stringify(report, null, 2));
  fs.writeFileSync(path.join(outDir, "report.html"), generateHtml(report));
}

function generateHtml(r: any): string {
  const esc = (s: any) =>
    String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  const riskColor =
    r.fingerprinting.riskScore > 60
      ? "#e74c3c"
      : r.fingerprinting.riskScore > 30
        ? "#f39c12"
        : "#27ae60";

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Sentinel Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;line-height:1.6}
h1{color:#58a6ff;margin-bottom:8px}h2{color:#79c0ff;margin:30px 0 12px;border-bottom:1px solid #21262d;padding-bottom:6px}
.meta{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:16px 0;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.meta-item{display:flex;flex-direction:column}.meta-label{font-size:.75em;color:#8b949e;text-transform:uppercase}.meta-value{font-size:1.1em;color:#f0f6fc;font-weight:600}
.risk-badge{display:inline-block;padding:4px 14px;border-radius:20px;font-weight:700;font-size:1.2em;color:#fff}
.bar{height:20px;background:#21262d;border-radius:4px;overflow:hidden;margin:8px 0}.bar-fill{height:100%;border-radius:4px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px}
.stat-box{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px;text-align:center}
.stat-number{font-size:1.6em;font-weight:700;color:#58a6ff}.stat-label{font-size:.75em;color:#8b949e}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:.9em}th{text-align:left;color:#8b949e;font-size:.75em;text-transform:uppercase;padding:6px 8px;border-bottom:1px solid #21262d}
td{padding:5px 8px;border-bottom:1px solid #21262d15}.num{text-align:right;font-family:monospace;color:#79c0ff}
.tag{display:inline-block;background:#21262d;border-radius:4px;padding:2px 8px;margin:2px;font-size:.82em}
.tag-warn{background:#d299221a;color:#d29922;border:1px solid #d2992233}
.tag-danger{background:#f851491a;color:#f85149;border:1px solid #f8514933}
code{background:#21262d;padding:1px 5px;border-radius:3px;font-size:.88em}
footer{margin-top:40px;padding-top:16px;border-top:1px solid #21262d;color:#484f58;font-size:.8em;text-align:center}
</style></head><body>
<h1>&#128737; Sentinel Owner Mode &mdash; Report</h1>
<div class="meta">
<div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">${esc(r.meta.url)}</span></div>
<div class="meta-item"><span class="meta-label">Mode</span><span class="meta-value">${esc(r.meta.mode).toUpperCase()}</span></div>
<div class="meta-item"><span class="meta-label">Duration</span><span class="meta-value">${esc(r.meta.duration)}</span></div>
<div class="meta-item"><span class="meta-label">Events</span><span class="meta-value">${r.meta.totalEvents.toLocaleString()}</span></div>
</div>

<h2>&#128270; Fingerprinting Risk</h2>
<div class="card">
<span class="risk-badge" style="background:${riskColor}">${r.fingerprinting.riskScore}/100</span>
<span style="margin-left:12px">${r.fingerprinting.riskScore > 60 ? "&#9888;&#65039; HIGH RISK" : r.fingerprinting.riskScore > 30 ? "&#9889; MODERATE" : "&#9989; LOW"}</span>
<div class="bar"><div class="bar-fill" style="width:${r.fingerprinting.riskScore}%;background:${riskColor}"></div></div>
${r.fingerprinting.apis.length > 0 ? `<table><tr><th>API</th><th>Calls</th></tr>${r.fingerprinting.apis.slice(0, 15).map((a: any) => `<tr><td><code>${esc(a.name)}</code></td><td class="num">${a.count}</td></tr>`).join("")}</table>` : ""}
</div>

<h2>&#128202; Overview</h2>
<div class="stat-grid">
<div class="stat-box"><div class="stat-number">${r.meta.totalEvents.toLocaleString()}</div><div class="stat-label">Events</div></div>
<div class="stat-box"><div class="stat-number">${r.networkSummary.totalRequests}</div><div class="stat-label">Requests</div></div>
<div class="stat-box"><div class="stat-number">${r.networkSummary.thirdPartyDomains.length}</div><div class="stat-label">3rd Party</div></div>
<div class="stat-box"><div class="stat-number">${r.evasionIndicators.dynamicIframes}</div><div class="stat-label">Dynamic Iframes</div></div>
<div class="stat-box"><div class="stat-number">${r.evasionIndicators.nestedIframeMaxDepth}</div><div class="stat-label">Max Depth</div></div>
<div class="stat-box"><div class="stat-number">${r.wasmUsage.length}</div><div class="stat-label">WASM</div></div>
<div class="stat-box"><div class="stat-number">${r.communications.postMessageCount}</div><div class="stat-label">postMessage</div></div>
<div class="stat-box"><div class="stat-number">${r.policyDenied.reduce((s: number, d: any) => s + d.count, 0)}</div><div class="stat-label">Blocked</div></div>
</div>

<h2>&#128680; Evasion Indicators</h2>
<div class="stat-grid">
<div class="stat-box"><div class="stat-number">${r.evasionIndicators.blobUrls}</div><div class="stat-label">Blob URLs</div></div>
<div class="stat-box"><div class="stat-number">${r.evasionIndicators.dataUrls}</div><div class="stat-label">Data URLs</div></div>
<div class="stat-box"><div class="stat-number">${r.evasionIndicators.srcdocFrames}</div><div class="stat-label">Srcdoc</div></div>
<div class="stat-box"><div class="stat-number">${r.evasionIndicators.hiddenFrames}</div><div class="stat-label">Hidden</div></div>
<div class="stat-box"><div class="stat-number">${r.evasionIndicators.zeroSizeFrames}</div><div class="stat-label">0x0</div></div>
</div>

<h2>&#128225; Top APIs</h2>
<div class="card"><table><tr><th>API</th><th>Count</th></tr>${r.topApis.slice(0, 25).map((a: any) => `<tr><td><code>${esc(a.name)}</code></td><td class="num">${a.count}</td></tr>`).join("")}</table></div>

<h2>&#127760; Network</h2>
<div class="card">
<p><strong>${r.networkSummary.totalRequests}</strong> requests to <strong>${r.networkSummary.uniqueDomains.length}</strong> domains (${r.networkSummary.thirdPartyDomains.length} 3rd-party)</p>
${r.networkSummary.thirdPartyDomains.length ? `<div style="margin-top:8px">${r.networkSummary.thirdPartyDomains.map((d: string) => `<span class="tag tag-warn">${esc(d)}</span>`).join("")}</div>` : ""}
</div>

<h2>&#128190; Storage</h2>
<div class="stat-grid">
<div class="stat-box"><div class="stat-number">${r.storageSummary.cookieAccess}</div><div class="stat-label">Cookie</div></div>
<div class="stat-box"><div class="stat-number">${r.storageSummary.localStorageOps}</div><div class="stat-label">localStorage</div></div>
<div class="stat-box"><div class="stat-number">${r.storageSummary.sessionStorageOps}</div><div class="stat-label">sessionStorage</div></div>
<div class="stat-box"><div class="stat-number">${r.storageSummary.indexedDBOps}</div><div class="stat-label">IndexedDB</div></div>
<div class="stat-box"><div class="stat-number">${r.storageSummary.cacheOps}</div><div class="stat-label">Cache API</div></div>
</div>

<h2>&#128236; Communication</h2>
<div class="stat-grid">
<div class="stat-box"><div class="stat-number">${r.communications.postMessageCount}</div><div class="stat-label">postMessage</div></div>
<div class="stat-box"><div class="stat-number">${r.communications.broadcastChannels.length}</div><div class="stat-label">BroadcastChannels</div></div>
<div class="stat-box"><div class="stat-number">${r.communications.messagePortCount}</div><div class="stat-label">MessagePort</div></div>
</div>

<h2>&#128203; All Event Types</h2>
<div class="card"><table><tr><th>Type</th><th>Count</th></tr>${r.eventTypes.map((e: any) => `<tr><td>${esc(e.name)}</td><td class="num">${e.count}</td></tr>`).join("")}</table></div>

<footer>&#128737; Sentinel Owner Mode &mdash; Generated ${esc(r.meta.finishedAt)}</footer>
</body></html>`;
}
