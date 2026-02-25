/**
 * ReportGenerator v6.3.0
 * Generates JSON + HTML forensic reports.
 */

'use strict';

const fs = require('fs');
const path = require('path');

class ReportGenerator {
  constructor(version) {
    this.version = version;
    this.outputDir = path.join(process.cwd(), 'output');
    if (!fs.existsSync(this.outputDir)) fs.mkdirSync(this.outputDir, { recursive: true });
  }

  save(mode, ts, events, analysis, context) {
    const base = `sentinel-${mode}-${ts}`;
    const jp = path.join(this.outputDir, `${base}-report.json`);
    const hp = path.join(this.outputDir, `${base}-report.html`);
    const cp = path.join(this.outputDir, `${base}-context.json`);

    fs.writeFileSync(jp, JSON.stringify({ version: this.version, target: context.target, mode, timestamp: new Date(ts).toISOString(), events, analysis }, null, 2));
    fs.writeFileSync(cp, JSON.stringify(context, null, 2));
    fs.writeFileSync(hp, this._html(analysis, context, events));

    return { json: jp, html: hp, context: cp };
  }

  _html(analysis, ctx, events) {
    const { categories, threats, libraryDetections, networkConversation, cookies, websockets, thirdParties, entropy, h5w, riskScore, injectionStatus, exfiltration } = analysis;
    const dur = ((Date.now() - new Date(ctx.scanDate).getTime()) / 1000).toFixed(1);

    let h = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${this.version} ${ctx.target}</title><style>
*{margin:0;padding:0;box-sizing:border-box}body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.6}
.c{max-width:1400px;margin:0 auto;padding:20px}header{text-align:center;padding:30px 0;border-bottom:1px solid #30363d}
h1{color:#58a6ff;font-size:1.8em}h2{color:#58a6ff;margin:20px 0 10px;font-size:1.2em;border-bottom:1px solid #21262d;padding-bottom:5px}
.sub{color:#8b949e;margin-top:8px}.kg{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin:16px 0}
.k{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;text-align:center}
.k.g{border-color:#238636}.k.w{border-color:#d29922}.k.b{border-color:#da3633}
.kv{font-size:1.5em;font-weight:bold;color:#f0f6fc}.kl{color:#8b949e;font-size:0.8em;margin-top:4px}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:0.85em}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #21262d}th{background:#161b22;color:#58a6ff;font-weight:600}
tr:hover{background:#161b22}.bd{background:#238636;color:#fff;padding:2px 6px;border-radius:4px;font-size:0.75em}
.rc{color:#ff7b72;font-weight:bold}.rh{color:#ffa657}.rm{color:#d29922}
.fl{display:flex;flex-wrap:wrap;gap:6px}.f{padding:3px 8px;border-radius:4px;font-size:0.8em}
.fo{background:#0d4429;color:#3fb950;border:1px solid #238636}.ff{background:#3d1e20;color:#ff7b72;border:1px solid #da3633}
.hb{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px;margin:6px 0}
.hb h3{color:#ffa657;margin-bottom:4px;font-size:1em}pre{color:#c9d1d9;white-space:pre-wrap;font-size:0.8em;max-height:180px;overflow-y:auto}
.u{max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
footer{text-align:center;color:#484f58;padding:20px 0;border-top:1px solid #21262d;margin-top:20px;font-size:0.85em}
.pure{background:#0d4429;color:#3fb950;padding:4px 12px;border-radius:6px;display:inline-block;margin:8px 0;font-weight:bold}
</style></head><body><div class="c">`;

    h += `<header><h1>🛡️ ${this.version} — Pure Observer CCTV</h1>`;
    h += `<p class="sub">Target: <strong>${ctx.target}</strong> | Mode: <strong>${ctx.mode}</strong> | ${ctx.scanDate}</p>`;
    h += `<div class="pure">✅ ZERO INJECTION | ZERO SPOOFING | 100% PASSIVE CDP</div>`;
    h += `<p class="sub">rebrowser-patches: <strong>${injectionStatus?.runtimeFixMode || 'addBinding'}</strong> | Runtime.Enable: <strong>PATCHED</strong></p></header>`;

    // KPIs
    const rc = riskScore >= 50 ? 'b' : riskScore >= 20 ? 'w' : 'g';
    h += `<div class="kg">`;
    h += `<div class="k g"><div class="kv">${events.length}</div><div class="kl">CDP Events</div></div>`;
    h += `<div class="k ${rc}"><div class="kv">${riskScore}/100</div><div class="kl">Risk Score</div></div>`;
    h += `<div class="k"><div class="kv">${categories.length}</div><div class="kl">Categories</div></div>`;
    h += `<div class="k"><div class="kv">${dur}s</div><div class="kl">Duration</div></div>`;
    h += `<div class="k g"><div class="kv">${ctx.coverageProof?.frameCoverage || 'N/A'}</div><div class="kl">Frame Coverage</div></div>`;
    h += `<div class="k ${threats.length > 10 ? 'b' : 'w'}"><div class="kv">${threats.length}</div><div class="kl">Threats</div></div>`;
    h += `<div class="k"><div class="kv">${injectionStatus?.networkEntries || 0}</div><div class="kl">Network Entries</div></div>`;
    h += `<div class="k"><div class="kv">${libraryDetections?.length || 0}</div><div class="kl">Libraries Found</div></div>`;
    h += `</div>`;

    // Observer Status
    h += `<section><h2>Observer Status</h2><div class="fl">`;
    if (injectionStatus) {
      for (const [k, v] of Object.entries(injectionStatus)) {
        const cls = v === true || v === 'addBinding' || (typeof v === 'number' && v > 0) ? 'fo' : (v === false ? 'ff' : 'fo');
        h += `<span class="f ${cls}">${k}: ${v}</span>`;
      }
    }
    h += `</div></section>`;

    // Categories
    h += `<section><h2>Event Categories (${categories.length})</h2><table><thead><tr><th>Category</th><th>Events</th><th>Risk</th></tr></thead><tbody>`;
    for (const c of categories) {
      const cls = c.risk === 'critical' ? 'rc' : c.risk === 'high' ? 'rh' : 'rm';
      h += `<tr><td>${c.name}</td><td>${c.events}</td><td class="${cls}">${c.risk}</td></tr>`;
    }
    h += `</tbody></table></section>`;

    // Libraries
    if (libraryDetections?.length > 0) {
      h += `<section><h2>🔍 Libraries Detected in Traffic</h2><table><thead><tr><th>Library</th><th>Confidence</th><th>Source URL</th></tr></thead><tbody>`;
      for (const l of libraryDetections) {
        h += `<tr><td><strong>${this._e(l.name)}</strong></td><td>${l.confidence}</td><td class="u">${this._e(l.url)}</td></tr>`;
      }
      h += `</tbody></table></section>`;
    }

    // Third Parties
    if (thirdParties?.length > 0) {
      h += `<section><h2>Third-Party Domains (${thirdParties.length})</h2><table><thead><tr><th>Domain</th><th>Requests</th><th>Categories</th><th>Risk</th></tr></thead><tbody>`;
      for (const tp of thirdParties.slice(0, 30)) {
        const cls = tp.risk === 'critical' ? 'rc' : tp.risk === 'high' ? 'rh' : 'rm';
        h += `<tr><td>${this._e(tp.domain)}</td><td>${tp.requests}</td><td>${tp.categories.slice(0, 3).join(', ')}</td><td class="${cls}">${tp.risk}</td></tr>`;
      }
      h += `</tbody></table></section>`;
    }

    // Threats
    h += `<section><h2>⚠️ Threats (${threats.length})</h2><table><thead><tr><th>Risk</th><th>Category</th><th>API</th><th>Detail</th></tr></thead><tbody>`;
    for (const t of threats.slice(0, 60)) {
      const cls = t.risk === 'critical' ? 'rc' : 'rh';
      h += `<tr><td class="${cls}">${t.risk}</td><td>${t.category}</td><td>${t.api}</td><td>${this._e(t.detail?.slice(0, 300))}</td></tr>`;
    }
    h += `</tbody></table></section>`;

    // WebSockets
    if (websockets?.length > 0) {
      h += `<section><h2>🔌 WebSocket Activity (${websockets.length})</h2><table><thead><tr><th>Action</th><th>Detail</th><th>Risk</th></tr></thead><tbody>`;
      for (const ws of websockets.slice(0, 20)) {
        h += `<tr><td>${ws.api}</td><td>${this._e(ws.detail?.slice(0, 300))}</td><td>${ws.risk}</td></tr>`;
      }
      h += `</tbody></table></section>`;
    }

    // Cookies
    h += `<section><h2>🍪 Cookie Activity</h2><p>Cookies set: <strong>${cookies?.cookiesSet || 0}</strong> | Cookies sent: <strong>${cookies?.cookiesSent || 0}</strong></p></section>`;

    // Network
    h += `<section><h2>🌐 Network (${networkConversation?.length || 0} requests)</h2><table><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Type</th><th>Initiator</th></tr></thead><tbody>`;
    for (const n of (networkConversation || []).slice(0, 100)) {
      h += `<tr><td><span class="bd">${n.method}</span></td><td class="u">${this._e(n.url)}</td><td>${n.status}</td><td>${n.type}</td><td>${n.initiator}</td></tr>`;
    }
    h += `</tbody></table></section>`;

    // 5W1H
    h += `<section><h2>🔍 5W1H Forensic Summary</h2>`;
    for (const [k, v] of Object.entries(h5w || {})) {
      h += `<div class="hb"><h3>${k.toUpperCase()}</h3><pre>${JSON.stringify(v, null, 2)}</pre></div>`;
    }
    h += `</section>`;

    // Entropy
    h += `<section><h2>📊 Entropy Analysis</h2><p>Category: <strong>${entropy?.categoryEntropy || 0}</strong> | API: <strong>${entropy?.apiEntropy || 0}</strong></p></section>`;

    h += `<footer><p>${this.version} — Pure Observer CCTV | Generated ${new Date().toISOString()}</p>`;
    h += `<p>Powered by: rebrowser-playwright-core + stealth plugin | ZERO INJECTION</p></footer></div></body></html>`;
    return h;
  }

  _e(s) { return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
}

module.exports = { ReportGenerator };
