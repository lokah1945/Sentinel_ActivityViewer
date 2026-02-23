"use strict";
const fs = require("fs");
const path = require("path");

const RISK_WEIGHTS = { critical: 40, high: 10, medium: 3, low: 1 };

function generateReport(eventsFile, outputDir) {
  if (!fs.existsSync(eventsFile)) { console.log("No events file found."); return null; }
  const raw = fs.readFileSync(eventsFile, "utf-8").trim();
  if (!raw) { console.log("Events file is empty."); return null; }

  const events = raw.split("\n").map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);

  const byCat = {};
  const byRisk = { critical: 0, high: 0, medium: 0, low: 0 };
  const byApi = {};
  const origins = new Set();
  const frames = new Set();

  for (const ev of events) {
    byCat[ev.cat] = (byCat[ev.cat] || 0) + 1;
    byRisk[ev.risk] = (byRisk[ev.risk] || 0) + 1;
    byApi[ev.api] = (byApi[ev.api] || 0) + 1;
    if (ev.origin) origins.add(ev.origin);
    if (ev.frame) frames.add(ev.frame);
  }

  let riskScore = 0;
  for (const [r, c] of Object.entries(byRisk)) riskScore += (RISK_WEIGHTS[r] || 0) * c;
  riskScore = Math.min(100, Math.round(riskScore / Math.max(events.length, 1) * 10));

  const topApis = Object.entries(byApi).sort((a, b) => b[1] - a[1]).slice(0, 20);

  const report = {
    generated: new Date().toISOString(),
    totalEvents: events.length,
    riskScore,
    byCategory: byCat,
    byRisk,
    topApis,
    uniqueOrigins: [...origins],
    frames: [...frames],
    timeSpanMs: events.length > 1 ? events[events.length - 1]._ts - events[0]._ts : 0,
  };

  fs.writeFileSync(path.join(outputDir, "report.json"), JSON.stringify(report, null, 2));

  const riskColor = riskScore >= 70 ? "#ef4444" : riskScore >= 40 ? "#f59e0b" : "#22c55e";
  const catRows = Object.entries(byCat).sort((a,b)=>b[1]-a[1]).map(([c,n])=>"<tr><td>"+c+"</td><td>"+n+"</td></tr>").join("");
  const apiRows = topApis.map(([a,n])=>"<tr><td>"+a+"</td><td>"+n+"</td></tr>").join("");
  const originList = [...origins].map(o=>"<li>"+o+"</li>").join("");

  const html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Sentinel Report</title>\n<style>\n*{margin:0;padding:0;box-sizing:border-box}\nbody{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}\nh1{font-size:1.8rem;margin-bottom:0.5rem;color:#f8fafc}\n.subtitle{color:#94a3b8;margin-bottom:2rem}\n.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}\n.card{background:#1e293b;border-radius:12px;padding:1.5rem;text-align:center}\n.card .label{font-size:0.85rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em}\n.card .value{font-size:2rem;font-weight:700;margin-top:0.25rem}\n.risk-badge{display:inline-block;font-size:3rem;font-weight:800;color:'+riskColor+';border:4px solid '+riskColor+';border-radius:50%;width:100px;height:100px;line-height:92px;text-align:center}\ntable{width:100%;border-collapse:collapse;margin-bottom:2rem}\nth,td{text-align:left;padding:0.6rem 1rem;border-bottom:1px solid #334155}\nth{color:#94a3b8;font-size:0.8rem;text-transform:uppercase}\ntd{font-family:SF Mono,monospace;font-size:0.9rem}\n.section{margin-top:2rem}\n.section h2{font-size:1.2rem;margin-bottom:1rem;color:#f8fafc}\nul{list-style:none;padding-left:0} li{padding:0.3rem 0;font-family:monospace;font-size:0.9rem}\nli::before{content:"-> ";color:#94a3b8}\n</style>\n</head>\n<body>\n<h1>Sentinel Owner Mode - Report</h1>\n<p class="subtitle">Generated '+report.generated+'</p>\n\n<div class="grid">\n<div class="card"><div class="label">Risk Score</div><div class="risk-badge">'+riskScore+'</div></div>\n<div class="card"><div class="label">Total Events</div><div class="value">'+events.length+'</div></div>\n<div class="card"><div class="label">Critical</div><div class="value" style="color:#ef4444">'+byRisk.critical+'</div></div>\n<div class="card"><div class="label">High</div><div class="value" style="color:#f59e0b">'+byRisk.high+'</div></div>\n<div class="card"><div class="label">Medium</div><div class="value" style="color:#3b82f6">'+byRisk.medium+'</div></div>\n<div class="card"><div class="label">Low</div><div class="value" style="color:#22c55e">'+byRisk.low+'</div></div>\n<div class="card"><div class="label">Categories</div><div class="value">'+Object.keys(byCat).length+'</div></div>\n<div class="card"><div class="label">Origins</div><div class="value">'+origins.size+'</div></div>\n</div>\n\n<div class="section"><h2>Events by Category</h2>\n<table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>'+catRows+'</tbody></table></div>\n\n<div class="section"><h2>Top APIs Called</h2>\n<table><thead><tr><th>API</th><th>Count</th></tr></thead><tbody>'+apiRows+'</tbody></table></div>\n\n<div class="section"><h2>Observed Origins</h2><ul>'+(originList||"<li>None</li>")+'</ul></div>\n</body></html>';

  fs.writeFileSync(path.join(outputDir, "report.html"), html);
  return report;
}

module.exports = { generateReport };
