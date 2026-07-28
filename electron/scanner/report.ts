import fs from 'fs'
import type { Finding } from './types'

function esc(s: string): string {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

export function writeHtmlReport(reportPath: string, findings: Finding[], platform: string): void {
  const rows = findings
    .map(
      (f) => `<tr data-sev="${esc(f.Severity)}" data-eco="${esc(f.Ecosystem)}" data-cache="${f.IsCache ? '1' : '0'}">
  <td>${esc(f.Severity)}</td>
  <td>${esc(f.Package)}${f.Version ? '@' + esc(f.Version) : ''}</td>
  <td>${esc(f.Ecosystem)}</td>
  <td>${esc(f.Title)}</td>
  <td>${esc(f.Path)}</td>
  <td>${f.HasFix ? esc(f.Fix) : ''}</td>
  <td>${esc(f.Advisory)}</td>
</tr>`
    )
    .join('\n')

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Vulnerable Library Report</title>
<style>
  body{font-family:ui-sans-serif,system-ui,sans-serif;margin:24px;background:#0f1419;color:#e7ecf3}
  h1{font-size:1.4rem;margin:0 0 8px}
  .meta{opacity:.7;margin-bottom:16px}
  input,select{background:#1a222d;border:1px solid #2c3848;color:#e7ecf3;padding:6px 8px;border-radius:6px;margin-right:8px}
  table{width:100%;border-collapse:collapse;margin-top:16px;font-size:13px}
  th,td{border-bottom:1px solid #243041;padding:8px;text-align:left;vertical-align:top}
  th{opacity:.7;font-weight:600}
  .critical,.high{color:#ff7b72}
  .medium,.moderate{color:#ffa657}
  .low{color:#7ee787}
</style>
</head>
<body>
  <h1>Vulnerable Library Report</h1>
  <div class="meta">${esc(platform)} · ${findings.length} finding(s) · ${esc(new Date().toISOString())}</div>
  <div>
    <input id="q" placeholder="Filter…" oninput="filter()"/>
    <select id="sev" onchange="filter()">
      <option value="">All severities</option>
      <option>critical</option><option>high</option><option>medium</option><option>low</option>
    </select>
    <select id="cache" onchange="filter()">
      <option value="">Projects + caches</option>
      <option value="0">Projects only</option>
      <option value="1">Caches only</option>
    </select>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Package</th><th>Eco</th><th>Title</th><th>Path</th><th>Fix</th><th>Advisory</th></tr></thead>
    <tbody id="tb">${rows}</tbody>
  </table>
  <script>
    function filter(){
      const q=(document.getElementById('q').value||'').toLowerCase();
      const sev=document.getElementById('sev').value;
      const cache=document.getElementById('cache').value;
      for (const tr of document.querySelectorAll('#tb tr')){
        const text=tr.innerText.toLowerCase();
        const okQ=!q||text.includes(q);
        const okS=!sev||tr.dataset.sev===sev;
        const okC=!cache||tr.dataset.cache===cache;
        tr.style.display=(okQ&&okS&&okC)?'':'none';
      }
    }
  </script>
</body>
</html>`

  fs.writeFileSync(reportPath, html, 'utf8')
}
