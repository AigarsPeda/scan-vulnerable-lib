import { useMemo, useState } from 'react'
import type { ExportFormat, ReportFinding, ScanState } from '../shared/types'

interface ReportViewProps {
  findings: ReportFinding[]
  findingCount: number
  scanState: ScanState
  phase: string
  percent: number
  onExport: (format: ExportFormat) => void
}

const EXPORTS: ExportFormat[] = ['json', 'txt', 'csv', 'md', 'html']

const LABELS: Record<ExportFormat, string> = {
  json: 'JSON',
  txt: 'TXT',
  csv: 'CSV',
  md: 'Markdown',
  html: 'HTML',
}

type KindFilter = 'all' | 'project' | 'cache'
type SevFilter = 'all' | 'critical' | 'high' | 'medium' | 'low'

function folderLabel(pathValue: string): string {
  if (!pathValue) return '(unknown)'
  const parts = pathValue.replace(/\//g, '\\').split('\\').filter(Boolean)
  return parts[parts.length - 1] || pathValue
}

export function ReportView(props: ReportViewProps) {
  const [kind, setKind] = useState<KindFilter>('all')
  const [sev, setSev] = useState<SevFilter>('all')
  const [query, setQuery] = useState('')

  const counts = useMemo(() => {
    const c = { total: props.findings.length, critical: 0, high: 0, medium: 0, low: 0 }
    for (const f of props.findings) {
      if (f.severity === 'critical') c.critical++
      else if (f.severity === 'high') c.high++
      else if (f.severity === 'medium' || f.severity === 'moderate') c.medium++
      else if (f.severity === 'low') c.low++
    }
    return c
  }, [props.findings])

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase()
    const map = new Map<string, ReportFinding[]>()

    for (const f of props.findings) {
      if (kind === 'project' && f.isCache) continue
      if (kind === 'cache' && !f.isCache) continue
      if (sev !== 'all' && f.severity !== sev && !(sev === 'medium' && f.severity === 'moderate')) continue
      if (q) {
        const hay = `${f.packageName} ${f.version} ${f.title} ${f.path} ${f.advisory} ${f.ecosystem}`.toLowerCase()
        if (!hay.includes(q)) continue
      }
      const key = f.path || '(unknown)'
      const list = map.get(key) || []
      list.push(f)
      map.set(key, list)
    }

    return Array.from(map.entries()).map(([path, items]) => ({
      path,
      name: folderLabel(path),
      isCache: items.some((i) => i.isCache),
      items,
    }))
  }, [props.findings, kind, sev, query])

  const visibleCount = groups.reduce((n, g) => n + g.items.length, 0)
  const live = props.scanState === 'running' || props.scanState === 'paused'

  return (
    <section className="view">
      <div className="report-toolbar">
        <div className="report-heading">
          <h2>Findings report</h2>
          <p className="report-note">
            {live
              ? `Live · ${props.phase || 'Scanning'} · ${Math.round(props.percent)}%`
              : 'Export a copy when you need a file.'}
          </p>
        </div>
        <div className="export-group" role="group" aria-label="Export report">
          <h2 className="export-label">Export</h2>
          <div className="export-buttons">
            {EXPORTS.map((format) => (
              <button
                key={format}
                type="button"
                className="btn ghost small"
                onClick={() => props.onExport(format)}
              >
                {LABELS[format]}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="report-native">
        <div className="report-summary">
          <span className="counts-pill total">total: {counts.total}</span>
          <span className="counts-pill critical">critical: {counts.critical}</span>
          <span className="counts-pill high">high: {counts.high}</span>
          <span className="counts-pill medium">medium: {counts.medium}</span>
          <span className="counts-pill low">low: {counts.low}</span>
        </div>

        <div className="report-filters">
          <input
            type="search"
            className="report-search"
            placeholder="Search package / CVE / path…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="filter-pills">
            {(
              [
                ['all', 'ALL'],
                ['project', 'PROJECTS'],
                ['cache', 'CACHES'],
              ] as const
            ).map(([value, label]) => (
              <button
                key={value}
                type="button"
                className={`filter-pill kind-${value}${kind === value ? ' active' : ''}`}
                onClick={() => setKind(value)}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="filter-pills">
            {(
              [
                ['all', 'ALL SEVERITIES'],
                ['critical', 'CRITICAL'],
                ['high', 'HIGH'],
                ['medium', 'MEDIUM'],
                ['low', 'LOW'],
              ] as const
            ).map(([value, label]) => (
              <button
                key={value}
                type="button"
                className={`filter-pill sev-${value}${sev === value ? ' active' : ''}`}
                onClick={() => setSev(value)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        <div className="report-list">
          {groups.length === 0 ? (
            <div className="report-empty-inline">
              {props.findingCount > 0 && props.findings.length === 0
                ? 'No findings match these filters.'
                : 'No findings yet. They appear here live while scanning.'}
            </div>
          ) : (
            groups.map((group) => (
              <article key={group.path} className={`report-group${group.isCache ? ' cache' : ''}`}>
                <header className="report-group-head">
                  <div className="report-group-label">
                    {group.isCache ? 'CACHE' : 'PROJECT'} · {group.items.length} finding
                    {group.items.length === 1 ? '' : 's'}
                  </div>
                  <h3>{group.name}</h3>
                  <div className="report-group-path">{group.path}</div>
                </header>
                <ul className="report-items">
                  {group.items.map((f) => (
                    <li key={f.id}>
                      <div className="issue-head">
                        <span className={`sev ${f.severity}`}>{f.severity}</span>
                        <span className={`fix-badge ${f.hasFix ? 'fix-yes' : 'fix-no'}`}>
                          {f.hasFix ? 'FIX AVAILABLE' : 'NO KNOWN FIX'}
                        </span>
                        <code>
                          {f.packageName}
                          {f.version ? `@${f.version}` : ''}
                          {f.ecosystem ? ` (${f.ecosystem})` : ''}
                        </code>
                      </div>
                      {f.title && <div className="issue-title">{f.title}</div>}
                      {f.fix && (
                        <div className="issue-fix">
                          <strong>How to solve:</strong> {f.fix}
                        </div>
                      )}
                      {f.advisory && (
                        <div className="issue-adv">
                          <strong>Advisories:</strong> {f.advisory}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              </article>
            ))
          )}
        </div>

        {groups.length > 0 && (
          <div className="report-footer">
            Showing {visibleCount} of {props.findings.length}
          </div>
        )}
      </div>
    </section>
  )
}
