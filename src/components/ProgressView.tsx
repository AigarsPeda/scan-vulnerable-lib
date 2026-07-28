import type { LiveFinding, StatusEvent } from '../shared/types'

interface ProgressViewProps {
  phase: string
  detail: string
  percent: number
  findings: LiveFinding[]
  findingCount: number
  events: StatusEvent[]
  scanState: 'idle' | 'running' | 'paused'
  elapsedMs: number
  ecoLabel: string
  ecoCurrent: number
  ecoTotal: number
  onClearEvents: () => void
}

function formatDuration(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000))
  const h = Math.floor(totalSec / 3600)
  const m = Math.floor((totalSec % 3600) / 60)
  const s = totalSec % 60
  if (h > 0) return `${h}h ${m}m ${s.toString().padStart(2, '0')}s`
  if (m > 0) return `${m}m ${s.toString().padStart(2, '0')}s`
  return `${s}s`
}

function parsePhaseStep(phase: string): { current: number; total: number } | null {
  const m = phase.match(/Phase\s+(\d+)\s*\/\s*(\d+)/i)
  if (!m) return null
  return { current: Number(m[1]), total: Number(m[2]) }
}

function parseItemProgress(detail: string): { current: number; total: number; label: string } | null {
  const m = detail.match(/^\[(\d+)\s*\/\s*(\d+)\]\s*(.*)$/)
  if (!m) return null
  return { current: Number(m[1]), total: Number(m[2]), label: m[3].trim() }
}

export function ProgressView(props: ProgressViewProps) {
  const pct = Math.max(0, Math.min(100, props.percent))
  const pctLabel = Number.isInteger(pct) ? `${pct}` : pct.toFixed(1)
  const active = props.scanState === 'running' || props.scanState === 'paused'
  const phaseStep = parsePhaseStep(props.phase)
  const itemProgress = parseItemProgress(props.detail)
  const showEco =
    Boolean(props.ecoLabel) && props.ecoTotal > 0 && (active || props.ecoCurrent > 0)

  const detailText = itemProgress?.label || props.detail

  return (
    <section className="view">
      <div className="progress-card panel">
        <div className="progress-top">
          <div className="progress-copy">
            <h2>{props.phase}</h2>
            <p className="detail">{detailText || ' '}</p>
            <div className="progress-meta">
              {phaseStep && (
                <span>
                  Phase {phaseStep.current} of {phaseStep.total}
                </span>
              )}
              {itemProgress && (
                <span>
                  Item {itemProgress.current} of {itemProgress.total}
                </span>
              )}
              {showEco && (
                <span className="eco-chip">
                  {props.ecoLabel} {props.ecoCurrent}/{props.ecoTotal}
                </span>
              )}
              {active && <span>Elapsed {formatDuration(props.elapsedMs)}</span>}
              {props.scanState === 'paused' && <span>Paused</span>}
            </div>
          </div>
          <div className="pct">{pctLabel}%</div>
        </div>
        <div className="bar" aria-hidden="true">
          <div className="bar-fill" style={{ width: `${pct}%` }} />
        </div>
        {showEco && (
          <div className="eco-bar" aria-label={`${props.ecoLabel} progress`}>
            <div className="eco-bar-label">
              <span>{props.ecoLabel}</span>
              <span>
                {props.ecoCurrent} / {props.ecoTotal}
              </span>
            </div>
            <div className="eco-bar-track">
              <div
                className="eco-bar-fill"
                style={{
                  width: `${Math.min(100, (props.ecoCurrent / Math.max(1, props.ecoTotal)) * 100)}%`,
                }}
              />
            </div>
          </div>
        )}
      </div>

      <div className="split-panels">
        <div className="findings-card panel">
          <div className="panel-head">
            <h2>Found so far</h2>
            <span className="findings-count">{props.findingCount}</span>
          </div>
          {props.findings.length === 0 ? (
            <p className="findings-empty">No issues found yet.</p>
          ) : (
            <ul className="live-findings">
              {props.findings.map((f) => (
                <li key={f.id}>
                  <span className={`sev ${f.severity}`}>{f.severity}</span>
                  <div>
                    <div className="pkg">
                      {f.package}
                      {f.ecosystem ? ` (${f.ecosystem})` : ''}
                    </div>
                    {(f.title || f.folder) && (
                      <div className="meta">{[f.title, f.folder].filter(Boolean).join(' · ')}</div>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="events-card panel">
          <div className="panel-head">
            <h2>Status</h2>
            <button type="button" className="btn ghost small" onClick={props.onClearEvents}>
              Clear
            </button>
          </div>
          <ul className="events">
            {props.events.map((e) => (
              <li key={e.id} className={e.type}>
                {e.time}  {e.text}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  )
}
