import type { LiveFinding, StatusEvent } from '../shared/types'

interface ProgressViewProps {
  phase: string
  detail: string
  percent: number
  findings: LiveFinding[]
  findingCount: number
  events: StatusEvent[]
  onClearEvents: () => void
}

export function ProgressView(props: ProgressViewProps) {
  const pct = Math.max(0, Math.min(100, props.percent))

  return (
    <section className="view">
      <div className="progress-card panel">
        <div className="progress-top">
          <div className="progress-copy">
            <h2>{props.phase}</h2>
            <p className="detail">{props.detail}</p>
          </div>
          <div className="pct">{pct}%</div>
        </div>
        <div className="bar" aria-hidden="true">
          <div className="bar-fill" style={{ width: `${pct}%` }} />
        </div>
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
