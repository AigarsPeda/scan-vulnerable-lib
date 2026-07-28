import type { ScanState } from '../shared/types'
import { motion } from 'motion/react'

interface SidebarProps {
  iconUrl: string
  scanState: ScanState
  statusLabel: string
  statusTone: string
  reportReady?: boolean
  tab: 'scan' | 'report'
  onSelectTab: (tab: 'scan' | 'report') => void
  optionsLocked: boolean
  highOnly: boolean
  skipCache: boolean
  skipOsv: boolean
  maxProjects: number
  rootPath: string
  onHighOnly: (v: boolean) => void
  onSkipCache: (v: boolean) => void
  onSkipOsv: (v: boolean) => void
  onMaxProjects: (v: number) => void
  onRootPath: (v: string) => void
  onPrimaryClick: () => void
  onStop: () => void
  onPickFolder: () => void
}

export function Sidebar(props: SidebarProps) {
  const primaryLabel =
    props.scanState === 'running' ? 'Pause' : props.scanState === 'paused' ? 'Resume' : 'Start'
  const primaryClass =
    props.scanState === 'running' ? 'btn warn' : 'btn primary'
  const locked = props.optionsLocked

  return (
    <aside className="sidebar">
      <div className="brand">
        <img className="brand-icon" src={props.iconUrl} alt="" width={28} height={28} />
        <div className="brand-text">
          <h1>Vuln Scanner</h1>
          <p>Library security scan</p>
        </div>
      </div>

      <div className={`status-pill ${props.statusTone}`.trim()}>
        {(props.scanState === 'running' || props.scanState === 'paused') && (
          <span
            className={`status-dots${props.scanState === 'paused' ? ' paused' : ''}`}
            aria-hidden="true"
          >
            <span /><span /><span />
            <span /><span /><span />
            <span /><span /><span />
          </span>
        )}
        <span>{props.statusLabel}</span>
      </div>

      <nav className="tabs" role="tablist">
        {(
          [
            ['scan', 'Progress'],
            ['report', 'Report'],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={`tab${props.tab === id ? ' active' : ''}`}
            onClick={() => props.onSelectTab(id)}
          >
            {props.tab === id && (
              <motion.span
                className="tab-indicator"
                layoutId="sidebar-tab-indicator"
                transition={{ type: 'spring', stiffness: 420, damping: 32 }}
              />
            )}
            <span className="tab-label">{label}</span>
            {id === 'report' && props.reportReady && (
              <span className="tab-ready-dot" title="Report is ready" />
            )}
          </button>
        ))}
      </nav>

      <section className={`side-panel${locked ? ' options-locked' : ''}`}>
        <h2>Options</h2>
        <div className="options-stack">
          <label className={`check${locked ? ' disabled' : ''}`}>
            <input
              type="checkbox"
              checked={props.highOnly}
              disabled={locked}
              onChange={(e) => props.onHighOnly(e.target.checked)}
            />
            <span>High / Critical only</span>
          </label>
          <label className={`check${locked ? ' disabled' : ''}`}>
            <input
              type="checkbox"
              checked={props.skipCache}
              disabled={locked}
              onChange={(e) => props.onSkipCache(e.target.checked)}
            />
            <span>Skip caches</span>
          </label>
          <label className={`check${locked ? ' disabled' : ''}`}>
            <input
              type="checkbox"
              checked={props.skipOsv}
              disabled={locked}
              onChange={(e) => props.onSkipOsv(e.target.checked)}
            />
            <span>Skip OSV API</span>
          </label>
        </div>
        <label className={`field${locked ? ' disabled' : ''}`}>
          <span>Max projects / ecosystem</span>
          <input
            type="number"
            min={1}
            max={500}
            value={props.maxProjects}
            disabled={locked}
            onChange={(e) => props.onMaxProjects(Number(e.target.value || 80))}
          />
        </label>
        <label className={`field${locked ? ' disabled' : ''}`}>
          <span>Optional root folder</span>
          <div className="path-row">
            <input
              type="text"
              placeholder="Leave empty for defaults"
              value={props.rootPath}
              disabled={locked}
              onChange={(e) => props.onRootPath(e.target.value)}
            />
            <button
              type="button"
              className="btn ghost icon-btn"
              disabled={locked}
              onClick={props.onPickFolder}
              title={locked ? 'Unavailable while scanning' : 'Browse'}
            >
              …
            </button>
          </div>
        </label>
        {locked && (
          <p className="options-lock-note">Options are locked while a scan is running or paused.</p>
        )}
      </section>

      <div className="side-actions">
        <button type="button" className={primaryClass} onClick={props.onPrimaryClick}>
          {primaryLabel}
        </button>
        <button
          type="button"
          className="btn danger"
          disabled={props.scanState === 'idle'}
          onClick={props.onStop}
        >
          Stop
        </button>
      </div>
    </aside>
  )
}
