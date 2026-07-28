import { useEffect, useId, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import type { ExportFormat } from '../shared/types'

const EXPORTS: { format: ExportFormat; label: string; meta: string }[] = [
  { format: 'json', label: 'JSON', meta: 'Structured data' },
  { format: 'txt', label: 'TXT', meta: 'Plain text report' },
  { format: 'csv', label: 'CSV', meta: 'Spreadsheet-friendly' },
  { format: 'md', label: 'Markdown', meta: 'Readable markdown' },
  { format: 'html', label: 'HTML', meta: 'Standalone web page' },
]

interface ExportDropdownProps {
  disabled?: boolean
  disabledReason?: string
  onExport: (format: ExportFormat) => void
}

export function ExportDropdown(props: ExportDropdownProps) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const listId = useId()

  useEffect(() => {
    if (!open) return
    const onPointer = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onPointer)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointer)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div
      className={`project-dropdown export-dropdown${props.disabled ? ' disabled' : ''}${open ? ' is-open' : ''}`}
      ref={rootRef}
    >
      <span className="project-filter-label">Export</span>
      <button
        type="button"
        className={`project-trigger${open ? ' open' : ''}`}
        disabled={props.disabled}
        title={props.disabled ? props.disabledReason : 'Export report'}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listId}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="project-trigger-text">
          <span className="project-trigger-title">Choose format</span>
          <span className="project-trigger-meta">JSON, TXT, CSV, Markdown, HTML</span>
        </span>
        <motion.span
          className="project-caret"
          animate={{ rotate: open ? 180 : 0 }}
          transition={{ duration: 0.18 }}
          aria-hidden="true"
        >
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path
              d="M2.5 4.5L6 8l3.5-3.5"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </motion.span>
      </button>

      <AnimatePresence>
        {open && !props.disabled && (
          <motion.div
            id={listId}
            className="project-menu"
            role="listbox"
            aria-label="Export formats"
            initial={{ opacity: 0, y: -6, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.98 }}
            transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
          >
            {EXPORTS.map((item) => (
              <button
                key={item.format}
                type="button"
                role="option"
                className="project-option"
                onClick={() => {
                  setOpen(false)
                  props.onExport(item.format)
                }}
              >
                <span className="project-option-title">{item.label}</span>
                <span className="project-option-meta">{item.meta}</span>
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
