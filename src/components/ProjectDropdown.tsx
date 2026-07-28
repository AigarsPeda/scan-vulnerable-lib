import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'

export interface ProjectOption {
  path: string
  name: string
  isCache: boolean
  count: number
}

interface ProjectDropdownProps {
  value: string
  options: ProjectOption[]
  disabled?: boolean
  onChange: (path: string) => void
}

export function ProjectDropdown(props: ProjectDropdownProps) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const listId = useId()

  const visible = useMemo(() => props.options, [props.options])

  const selected = useMemo(() => {
    if (props.value === 'all') {
      return {
        label: `All projects (${props.options.length})`,
        meta: 'Show every project and cache',
      }
    }
    const match = props.options.find((o) => o.path === props.value)
    if (!match) {
      return {
        label: `All projects (${props.options.length})`,
        meta: 'Show every project and cache',
      }
    }
    return {
      label: match.name,
      meta: match.isCache
        ? `Cache · ${match.count} finding${match.count === 1 ? '' : 's'}`
        : `${match.count} finding${match.count === 1 ? '' : 's'}`,
    }
  }, [props.options, props.value])

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
    <div className={`project-dropdown${props.disabled ? ' disabled' : ''}${open ? ' is-open' : ''}`} ref={rootRef}>
      <span className="project-filter-label">Project</span>
      <button
        type="button"
        className={`project-trigger${open ? ' open' : ''}`}
        disabled={props.disabled || props.options.length === 0}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listId}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="project-trigger-text">
          <span className="project-trigger-title">{selected.label}</span>
          <span className="project-trigger-meta">{selected.meta}</span>
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
        {open && (
          <motion.div
            id={listId}
            className="project-menu"
            role="listbox"
            aria-label="Projects"
            initial={{ opacity: 0, y: -6, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.98 }}
            transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
          >
            <button
              type="button"
              role="option"
              aria-selected={props.value === 'all'}
              className={`project-option${props.value === 'all' ? ' selected' : ''}`}
              onClick={() => {
                props.onChange('all')
                setOpen(false)
              }}
            >
              <span className="project-option-title">All projects</span>
              <span className="project-option-meta">{props.options.length} locations</span>
            </button>
            <div className="project-option-divider" />
            {visible.map((p) => (
              <button
                key={p.path}
                type="button"
                role="option"
                aria-selected={props.value === p.path}
                className={`project-option${props.value === p.path ? ' selected' : ''}`}
                title={p.path}
                onClick={() => {
                  props.onChange(p.path)
                  setOpen(false)
                }}
              >
                <span className="project-option-title">{p.name}</span>
                <span className="project-option-meta">
                  {p.isCache
                    ? `Cache · ${p.count}`
                    : `${p.count} finding${p.count === 1 ? '' : 's'}`}
                </span>
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
