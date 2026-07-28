import { useCallback, useEffect, useRef, useState } from 'react'
import type {
  ExportFormat,
  LiveFinding,
  ReportFinding,
  ScanFinding,
  ScanOptions,
  ScanProgress,
  ScanState,
  StatusEvent,
  TabName,
} from '../shared/types'

let nextEventId = 1
let nextFindingId = 1

function isTerminalPhase(phase?: string): boolean {
  const p = String(phase || '').toUpperCase()
  return p === 'DONE' || p === 'STOPPED' || p === 'FAILED' || p === 'READY' || p === ''
}

export function useScan() {
  const [tab, setTab] = useState<TabName>('scan')
  const [scanState, setScanState] = useState<ScanState>('idle')
  const [statusLabel, setStatusLabel] = useState('Idle')
  const [statusTone, setStatusTone] = useState('')
  const [phase, setPhase] = useState('Ready')
  const [detail, setDetail] = useState('Configure options and start a scan.')
  const [percent, setPercent] = useState(0)
  const [events, setEvents] = useState<StatusEvent[]>([])
  const [findings, setFindings] = useState<LiveFinding[]>([])
  const [reportFindings, setReportFindings] = useState<ReportFinding[]>([])
  const [findingCount, setFindingCount] = useState(0)
  const [scriptMissing, setScriptMissing] = useState(false)

  const [highOnly, setHighOnly] = useState(false)
  const [skipCache, setSkipCache] = useState(false)
  const [skipOsv, setSkipOsv] = useState(false)
  const [maxProjects, setMaxProjects] = useState(80)
  const [rootPath, setRootPath] = useState('')

  const scanStateRef = useRef(scanState)
  scanStateRef.current = scanState
  const reportFindingsRef = useRef<ReportFinding[]>([])
  reportFindingsRef.current = reportFindings
  const reloadTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const addEvent = useCallback((type: string, text: string) => {
    const item: StatusEvent = {
      id: nextEventId++,
      type,
      text,
      time: new Date().toLocaleTimeString(),
    }
    setEvents((prev) => [item, ...prev].slice(0, 200))
  }, [])

  const clearEvents = useCallback(() => setEvents([]), [])

  const clearFindings = useCallback(() => {
    setFindings([])
    setReportFindings([])
    setFindingCount(0)
  }, [])

  const reloadFindings = useCallback(async () => {
    try {
      const res = await window.scannerApi.getFindings()
      if (!res.ok || !res.findings) return
      // Don't wipe live rows with an empty/partial file read mid-scan
      if (
        res.findings.length === 0 &&
        reportFindingsRef.current.length > 0 &&
        scanStateRef.current !== 'idle'
      ) {
        return
      }
      if (res.findings.length === 0 && reportFindingsRef.current.length === 0) {
        setFindingCount((c) => (typeof res.count === 'number' && res.count > c ? res.count : c))
        return
      }
      setReportFindings(res.findings)
      setFindingCount((c) => Math.max(c, res.count ?? res.findings!.length))
    } catch {
      // ignore
    }
  }, [])

  const appendLiveReportFinding = useCallback((payload: ScanFinding) => {
    const raw = String(payload.package || 'unknown package')
    const at = raw.lastIndexOf('@')
    const packageName = at > 0 ? raw.slice(0, at) : raw
    const version = at > 0 ? raw.slice(at + 1) : ''
    let severity = String(payload.severity || 'unknown').toLowerCase()
    if (severity === 'moderate') severity = 'medium'
    const pathValue = String(payload.folder || '')
    const title = String(payload.title || '')
    const item: ReportFinding = {
      id: `live-${nextFindingId}-${pathValue}|${packageName}|${version}|${title}|${severity}`,
      severity,
      ecosystem: String(payload.ecosystem || ''),
      packageName,
      version,
      title,
      path: pathValue,
      fix: '',
      hasFix: Boolean(payload.hasFix),
      advisory: '',
      isCache: /cache/i.test(pathValue),
      source: '',
    }
    setReportFindings((prev) => {
      if (
        prev.some(
          (f) =>
            f.packageName === item.packageName &&
            f.version === item.version &&
            f.title === item.title &&
            f.path === item.path &&
            f.severity === item.severity
        )
      ) {
        return prev
      }
      return [item, ...prev]
    })
  }, [])

  const scheduleReloadFindings = useCallback(() => {
    if (reloadTimer.current) return
    reloadTimer.current = setTimeout(() => {
      reloadTimer.current = null
      void reloadFindings()
    }, 500)
  }, [reloadFindings])

  const markActive = useCallback((paused = false) => {
    if (paused) {
      setScanState('paused')
      setStatusLabel('Paused')
      setStatusTone('paused')
      return
    }
    setScanState('running')
    setStatusLabel('Scanning')
    setStatusTone('running')
  }, [])

  const applyProgress = useCallback(
    (payload: ScanProgress, opts?: { live?: boolean }) => {
      const live = Boolean(opts?.live)
      const phaseUpper = String(payload.phase || '').toUpperCase()

      // Stop clears the bar — ignore any stale percent from the dying scanner
      if (phaseUpper === 'STOPPED') {
        setPercent(0)
        setPhase('STOPPED')
        if (typeof payload.detail === 'string') setDetail(payload.detail || 'Stopped by user')
        return
      }

      if (typeof payload.percent === 'number') {
        setPercent(Math.max(0, Math.min(100, payload.percent)))
      }
      if (payload.phase) setPhase(payload.phase)
      if (typeof payload.detail === 'string') setDetail(payload.detail || ' ')
      if (typeof payload.findingCount === 'number') {
        setFindingCount((c) => (payload.findingCount! > c ? payload.findingCount! : c))
      }

      if (!live) return

      if (payload.paused === true) {
        markActive(true)
        return
      }

      if (
        scanStateRef.current === 'idle' &&
        !isTerminalPhase(payload.phase) &&
        (typeof payload.percent === 'number' ? payload.percent > 0 : Boolean(payload.phase))
      ) {
        markActive(false)
        return
      }

      if (
        payload.paused === false &&
        scanStateRef.current === 'paused' &&
        payload.phase !== 'Paused'
      ) {
        markActive(false)
      }
    },
    [markActive]
  )

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [info, runtime] = await Promise.all([
          window.scannerApi.getAppInfo(),
          window.scannerApi.getScanRuntime(),
        ])
        if (cancelled) return

        setScriptMissing(!info.scriptExists)
        if (!info.scriptExists) addEvent('error', 'Scanner script missing from app package.')

        if (runtime.progress) applyProgress(runtime.progress as ScanProgress, { live: false })
        await reloadFindings()

        if (runtime.recentFindings?.length && findings.length === 0) {
          setFindings(
            runtime.recentFindings.map((f) => ({
              id: nextFindingId++,
              severity: String(f.severity || 'unknown').toLowerCase(),
              package: f.package || 'unknown package',
              ecosystem: f.ecosystem || '',
              title: f.title || '',
              folder: f.folder || '',
              hasFix: Boolean(f.hasFix),
            }))
          )
        }

        if (runtime.recentLogs.length) {
          setEvents(
            runtime.recentLogs.map((log) => ({
              id: nextEventId++,
              type: log.type || 'info',
              text: log.text || '',
              time: new Date().toLocaleTimeString(),
            }))
          )
        }

        if (runtime.running) {
          markActive(runtime.paused)
          addEvent('meta', 'Reconnected to active scan')
        } else {
          setScanState('idle')
          const phaseText = String((runtime.progress as ScanProgress | null)?.phase || '')
          if (isTerminalPhase(phaseText) && phaseText.toUpperCase() === 'DONE') {
            setStatusLabel('Finished')
            setStatusTone('done')
          } else if (runtime.findingCount > 0 || runtime.reportUrl) {
            setStatusLabel('Idle')
            setStatusTone('')
            addEvent('meta', 'Loaded previous scan results — press Start to run again')
          } else {
            setStatusLabel('Idle')
            setStatusTone('')
          }
        }
      } catch (err) {
        if (!cancelled) addEvent('error', String(err))
      }
    })()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- hydrate once on mount
  }, [])

  useEffect(() => {
    const unsubs = [
      window.scannerApi.onScanLog((payload) => {
        addEvent(payload.type || 'info', payload.text || '')
      }),
      window.scannerApi.onScanProgress((payload) => {
        applyProgress(payload, { live: true })
      }),
      window.scannerApi.onScanFinding((payload) => {
        if (scanStateRef.current === 'idle') markActive(false)
        const item: LiveFinding = {
          id: nextFindingId++,
          severity: String(payload.severity || 'unknown').toLowerCase(),
          package: payload.package || 'unknown package',
          ecosystem: payload.ecosystem || '',
          title: payload.title || '',
          folder: payload.folder || '',
          hasFix: Boolean(payload.hasFix),
        }
        setFindings((prev) => [item, ...prev].slice(0, 300))
        setFindingCount((c) => (Number(payload.count) > 0 ? Number(payload.count) : c + 1))
        // Live Report: append immediately from the stream (don't wait on findings.json)
        appendLiveReportFinding(payload)
        scheduleReloadFindings()
      }),
      window.scannerApi.onFindingsUpdated(() => {
        scheduleReloadFindings()
      }),
      window.scannerApi.onScanStatus((payload) => {
        if (payload.running) {
          markActive(Boolean(payload.paused))
          return
        }

        setScanState('idle')
        void reloadFindings()

        if (payload.stopped) {
          setPercent(0)
          setPhase('STOPPED')
          setDetail('Stopped by user')
          setStatusLabel('Stopped')
          setStatusTone('error')
          addEvent('warn', 'Scan stopped')
          return
        }

        if (payload.error) {
          setStatusLabel('Error')
          setStatusTone('error')
          addEvent('error', payload.error)
          return
        }

        if (payload.reportExists || payload.exitCode === 0) {
          setStatusLabel('Finished')
          setStatusTone('done')
          setPercent(100)
          setPhase('DONE')
          setDetail('Scan finished')
          addEvent('done', 'Scan finished')
          setTab('report')
        } else {
          setStatusLabel(`Exit ${payload.exitCode}`)
          setStatusTone('error')
          addEvent('error', `Scanner exited with code ${payload.exitCode}`)
        }
      }),
    ]

    return () => {
      unsubs.forEach((u) => u())
      if (reloadTimer.current) clearTimeout(reloadTimer.current)
    }
  }, [addEvent, appendLiveReportFinding, applyProgress, markActive, reloadFindings, scheduleReloadFindings])

  const selectTab = useCallback(
    async (name: TabName) => {
      setTab(name)
      if (name === 'report') await reloadFindings()
    },
    [reloadFindings]
  )

  const startScan = useCallback(async () => {
    clearFindings()
    markActive(false)
    setPercent(1)
    setPhase('Starting')
    setDetail('Launching scanner…')
    addEvent('meta', 'Scan started')

    const options: ScanOptions = {
      highOnly,
      skipCache,
      skipOsv,
      maxProjects,
      driveOrPath: rootPath.trim(),
    }

    const res = await window.scannerApi.startScan(options)
    if (!res.ok) {
      setScanState('idle')
      setStatusLabel('Error')
      setStatusTone('error')
      addEvent('error', res.error || 'Failed to start')
    }
  }, [addEvent, clearFindings, highOnly, markActive, maxProjects, rootPath, skipCache, skipOsv])

  const pauseScan = useCallback(async () => {
    const res = await window.scannerApi.pauseScan()
    if (!res.ok) {
      addEvent('error', res.error || 'Could not pause')
      return
    }
    markActive(true)
    addEvent('warn', 'Pause requested')
  }, [addEvent, markActive])

  const resumeScan = useCallback(async () => {
    const res = await window.scannerApi.resumeScan()
    if (!res.ok) {
      addEvent('error', res.error || 'Could not resume')
      return
    }
    markActive(false)
    addEvent('meta', 'Resume requested')
  }, [addEvent, markActive])

  const stopScan = useCallback(async () => {
    // Reset progress immediately on click — don't wait for process exit
    setPercent(0)
    setPhase('STOPPED')
    setDetail('Stopped by user')
    setScanState('idle')
    setStatusLabel('Stopped')
    setStatusTone('error')

    const res = await window.scannerApi.stopScan()
    if (!res.ok) {
      setStatusLabel('Idle')
      setStatusTone('')
      addEvent('warn', res.error || 'No active scan — UI reset')
      return
    }
  }, [addEvent])

  const onPrimaryClick = useCallback(async () => {
    if (scanState === 'idle') await startScan()
    else if (scanState === 'running') await pauseScan()
    else if (scanState === 'paused') await resumeScan()
  }, [pauseScan, resumeScan, scanState, startScan])

  const optionsLocked = scanState === 'running' || scanState === 'paused'

  const resetScanUiForOptions = useCallback(() => {
    clearFindings()
    setPercent(0)
    setPhase('Ready')
    setDetail('Configure options and start a scan.')
    setStatusLabel('Idle')
    setStatusTone('')
    addEvent('warn', 'Scan progress cleared after options change')
  }, [addEvent, clearFindings])

  const tryChangeOption = useCallback(
    (apply: () => void) => {
      if (scanStateRef.current !== 'idle') return
      const dirty =
        findingCount > 0 ||
        findings.length > 0 ||
        reportFindings.length > 0 ||
        percent > 0
      if (dirty) {
        const ok = window.confirm(
          'Changing options will reset scan progress and findings. Continue?'
        )
        if (!ok) return
        resetScanUiForOptions()
      }
      apply()
    },
    [findingCount, findings.length, percent, reportFindings.length, resetScanUiForOptions]
  )

  const setHighOnlySafe = useCallback(
    (v: boolean) => tryChangeOption(() => setHighOnly(v)),
    [tryChangeOption]
  )
  const setSkipCacheSafe = useCallback(
    (v: boolean) => tryChangeOption(() => setSkipCache(v)),
    [tryChangeOption]
  )
  const setSkipOsvSafe = useCallback(
    (v: boolean) => tryChangeOption(() => setSkipOsv(v)),
    [tryChangeOption]
  )
  const setMaxProjectsSafe = useCallback(
    (v: number) => tryChangeOption(() => setMaxProjects(v)),
    [tryChangeOption]
  )
  const setRootPathSafe = useCallback(
    (v: string) => tryChangeOption(() => setRootPath(v)),
    [tryChangeOption]
  )

  const pickFolder = useCallback(async () => {
    if (scanStateRef.current !== 'idle') return
    const folder = await window.scannerApi.pickFolder()
    if (!folder) return
    tryChangeOption(() => setRootPath(folder))
  }, [tryChangeOption])

  const exportReport = useCallback(
    async (format: ExportFormat) => {
      const res = await window.scannerApi.exportReport(format)
      if (res?.canceled) return
      if (!res?.ok) {
        addEvent('error', res?.error || `Export ${format} failed`)
        return
      }
      addEvent('done', `Exported ${String(format).toUpperCase()}: ${res.path}`)
    },
    [addEvent]
  )

  return {
    tab,
    selectTab,
    scanState,
    statusLabel,
    statusTone,
    phase,
    detail,
    percent,
    events,
    clearEvents,
    findings,
    reportFindings,
    findingCount,
    scriptMissing,
    optionsLocked,
    highOnly,
    setHighOnly: setHighOnlySafe,
    skipCache,
    setSkipCache: setSkipCacheSafe,
    skipOsv,
    setSkipOsv: setSkipOsvSafe,
    maxProjects,
    setMaxProjects: setMaxProjectsSafe,
    rootPath,
    setRootPath: setRootPathSafe,
    onPrimaryClick,
    stopScan,
    pickFolder,
    exportReport,
  }
}
