import { app, BrowserWindow, ipcMain, shell, dialog, Menu, clipboard } from 'electron'
import path from 'path'
import fs from 'fs'
import os from 'os'
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process'
import { pathToFileURL } from 'url'
import type { ExportFormat, ScanOptions } from '../../src/shared/types'

let mainWindow: BrowserWindow | null = null
let scanProcess: ChildProcessWithoutNullStreams | null = null
let progressTimer: ReturnType<typeof setInterval> | null = null
let userRequestedStop = false
let lastFindingsMtime = 0
let lastReportMtime = 0
const recentLogs: { type: string; text: string }[] = []

function pushLog(type: string, text: string): void {
  recentLogs.unshift({ type, text })
  if (recentLogs.length > 120) recentLogs.length = 120
  send('scan-log', { type, text })
}

function readControlAction(): string {
  try {
    const p = getControlPath()
    if (!fs.existsSync(p)) return 'run'
    const raw = JSON.parse(fs.readFileSync(p, 'utf8')) as { action?: string }
    return raw.action === 'pause' || raw.action === 'stop' || raw.action === 'run' ? raw.action : 'run'
  } catch {
    return 'run'
  }
}

function projectRoot(): string {
  // Dev: out/main -> repo root
  return path.join(__dirname, '../..')
}

/** Packaged apps load scripts/assets from extraResources; dev uses the repo root. */
function resourceRoot(): string {
  if (app.isPackaged) return process.resourcesPath
  return projectRoot()
}

function getDataDir(): string {
  const dir = path.join(app.getPath('userData'), 'scan-data')
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
  return dir
}

function getReportPath(): string {
  return path.join(getDataDir(), 'vulnerable-libs-report.html')
}

function getProgressPath(): string {
  return path.join(getDataDir(), 'scan-progress.json')
}

function getControlPath(): string {
  return path.join(getDataDir(), 'scan-control.json')
}

function getFindingsPath(): string {
  return path.join(getDataDir(), 'findings.json')
}

function writeControlAction(action: string): void {
  const payload = JSON.stringify({ action, updated: new Date().toISOString() })
  fs.writeFileSync(getControlPath(), payload, 'utf8')
}

function getScannerScriptPath(): string {
  return path.join(resourceRoot(), 'scripts', 'scan-vulnerable-libs.ps1')
}

function getAppIconPath(): string {
  return path.join(resourceRoot(), 'assets', 'icon.png')
}

function resolvePowerShell(): string {
  if (process.platform === 'win32') {
    const candidates = [
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'PowerShell', '7', 'pwsh.exe'),
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'PowerShell', '7-preview', 'pwsh.exe'),
      path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ]
    for (const c of candidates) {
      if (fs.existsSync(c)) return c
    }
    return 'powershell.exe'
  }
  const candidates = ['/opt/homebrew/bin/pwsh', '/usr/local/bin/pwsh', '/usr/bin/pwsh']
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  return 'pwsh'
}

function send(channel: string, payload: unknown): void {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload)
  }
}

function readProgressFile(): Record<string, unknown> | null {
  try {
    const p = getProgressPath()
    if (!fs.existsSync(p)) return null
    return JSON.parse(fs.readFileSync(p, 'utf8')) as Record<string, unknown>
  } catch {
    return null
  }
}

function stopProgressPolling(): void {
  if (progressTimer) {
    clearInterval(progressTimer)
    progressTimer = null
  }
}

function startProgressPolling(): void {
  stopProgressPolling()
  progressTimer = setInterval(() => {
    const prog = readProgressFile()
    if (prog) {
      const action = readControlAction()
      // Keep UI paused while control says pause — stale progress.json still has paused:false
      // until the scanner reaches the next Wait-IfGuiPaused checkpoint.
      if (action === 'pause') {
        send('scan-progress', {
          ...prog,
          paused: true,
          phase: 'Paused',
          detail:
            typeof prog.detail === 'string' && /resume/i.test(prog.detail)
              ? prog.detail
              : 'Pause requested — waiting for current step to finish…',
        })
      } else {
        send('scan-progress', prog)
      }
    }
    const report = getReportPath()
    if (fs.existsSync(report)) {
      try {
        const st = fs.statSync(report)
        if (st.mtimeMs !== lastReportMtime) {
          lastReportMtime = st.mtimeMs
          send('report-updated', {
            path: report,
            mtimeMs: st.mtimeMs,
            url: pathToFileURL(report).href,
          })
        }
      } catch {
        // ignore
      }
    }
    const findingsPath = getFindingsPath()
    if (fs.existsSync(findingsPath)) {
      try {
        const st = fs.statSync(findingsPath)
        if (st.mtimeMs !== lastFindingsMtime) {
          lastFindingsMtime = st.mtimeMs
          const data = readFindingsData()
          send('findings-updated', {
            mtimeMs: st.mtimeMs,
            count: data?.count ?? data?.findings?.length ?? 0,
          })
        }
      } catch {
        // ignore
      }
    }
  }, 400)
}

function createWindow(): void {
  const iconPath = getAppIconPath()
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 960,
    minHeight: 640,
    title: 'Vulnerable Library Scanner',
    backgroundColor: '#0b0b0b',
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  })

  if (process.env.ELECTRON_RENDERER_URL) {
    mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL)
  } else {
    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'))
  }

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null)
  getDataDir()
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  stopProgressPolling()
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => {
  stopProgressPolling()
  if (scanProcess && !scanProcess.killed) {
    try {
      scanProcess.kill()
    } catch {
      // ignore
    }
  }
})

ipcMain.handle('get-app-info', async () => {
  const scriptPath = getScannerScriptPath()
  const reportPath = getReportPath()
  return {
    platform: process.platform,
    platformLabel:
      process.platform === 'darwin' ? 'macOS' : process.platform === 'win32' ? 'Windows' : process.platform,
    dataDir: getDataDir(),
    reportPath,
    reportUrl: fs.existsSync(reportPath) ? pathToFileURL(reportPath).href : null,
    scriptPath,
    scriptExists: fs.existsSync(scriptPath),
    reportExists: fs.existsSync(reportPath),
    powerShell: resolvePowerShell(),
    home: os.homedir(),
  }
})

ipcMain.handle('get-report-url', async () => {
  const reportPath = getReportPath()
  if (!fs.existsSync(reportPath)) return { ok: false, error: 'No report yet.' }
  return { ok: true, path: reportPath, url: pathToFileURL(reportPath).href }
})

ipcMain.handle('get-findings', async () => {
  try {
    const p = getFindingsPath()
    if (!fs.existsSync(p)) {
      return { ok: true, count: 0, findings: [], generated: '', mtimeMs: 0 }
    }
    let data: FindingsFile
    try {
      data = JSON.parse(fs.readFileSync(p, 'utf8')) as FindingsFile
    } catch {
      // Don't treat a mid-write / corrupt file as an empty report
      return { ok: false, error: 'Findings file is not readable yet.' }
    }
    const raw = data?.findings
    const rows: FindingRow[] = Array.isArray(raw) ? raw : raw ? [raw as FindingRow] : []
    const mtimeMs = fs.statSync(p).mtimeMs
    lastFindingsMtime = mtimeMs
    return {
      ok: true,
      count: data?.count ?? rows.length,
      generated: data?.generated || '',
      mtimeMs,
      findings: rows.map((f, i) => mapFindingRow(f, i)),
    }
  } catch (err) {
    return { ok: false, error: String(err) }
  }
})

ipcMain.handle('get-scan-runtime', async () => {
  const running = Boolean(scanProcess && !scanProcess.killed)
  // Clear stale pause flag left behind by a previous app session
  if (!running) {
    try {
      writeControlAction('run')
    } catch {
      // ignore
    }
  }

  const prog = readProgressFile()
  const reportPath = getReportPath()
  const reportExists = fs.existsSync(reportPath)
  let reportMtimeMs = 0
  if (reportExists) {
    try {
      reportMtimeMs = fs.statSync(reportPath).mtimeMs
    } catch {
      reportMtimeMs = 0
    }
  }
  const findings = readFindingsData()
  const rows = Array.isArray(findings?.findings) ? findings!.findings! : []
  const recentFindings = rows
    .slice(-80)
    .reverse()
    .map((f) => ({
      severity: String(f.Severity || 'unknown').toLowerCase(),
      package: f.Version ? `${f.Package || ''}@${f.Version}` : String(f.Package || ''),
      ecosystem: f.Ecosystem || '',
      title: f.Title || '',
      folder: f.Path || '',
      hasFix: Boolean(f.HasFix),
      isCache: Boolean(f.IsCache),
      count: rows.length,
    }))
  const action = readControlAction()
  return {
    running,
    paused: running && action === 'pause',
    progress: prog,
    reportUrl: reportExists ? pathToFileURL(reportPath).href : null,
    reportMtimeMs,
    findingCount: findings?.count ?? rows.length,
    recentLogs: [...recentLogs],
    recentFindings,
  }
})

interface FindingRow {
  Severity?: string
  Ecosystem?: string
  Package?: string
  Version?: string
  Title?: string
  Path?: string
  HasFix?: boolean
  Fix?: string
  Advisory?: string
  IsCache?: boolean
  Source?: string
}

interface FindingsFile {
  generated?: string
  platform?: string
  count?: number
  findings?: FindingRow[]
}

function readFindingsData(): FindingsFile | null {
  const p = getFindingsPath()
  if (!fs.existsSync(p)) return null
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8')) as FindingsFile
  } catch {
    return null
  }
}

function mapFindingRow(f: FindingRow, i: number) {
  const packageName = String(f.Package || '')
  const version = String(f.Version || '')
  const pathValue = String(f.Path || '')
  const title = String(f.Title || '')
  let severity = String(f.Severity || 'unknown').toLowerCase()
  if (severity === 'moderate') severity = 'medium'
  return {
    id: `${pathValue}|${packageName}|${version}|${title}|${severity}|${i}`,
    severity,
    ecosystem: String(f.Ecosystem || ''),
    packageName,
    version,
    title,
    path: pathValue,
    fix: String(f.Fix || ''),
    hasFix: Boolean(f.HasFix),
    advisory: String(f.Advisory || ''),
    isCache: Boolean(f.IsCache),
    source: String(f.Source || ''),
  }
}

function csvEscape(value: unknown): string {
  const s = value == null ? '' : String(value)
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`
  return s
}

function buildExportContent(format: ExportFormat, data: FindingsFile) {
  const findings = Array.isArray(data?.findings) ? data.findings : []
  const generated = data?.generated || new Date().toISOString()
  const count = data?.count ?? findings.length

  if (format === 'json') {
    return {
      content: JSON.stringify({ generated, platform: data?.platform || '', count, findings }, null, 2),
      defaultPath: 'vulnerable-libs-report.json',
      filters: [{ name: 'JSON', extensions: ['json'] }],
    }
  }

  if (format === 'csv') {
    const header = [
      'Severity',
      'Ecosystem',
      'Package',
      'Version',
      'Title',
      'Path',
      'HasFix',
      'Fix',
      'Advisory',
      'IsCache',
      'Source',
    ]
    const rows = findings.map((f) =>
      [
        f.Severity,
        f.Ecosystem,
        f.Package,
        f.Version,
        f.Title,
        f.Path,
        f.HasFix ? 'yes' : 'no',
        f.Fix,
        f.Advisory,
        f.IsCache ? 'yes' : 'no',
        f.Source,
      ]
        .map(csvEscape)
        .join(',')
    )
    return {
      content: [header.join(','), ...rows].join('\r\n'),
      defaultPath: 'vulnerable-libs-report.csv',
      filters: [{ name: 'CSV', extensions: ['csv'] }],
    }
  }

  if (format === 'txt') {
    const lines = [
      'Vulnerable Library Scanner Report',
      `Generated: ${generated}`,
      `Findings: ${count}`,
      '',
    ]
    findings.forEach((f, i) => {
      lines.push(
        `--- ${i + 1}. [${String(f.Severity || 'unknown').toUpperCase()}] ${f.Package || ''}@${f.Version || ''} ---`
      )
      lines.push(`Ecosystem: ${f.Ecosystem || ''}`)
      lines.push(`Title: ${f.Title || ''}`)
      lines.push(`Path: ${f.Path || ''}`)
      lines.push(`Fix available: ${f.HasFix ? 'yes' : 'no'}`)
      if (f.Fix) lines.push(`Fix: ${f.Fix}`)
      if (f.Advisory) lines.push(`Advisories: ${f.Advisory}`)
      lines.push('')
    })
    return {
      content: lines.join('\r\n'),
      defaultPath: 'vulnerable-libs-report.txt',
      filters: [{ name: 'Text', extensions: ['txt'] }],
    }
  }

  if (format === 'md') {
    const lines = [
      '# Vulnerable Library Scanner Report',
      '',
      `- Generated: ${generated}`,
      `- Findings: **${count}**`,
      '',
    ]
    findings.forEach((f, i) => {
      lines.push(`## ${i + 1}. ${f.Package || 'package'}@${f.Version || '?'}`)
      lines.push('')
      lines.push(`- **Severity:** ${f.Severity || 'unknown'}`)
      lines.push(`- **Ecosystem:** ${f.Ecosystem || ''}`)
      lines.push(`- **Title:** ${f.Title || ''}`)
      lines.push(`- **Path:** \`${f.Path || ''}\``)
      lines.push(`- **Fix available:** ${f.HasFix ? 'yes' : 'no'}`)
      if (f.Fix) lines.push(`- **Fix:** ${f.Fix}`)
      if (f.Advisory) lines.push(`- **Advisories:** ${f.Advisory}`)
      lines.push('')
    })
    return {
      content: lines.join('\n'),
      defaultPath: 'vulnerable-libs-report.md',
      filters: [{ name: 'Markdown', extensions: ['md'] }],
    }
  }

  if (format === 'html') {
    const reportPath = getReportPath()
    if (!fs.existsSync(reportPath)) {
      throw new Error('No HTML report yet.')
    }
    return {
      content: fs.readFileSync(reportPath, 'utf8'),
      defaultPath: 'vulnerable-libs-report.html',
      filters: [{ name: 'HTML', extensions: ['html'] }],
    }
  }

  throw new Error(`Unknown export format: ${format}`)
}

ipcMain.handle('export-report', async (_event, format: ExportFormat = 'json') => {
  try {
    const data = readFindingsData()
    if ((!data || !Array.isArray(data.findings) || data.findings.length === 0) && format !== 'html') {
      return { ok: false, error: 'No findings to export yet. Run a scan first.' }
    }
    if (format === 'html' && !fs.existsSync(getReportPath())) {
      return { ok: false, error: 'No HTML report yet. Run a scan first.' }
    }

    const built = buildExportContent(format, data || { findings: [], count: 0 })
    const result = await dialog.showSaveDialog(mainWindow!, {
      title: `Export report (${String(format).toUpperCase()})`,
      defaultPath: path.join(os.homedir(), 'Desktop', built.defaultPath),
      filters: built.filters,
    })
    if (result.canceled || !result.filePath) return { ok: false, canceled: true }

    fs.writeFileSync(result.filePath, built.content, 'utf8')
    return { ok: true, path: result.filePath, format }
  } catch (err) {
    return { ok: false, error: String(err) }
  }
})

ipcMain.handle('reveal-data', async () => {
  const dir = getDataDir()
  shell.openPath(dir)
  return { ok: true, path: dir }
})

ipcMain.handle('open-path', async (_event, targetPath: string) => {
  try {
    if (!targetPath || typeof targetPath !== 'string') {
      return { ok: false, error: 'No path provided.' }
    }
    let p = targetPath
    if (!fs.existsSync(p)) {
      // If a file path was passed, try parent folder
      const parent = path.dirname(p)
      if (fs.existsSync(parent)) p = parent
      else return { ok: false, error: 'Path not found.' }
    }
    const st = fs.statSync(p)
    const openTarget = st.isDirectory() ? p : path.dirname(p)
    await shell.openPath(openTarget)
    return { ok: true, path: openTarget }
  } catch (err) {
    return { ok: false, error: String(err) }
  }
})

ipcMain.handle('copy-text', async (_event, text: string) => {
  try {
    clipboard.writeText(String(text || ''))
    return { ok: true }
  } catch (err) {
    return { ok: false, error: String(err) }
  }
})

ipcMain.handle('pick-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow!, {
    properties: ['openDirectory'],
    title: 'Choose a folder to scan',
  })
  if (result.canceled || !result.filePaths.length) return null
  return result.filePaths[0]
})

ipcMain.handle('pause-scan', async () => {
  if (!scanProcess) return { ok: false, error: 'No scan is running.' }
  try {
    writeControlAction('pause')
    const prev = readProgressFile() || {}
    const percent = typeof prev.percent === 'number' ? prev.percent : undefined
    const detail = 'Pause requested — waiting for current step to finish…'
    try {
      fs.writeFileSync(
        getProgressPath(),
        JSON.stringify({
          ...prev,
          paused: true,
          phase: 'Paused',
          detail,
          updated: new Date().toISOString(),
        }),
        'utf8'
      )
    } catch {
      // ignore
    }
    send('scan-progress', { percent, phase: 'Paused', detail, paused: true })
    send('scan-status', { running: true, paused: true })
    pushLog('warn', 'Pause requested — waiting for current step…')
    return { ok: true }
  } catch (err) {
    return { ok: false, error: String(err) }
  }
})

ipcMain.handle('resume-scan', async () => {
  if (!scanProcess) return { ok: false, error: 'No scan is running.' }
  try {
    writeControlAction('run')
    try {
      const prev = readProgressFile() || {}
      fs.writeFileSync(
        getProgressPath(),
        JSON.stringify({
          ...prev,
          paused: false,
          detail: 'Resuming…',
          updated: new Date().toISOString(),
        }),
        'utf8'
      )
    } catch {
      // ignore
    }
    send('scan-status', { running: true, paused: false })
    pushLog('meta', 'Resume requested')
    return { ok: true }
  } catch (err) {
    return { ok: false, error: String(err) }
  }
})

ipcMain.handle('stop-scan', async () => {
  if (!scanProcess) return { ok: false, error: 'No scan is running.' }
  try {
    userRequestedStop = true
    writeControlAction('stop')
    pushLog('warn', 'Stop requested')

    // Zero progress immediately so the UI bar clears on click
    try {
      fs.writeFileSync(
        getProgressPath(),
        JSON.stringify({
          percent: 0,
          phase: 'STOPPED',
          detail: 'Stopped by user',
          report: getReportPath(),
          paused: false,
        }),
        'utf8'
      )
    } catch {
      // ignore
    }
    send('scan-progress', {
      percent: 0,
      phase: 'STOPPED',
      detail: 'Stopped by user',
      paused: false,
    })

    const proc = scanProcess
    await new Promise((resolve) => setTimeout(resolve, 900))
    if (scanProcess === proc && proc && !proc.killed) {
      try {
        if (process.platform === 'win32') {
          spawn('taskkill', ['/pid', String(proc.pid), '/T', '/F'], { windowsHide: true })
        } else {
          proc.kill('SIGTERM')
        }
      } catch {
        try {
          proc.kill()
        } catch {
          // ignore
        }
      }
    }
    return { ok: true }
  } catch (err) {
    return { ok: false, error: String(err) }
  }
})

function handleStdoutLine(line: string): void {
  const text = line.trim()
  if (!text) return

  if (text.startsWith('PROGRESS|')) {
    const parts = text.split('|')
    const percent = Number(parts[1] || 0)
    const phase = parts[2] || ''
    const detail = parts.slice(3).join('|')
    const paused = phase === 'Paused' || /Waiting for resume/i.test(detail)
    send('scan-progress', { percent, phase, detail, paused })
    return
  }
  if (text.startsWith('FINDING|')) {
    const parts = text.split('|')
    send('scan-finding', {
      severity: parts[1] || 'unknown',
      package: parts[2] || '',
      ecosystem: parts[3] || '',
      title: parts[4] || '',
      folder: parts[5] || '',
      hasFix: parts[6] === '1',
      count: Number(parts[7] || 0),
      isCache: parts[8] === '1',
    })
    return
  }
  if (text.startsWith('ECOSTATUS|')) {
    const parts = text.split('|')
    send('scan-progress', {
      eco: parts[1] || '',
      ecoCurrent: Number(parts[2] || 0),
      ecoTotal: Number(parts[3] || 0),
    })
    return
  }
  if (text.startsWith('LOG|')) {
    const parts = text.split('|')
    const kind = parts[1] || 'info'
    const msg = parts.slice(2).join('|')
    pushLog(kind, msg)
    return
  }
  if (text.startsWith('DONE|')) {
    const parts = text.split('|')
    pushLog('meta', `Finished: ${parts[1] || ''} ${parts[2] || ''}`)
    return
  }
  pushLog('stdout', text)
}

ipcMain.handle('start-scan', async (_event, options: ScanOptions = {}) => {
  if (scanProcess) {
    return { ok: false, error: 'A scan is already running.' }
  }

  const scriptPath = getScannerScriptPath()
  if (!fs.existsSync(scriptPath)) {
    return { ok: false, error: `Scanner script missing:\n${scriptPath}` }
  }

  const dataDir = getDataDir()
  const ps = resolvePowerShell()
  const args = [
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    scriptPath,
    '-GuiMode',
    '-NoOpen',
    '-OutputDir',
    dataDir,
  ]

  if (options.highOnly) args.push('-HighOnly')
  if (options.skipCache) args.push('-SkipCache')
  if (options.skipOsv) args.push('-SkipOsv')
  if (options.maxProjects) {
    args.push('-MaxProjectsPerEco')
    args.push(String(options.maxProjects))
  }
  if (options.driveOrPath) {
    args.push('-Drive')
    args.push(String(options.driveOrPath))
  }

  try {
    fs.writeFileSync(
      getProgressPath(),
      JSON.stringify({
        percent: 1,
        phase: 'Starting',
        detail: 'Launching scanner…',
        report: getReportPath(),
        paused: false,
      }),
      'utf8'
    )
    writeControlAction('run')
    // Clear previous findings so the live Report starts empty
    fs.writeFileSync(
      getFindingsPath(),
      JSON.stringify({ generated: new Date().toISOString(), platform: '', count: 0, findings: [] }),
      'utf8'
    )
    lastFindingsMtime = fs.statSync(getFindingsPath()).mtimeMs
    send('findings-updated', { mtimeMs: lastFindingsMtime, count: 0 })
  } catch {
    // ignore
  }

  recentLogs.length = 0
  pushLog('meta', 'Starting scan…')
  send('scan-progress', { percent: 1, phase: 'Starting', detail: 'Launching scanner…', paused: false })
  send('scan-status', { running: true, paused: false, stopped: false })
  userRequestedStop = false
  startProgressPolling()

  try {
    scanProcess = spawn(ps, args, {
      cwd: path.dirname(scriptPath),
      windowsHide: true,
      env: {
        ...process.env,
        PYTHONUNBUFFERED: '1',
      },
    })
  } catch (err) {
    scanProcess = null
    stopProgressPolling()
    send('scan-status', { running: false, error: String(err) })
    return { ok: false, error: String(err) }
  }

  let stdoutBuf = ''
  const flushStdout = (chunk: Buffer) => {
    stdoutBuf += chunk.toString('utf8')
    const lines = stdoutBuf.split(/\r?\n/)
    stdoutBuf = lines.pop() || ''
    for (const line of lines) handleStdoutLine(line)
  }

  scanProcess.stdout.on('data', flushStdout)
  scanProcess.stderr.on('data', (d: Buffer) => {
    const text = d.toString('utf8').trim()
    if (text) pushLog('stderr', text)
  })

  scanProcess.on('error', (err) => {
    pushLog('error', String(err))
    send('scan-status', { running: false, error: String(err) })
    stopProgressPolling()
    scanProcess = null
  })

  scanProcess.on('close', (code) => {
    if (stdoutBuf.trim()) handleStdoutLine(stdoutBuf)
    stdoutBuf = ''
    stopProgressPolling()

    const wasStopped = userRequestedStop
    userRequestedStop = false
    const reportPath = getReportPath()
    const reportExists = fs.existsSync(reportPath)
    const prog = readProgressFile() || {}

    if (wasStopped || String(prog.phase || '').toUpperCase() === 'STOPPED') {
      send('scan-progress', {
        percent: 0,
        phase: 'STOPPED',
        detail: 'Stopped by user',
        paused: false,
      })
      send('scan-status', { running: false, stopped: true, exitCode: code })
      scanProcess = null
      return
    }

    send('scan-progress', {
      percent: reportExists ? 100 : prog.percent || 0,
      phase: reportExists ? 'DONE' : prog.phase || 'Finished',
      detail: prog.detail || '',
      paused: false,
    })
    send('scan-status', {
      running: false,
      exitCode: code,
      reportExists,
      reportPath,
      reportUrl: reportExists ? pathToFileURL(reportPath).href : null,
    })
    scanProcess = null
  })

  return { ok: true, powerShell: ps, dataDir }
})
