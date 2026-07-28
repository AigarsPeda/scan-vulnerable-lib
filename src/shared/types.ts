export type ScanState = 'idle' | 'running' | 'paused'

export type ExportFormat = 'json' | 'txt' | 'csv' | 'md' | 'html'

export type TabName = 'scan' | 'report'

export interface ScanOptions {
  highOnly?: boolean
  skipCache?: boolean
  skipOsv?: boolean
  maxProjects?: number
  driveOrPath?: string
}

export interface AppInfo {
  platform: string
  platformLabel: string
  dataDir: string
  reportPath: string
  reportUrl: string | null
  scriptPath: string
  scriptExists: boolean
  reportExists: boolean
  powerShell: string
  home: string
}

export interface OkResult {
  ok: boolean
  error?: string
  canceled?: boolean
  path?: string
  format?: string
  powerShell?: string
  dataDir?: string
}

export interface ReportUrlResult {
  ok: boolean
  error?: string
  path?: string
  url?: string
}

export interface ScanProgress {
  percent?: number
  phase?: string
  detail?: string
  paused?: boolean
  findingCount?: number
  report?: string
  eco?: string
  ecoCurrent?: number
  ecoTotal?: number
}

export interface ScanFinding {
  severity?: string
  package?: string
  ecosystem?: string
  title?: string
  folder?: string
  hasFix?: boolean
  count?: number
  isCache?: boolean
}

export interface ReportFinding {
  id: string
  severity: string
  ecosystem: string
  packageName: string
  version: string
  title: string
  path: string
  fix: string
  hasFix: boolean
  advisory: string
  isCache: boolean
  source: string
}

export interface FindingsResult {
  ok: boolean
  error?: string
  count?: number
  generated?: string
  findings?: ReportFinding[]
  mtimeMs?: number
}

export interface ScanLog {
  type?: string
  text?: string
}

export interface ScanStatus {
  running?: boolean
  paused?: boolean
  stopped?: boolean
  error?: string
  exitCode?: number | null
  reportExists?: boolean
  reportPath?: string
  reportUrl?: string | null
}

export interface ReportUpdated {
  path?: string
  mtimeMs?: number
  url?: string
}

export interface FindingsUpdated {
  mtimeMs?: number
  count?: number
}

export interface StatusEvent {
  id: number
  type: string
  text: string
  time: string
}

export interface LiveFinding {
  id: number
  severity: string
  package: string
  ecosystem: string
  title: string
  folder: string
  hasFix: boolean
}

export interface ScanRuntime {
  running: boolean
  paused: boolean
  progress: ScanProgress | null
  reportUrl: string | null
  reportMtimeMs: number
  findingCount: number
  recentLogs: ScanLog[]
  recentFindings: ScanFinding[]
}

export interface ScannerApi {
  getAppInfo: () => Promise<AppInfo>
  getReportUrl: () => Promise<ReportUrlResult>
  getFindings: () => Promise<FindingsResult>
  getScanRuntime: () => Promise<ScanRuntime>
  exportReport: (format: ExportFormat) => Promise<OkResult>
  startScan: (options: ScanOptions) => Promise<OkResult>
  pauseScan: () => Promise<OkResult>
  resumeScan: () => Promise<OkResult>
  stopScan: () => Promise<OkResult>
  revealData: () => Promise<OkResult>
  openPath: (targetPath: string) => Promise<OkResult>
  copyText: (text: string) => Promise<OkResult>
  pickFolder: () => Promise<string | null>
  onScanLog: (cb: (payload: ScanLog) => void) => () => void
  onScanStatus: (cb: (payload: ScanStatus) => void) => () => void
  onScanProgress: (cb: (payload: ScanProgress) => void) => () => void
  onScanFinding: (cb: (payload: ScanFinding) => void) => () => void
  onReportUpdated: (cb: (payload: ReportUpdated) => void) => () => void
  onFindingsUpdated: (cb: (payload: FindingsUpdated) => void) => () => void
}

declare global {
  interface Window {
    scannerApi: ScannerApi
  }
}

export {}
