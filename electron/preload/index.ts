import { contextBridge, ipcRenderer } from 'electron'
import type {
  ExportFormat,
  FindingsUpdated,
  ScanFinding,
  ScanLog,
  ScanOptions,
  ScanProgress,
  ScanStatus,
  ReportUpdated,
  ScannerApi,
} from '../../src/shared/types'

function subscribe<T>(channel: string, cb: (payload: T) => void): () => void {
  const listener = (_e: Electron.IpcRendererEvent, payload: T) => cb(payload)
  ipcRenderer.on(channel, listener)
  return () => ipcRenderer.removeListener(channel, listener)
}

const api: ScannerApi = {
  getAppInfo: () => ipcRenderer.invoke('get-app-info'),
  getReportUrl: () => ipcRenderer.invoke('get-report-url'),
  getFindings: () => ipcRenderer.invoke('get-findings'),
  getScanRuntime: () => ipcRenderer.invoke('get-scan-runtime'),
  exportReport: (format: ExportFormat) => ipcRenderer.invoke('export-report', format),
  startScan: (options: ScanOptions) => ipcRenderer.invoke('start-scan', options),
  pauseScan: () => ipcRenderer.invoke('pause-scan'),
  resumeScan: () => ipcRenderer.invoke('resume-scan'),
  stopScan: () => ipcRenderer.invoke('stop-scan'),
  revealData: () => ipcRenderer.invoke('reveal-data'),
  openPath: (targetPath) => ipcRenderer.invoke('open-path', targetPath),
  copyText: (text) => ipcRenderer.invoke('copy-text', text),
  pickFolder: () => ipcRenderer.invoke('pick-folder'),
  onScanLog: (cb) => subscribe<ScanLog>('scan-log', cb),
  onScanStatus: (cb) => subscribe<ScanStatus>('scan-status', cb),
  onScanProgress: (cb) => subscribe<ScanProgress>('scan-progress', cb),
  onScanFinding: (cb) => subscribe<ScanFinding>('scan-finding', cb),
  onReportUpdated: (cb) => subscribe<ReportUpdated>('report-updated', cb),
  onFindingsUpdated: (cb) => subscribe<FindingsUpdated>('findings-updated', cb),
}

contextBridge.exposeInMainWorld('scannerApi', api)
