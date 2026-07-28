const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('scannerApi', {
  getAppInfo: () => ipcRenderer.invoke('get-app-info'),
  getReportUrl: () => ipcRenderer.invoke('get-report-url'),
  exportReport: (format) => ipcRenderer.invoke('export-report', format),
  startScan: (options) => ipcRenderer.invoke('start-scan', options),
  pauseScan: () => ipcRenderer.invoke('pause-scan'),
  resumeScan: () => ipcRenderer.invoke('resume-scan'),
  stopScan: () => ipcRenderer.invoke('stop-scan'),
  revealData: () => ipcRenderer.invoke('reveal-data'),
  pickFolder: () => ipcRenderer.invoke('pick-folder'),
  onScanLog: (cb) => {
    const listener = (_e, payload) => cb(payload);
    ipcRenderer.on('scan-log', listener);
    return () => ipcRenderer.removeListener('scan-log', listener);
  },
  onScanStatus: (cb) => {
    const listener = (_e, payload) => cb(payload);
    ipcRenderer.on('scan-status', listener);
    return () => ipcRenderer.removeListener('scan-status', listener);
  },
  onScanProgress: (cb) => {
    const listener = (_e, payload) => cb(payload);
    ipcRenderer.on('scan-progress', listener);
    return () => ipcRenderer.removeListener('scan-progress', listener);
  },
  onScanFinding: (cb) => {
    const listener = (_e, payload) => cb(payload);
    ipcRenderer.on('scan-finding', listener);
    return () => ipcRenderer.removeListener('scan-finding', listener);
  },
  onReportUpdated: (cb) => {
    const listener = (_e, payload) => cb(payload);
    ipcRenderer.on('report-updated', listener);
    return () => ipcRenderer.removeListener('report-updated', listener);
  },
});
