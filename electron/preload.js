const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('scannerApi', {
  getAppInfo: () => ipcRenderer.invoke('get-app-info'),
  startScan: (options) => ipcRenderer.invoke('start-scan', options),
  stopScan: () => ipcRenderer.invoke('stop-scan'),
  openReport: () => ipcRenderer.invoke('open-report'),
  revealReport: () => ipcRenderer.invoke('reveal-report'),
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
});
