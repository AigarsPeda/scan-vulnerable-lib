const { app, BrowserWindow, ipcMain, shell, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');

let mainWindow = null;
let scanProcess = null;

function getDesktopDir() {
  return app.getPath('desktop');
}

function getReportPath() {
  return path.join(getDesktopDir(), 'vulnerable-libs-report.html');
}

function getScannerScriptPath() {
  return path.join(__dirname, '..', 'scripts', 'scan-vulnerable-libs.ps1');
}

function resolvePowerShell() {
  if (process.platform === 'win32') {
    const candidates = [
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'PowerShell', '7', 'pwsh.exe'),
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'PowerShell', '7-preview', 'pwsh.exe'),
      path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
    return 'powershell.exe';
  }

  const candidates = ['/opt/homebrew/bin/pwsh', '/usr/local/bin/pwsh', '/usr/bin/pwsh'];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return 'pwsh';
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 860,
    minHeight: 560,
    title: 'Vulnerable Library Scanner',
    backgroundColor: '#0b1220',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'src', 'index.html'));
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function send(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (scanProcess && !scanProcess.killed) {
    try {
      scanProcess.kill();
    } catch {
      // ignore
    }
  }
});

ipcMain.handle('get-app-info', async () => {
  const scriptPath = getScannerScriptPath();
  return {
    platform: process.platform,
    platformLabel:
      process.platform === 'darwin' ? 'macOS' : process.platform === 'win32' ? 'Windows' : process.platform,
    desktop: getDesktopDir(),
    reportPath: getReportPath(),
    scriptPath,
    scriptExists: fs.existsSync(scriptPath),
    reportExists: fs.existsSync(getReportPath()),
    powerShell: resolvePowerShell(),
    home: os.homedir(),
  };
});

ipcMain.handle('open-report', async () => {
  const report = getReportPath();
  if (!fs.existsSync(report)) {
    return { ok: false, error: 'Report not found yet. Run a scan first.' };
  }
  await shell.openPath(report);
  return { ok: true, path: report };
});

ipcMain.handle('reveal-report', async () => {
  const report = getReportPath();
  if (!fs.existsSync(report)) {
    return { ok: false, error: 'Report not found yet.' };
  }
  shell.showItemInFolder(report);
  return { ok: true, path: report };
});

ipcMain.handle('pick-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Choose a folder to scan',
  });
  if (result.canceled || !result.filePaths.length) return null;
  return result.filePaths[0];
});

ipcMain.handle('stop-scan', async () => {
  if (!scanProcess) return { ok: false, error: 'No scan is running.' };
  try {
    scanProcess.kill();
    scanProcess = null;
    send('scan-status', { running: false, stopped: true });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
});

ipcMain.handle('start-scan', async (_event, options = {}) => {
  if (scanProcess) {
    return { ok: false, error: 'A scan is already running.' };
  }

  const scriptPath = getScannerScriptPath();
  if (!fs.existsSync(scriptPath)) {
    return { ok: false, error: `Scanner script missing:\n${scriptPath}` };
  }

  const ps = resolvePowerShell();
  const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath];

  if (options.highOnly) args.push('-HighOnly');
  if (options.skipCache) args.push('-SkipCache');
  if (options.skipOsv) args.push('-SkipOsv');
  if (options.maxProjects) {
    args.push('-MaxProjectsPerEco');
    args.push(String(options.maxProjects));
  }
  if (options.driveOrPath) {
    args.push('-Drive');
    args.push(String(options.driveOrPath));
  }

  send('scan-log', { type: 'meta', text: `Starting: ${ps} ${args.join(' ')}` });
  send('scan-status', { running: true, stopped: false });

  try {
    scanProcess = spawn(ps, args, {
      cwd: path.dirname(scriptPath),
      windowsHide: true,
      env: { ...process.env },
    });
  } catch (err) {
    scanProcess = null;
    send('scan-status', { running: false, error: String(err) });
    return { ok: false, error: String(err) };
  }

  const onChunk = (buf, type) => {
    const text = buf.toString('utf8');
    if (!text.trim()) return;
    send('scan-log', { type, text });
  };

  scanProcess.stdout.on('data', (d) => onChunk(d, 'stdout'));
  scanProcess.stderr.on('data', (d) => onChunk(d, 'stderr'));

  scanProcess.on('error', (err) => {
    send('scan-log', { type: 'error', text: String(err) });
    send('scan-status', { running: false, error: String(err) });
    scanProcess = null;
  });

  scanProcess.on('close', (code) => {
    const reportPath = getReportPath();
    const reportExists = fs.existsSync(reportPath);
    send('scan-log', {
      type: 'meta',
      text: `Scan process exited with code ${code}${reportExists ? `\nReport: ${reportPath}` : ''}`,
    });
    send('scan-status', {
      running: false,
      exitCode: code,
      reportExists,
      reportPath,
    });
    scanProcess = null;
  });

  return { ok: true, powerShell: ps, args };
});
