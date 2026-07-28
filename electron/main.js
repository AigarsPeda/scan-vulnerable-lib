const { app, BrowserWindow, ipcMain, shell, dialog, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const { pathToFileURL } = require('url');

let mainWindow = null;
let scanProcess = null;
let progressTimer = null;
let userRequestedStop = false;

function getDataDir() {
  const dir = path.join(app.getPath('userData'), 'scan-data');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function getReportPath() {
  return path.join(getDataDir(), 'vulnerable-libs-report.html');
}

function getProgressPath() {
  return path.join(getDataDir(), 'scan-progress.json');
}

function getControlPath() {
  return path.join(getDataDir(), 'scan-control.json');
}

function writeControlAction(action) {
  const payload = JSON.stringify({ action, updated: new Date().toISOString() });
  fs.writeFileSync(getControlPath(), payload, 'utf8');
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

function send(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

function readProgressFile() {
  try {
    const p = getProgressPath();
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

function stopProgressPolling() {
  if (progressTimer) {
    clearInterval(progressTimer);
    progressTimer = null;
  }
}

function startProgressPolling() {
  stopProgressPolling();
  progressTimer = setInterval(() => {
    const prog = readProgressFile();
    if (prog) send('scan-progress', prog);
    const report = getReportPath();
    if (fs.existsSync(report)) {
      try {
        const st = fs.statSync(report);
        send('report-updated', {
          path: report,
          mtimeMs: st.mtimeMs,
          url: pathToFileURL(report).href,
        });
      } catch {
        // ignore
      }
    }
  }, 400);
}

function createWindow() {
  const iconPath = path.join(__dirname, '..', 'assets', 'icon.png');
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 960,
    minHeight: 640,
    title: 'Vulnerable Library Scanner',
    backgroundColor: '#0b0b0b',
    icon: iconPath,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webviewTag: true,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'src', 'index.html'));
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  // Hide default File/Edit/View/Window/Help menu — the app UI has its own controls
  Menu.setApplicationMenu(null);
  getDataDir();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  stopProgressPolling();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  stopProgressPolling();
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
  const reportPath = getReportPath();
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
  };
});

ipcMain.handle('get-report-url', async () => {
  const reportPath = getReportPath();
  if (!fs.existsSync(reportPath)) return { ok: false, error: 'No report yet.' };
  return { ok: true, path: reportPath, url: pathToFileURL(reportPath).href };
});

ipcMain.handle('reveal-data', async () => {
  const dir = getDataDir();
  shell.openPath(dir);
  return { ok: true, path: dir };
});

ipcMain.handle('pick-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Choose a folder to scan',
  });
  if (result.canceled || !result.filePaths.length) return null;
  return result.filePaths[0];
});

ipcMain.handle('pause-scan', async () => {
  if (!scanProcess) return { ok: false, error: 'No scan is running.' };
  try {
    writeControlAction('pause');
    send('scan-status', { running: true, paused: true });
    send('scan-log', { type: 'warn', text: 'Pause requested — waiting for current step…' });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
});

ipcMain.handle('resume-scan', async () => {
  if (!scanProcess) return { ok: false, error: 'No scan is running.' };
  try {
    writeControlAction('run');
    send('scan-status', { running: true, paused: false });
    send('scan-log', { type: 'meta', text: 'Resume requested' });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
});

ipcMain.handle('stop-scan', async () => {
  if (!scanProcess) return { ok: false, error: 'No scan is running.' };
  try {
    userRequestedStop = true;
    writeControlAction('stop');
    send('scan-log', { type: 'warn', text: 'Stop requested' });

    const proc = scanProcess;
    // Give cooperative stop a moment, then force-kill if still alive
    await new Promise((resolve) => setTimeout(resolve, 900));
    if (scanProcess === proc && proc && !proc.killed) {
      try {
        if (process.platform === 'win32') {
          spawn('taskkill', ['/pid', String(proc.pid), '/T', '/F'], { windowsHide: true });
        } else {
          proc.kill('SIGTERM');
        }
      } catch {
        try {
          proc.kill();
        } catch {
          // ignore
        }
      }
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
});

function handleStdoutLine(line) {
  const text = line.trim();
  if (!text) return;

  if (text.startsWith('PROGRESS|')) {
    const parts = text.split('|');
    const percent = Number(parts[1] || 0);
    const phase = parts[2] || '';
    const detail = parts.slice(3).join('|');
    const paused = phase === 'Paused' || /Waiting for resume/i.test(detail);
    send('scan-progress', { percent, phase, detail, paused });
    return;
  }
  if (text.startsWith('FINDING|')) {
    const parts = text.split('|');
    send('scan-finding', {
      severity: parts[1] || 'unknown',
      package: parts[2] || '',
      ecosystem: parts[3] || '',
      title: parts[4] || '',
      folder: parts[5] || '',
      hasFix: parts[6] === '1',
      count: Number(parts[7] || 0),
    });
    return;
  }
  if (text.startsWith('LOG|')) {
    const parts = text.split('|');
    const kind = parts[1] || 'info';
    const msg = parts.slice(2).join('|');
    send('scan-log', { type: kind, text: msg });
    return;
  }
  if (text.startsWith('DONE|')) {
    const parts = text.split('|');
    send('scan-log', { type: 'meta', text: `Finished: ${parts[1] || ''} ${parts[2] || ''}` });
    return;
  }
  send('scan-log', { type: 'stdout', text });
}

ipcMain.handle('start-scan', async (_event, options = {}) => {
  if (scanProcess) {
    return { ok: false, error: 'A scan is already running.' };
  }

  const scriptPath = getScannerScriptPath();
  if (!fs.existsSync(scriptPath)) {
    return { ok: false, error: `Scanner script missing:\n${scriptPath}` };
  }

  const dataDir = getDataDir();
  const ps = resolvePowerShell();
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
  ];

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

  // Reset progress + control files
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
    );
    writeControlAction('run');
  } catch {
    // ignore
  }

  send('scan-log', { type: 'meta', text: 'Starting scan…' });
  send('scan-progress', { percent: 1, phase: 'Starting', detail: 'Launching scanner…', paused: false });
  send('scan-status', { running: true, paused: false, stopped: false });
  userRequestedStop = false;
  startProgressPolling();

  try {
    scanProcess = spawn(ps, args, {
      cwd: path.dirname(scriptPath),
      windowsHide: true,
      env: {
        ...process.env,
        PYTHONUNBUFFERED: '1',
      },
    });
  } catch (err) {
    scanProcess = null;
    stopProgressPolling();
    send('scan-status', { running: false, error: String(err) });
    return { ok: false, error: String(err) };
  }

  let stdoutBuf = '';
  const flushStdout = (chunk) => {
    stdoutBuf += chunk.toString('utf8');
    const lines = stdoutBuf.split(/\r?\n/);
    stdoutBuf = lines.pop() || '';
    for (const line of lines) handleStdoutLine(line);
  };

  scanProcess.stdout.on('data', flushStdout);
  scanProcess.stderr.on('data', (d) => {
    const text = d.toString('utf8').trim();
    if (text) send('scan-log', { type: 'stderr', text });
  });

  scanProcess.on('error', (err) => {
    send('scan-log', { type: 'error', text: String(err) });
    send('scan-status', { running: false, error: String(err) });
    stopProgressPolling();
    scanProcess = null;
  });

  scanProcess.on('close', (code) => {
    if (stdoutBuf.trim()) handleStdoutLine(stdoutBuf);
    stdoutBuf = '';
    stopProgressPolling();

    const wasStopped = userRequestedStop;
    userRequestedStop = false;
    const reportPath = getReportPath();
    const reportExists = fs.existsSync(reportPath);
    const prog = readProgressFile() || {};

    if (wasStopped || String(prog.phase || '').toUpperCase() === 'STOPPED') {
      send('scan-progress', {
        percent: prog.percent || 0,
        phase: 'STOPPED',
        detail: 'Stopped by user',
        paused: false,
      });
      send('scan-status', { running: false, stopped: true, exitCode: code });
      scanProcess = null;
      return;
    }

    send('scan-progress', {
      percent: reportExists ? 100 : prog.percent || 0,
      phase: reportExists ? 'DONE' : prog.phase || 'Finished',
      detail: prog.detail || '',
      paused: false,
    });
    send('scan-status', {
      running: false,
      exitCode: code,
      reportExists,
      reportPath,
      reportUrl: reportExists ? pathToFileURL(reportPath).href : null,
    });
    scanProcess = null;
  });

  return { ok: true, powerShell: ps, dataDir };
});
