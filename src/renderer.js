const logEl = document.getElementById('log');
const statusPill = document.getElementById('status-pill');
const platformLine = document.getElementById('platform-line');
const pathScript = document.getElementById('path-script');
const pathReport = document.getElementById('path-report');
const pathPs = document.getElementById('path-ps');

const btnStart = document.getElementById('btn-start');
const btnStop = document.getElementById('btn-stop');
const btnOpen = document.getElementById('btn-open');
const btnReveal = document.getElementById('btn-reveal');
const btnPick = document.getElementById('btn-pick');
const btnClear = document.getElementById('btn-clear');

function appendLog(type, text) {
  const span = document.createElement('span');
  span.className = type || 'stdout';
  span.textContent = text.endsWith('\n') ? text : `${text}\n`;
  logEl.appendChild(span);
  logEl.scrollTop = logEl.scrollHeight;
}

function setRunning(running) {
  btnStart.disabled = running;
  btnStop.disabled = !running;
  statusPill.classList.remove('running', 'done', 'error');
  if (running) {
    statusPill.textContent = 'Scanning';
    statusPill.classList.add('running');
  }
}

function setReportAvailable(available) {
  btnOpen.disabled = !available;
  btnReveal.disabled = !available;
}

async function refreshInfo() {
  const info = await window.scannerApi.getAppInfo();
  platformLine.textContent = `${info.platformLabel} · report opens from your Desktop`;
  pathScript.textContent = info.scriptPath + (info.scriptExists ? '' : ' (missing)');
  pathReport.textContent = info.reportPath;
  pathPs.textContent = info.powerShell;
  setReportAvailable(info.reportExists);
  if (!info.scriptExists) {
    appendLog('error', 'Scanner script not found. Expected scripts/scan-vulnerable-libs.ps1');
  }
  return info;
}

btnClear.addEventListener('click', () => {
  logEl.textContent = '';
});

btnPick.addEventListener('click', async () => {
  const folder = await window.scannerApi.pickFolder();
  if (folder) document.getElementById('opt-path').value = folder;
});

btnOpen.addEventListener('click', async () => {
  const res = await window.scannerApi.openReport();
  if (!res.ok) appendLog('error', res.error || 'Could not open report');
});

btnReveal.addEventListener('click', async () => {
  const res = await window.scannerApi.revealReport();
  if (!res.ok) appendLog('error', res.error || 'Could not reveal report');
});

btnStop.addEventListener('click', async () => {
  const res = await window.scannerApi.stopScan();
  if (!res.ok) appendLog('error', res.error || 'Could not stop scan');
});

btnStart.addEventListener('click', async () => {
  const options = {
    highOnly: document.getElementById('opt-high-only').checked,
    skipCache: document.getElementById('opt-skip-cache').checked,
    skipOsv: document.getElementById('opt-skip-osv').checked,
    maxProjects: Number(document.getElementById('opt-max').value || 80),
    driveOrPath: (document.getElementById('opt-path').value || '').trim(),
  };

  setRunning(true);
  appendLog('meta', 'Starting scan…');
  const res = await window.scannerApi.startScan(options);
  if (!res.ok) {
    setRunning(false);
    statusPill.textContent = 'Error';
    statusPill.classList.add('error');
    appendLog('error', res.error || 'Failed to start scan');
  }
});

window.scannerApi.onScanLog((payload) => {
  appendLog(payload.type || 'stdout', payload.text || '');
});

window.scannerApi.onScanStatus((payload) => {
  if (payload.running) {
    setRunning(true);
    return;
  }

  setRunning(false);
  setReportAvailable(!!payload.reportExists);

  if (payload.stopped) {
    statusPill.textContent = 'Stopped';
    statusPill.classList.add('error');
    appendLog('meta', 'Scan stopped by user.');
    return;
  }

  if (payload.error) {
    statusPill.textContent = 'Error';
    statusPill.classList.add('error');
    appendLog('error', payload.error);
    return;
  }

  if (payload.exitCode === 0 || payload.reportExists) {
    statusPill.textContent = 'Finished';
    statusPill.classList.add('done');
    appendLog('meta', 'Scan finished. Use Open HTML report to view findings.');
  } else {
    statusPill.textContent = `Exit ${payload.exitCode}`;
    statusPill.classList.add('error');
  }
});

refreshInfo().catch((err) => appendLog('error', String(err)));
