const statusPill = document.getElementById('status-pill');
const platformLine = document.getElementById('platform-line');
const phaseText = document.getElementById('phase-text');
const detailText = document.getElementById('detail-text');
const pctText = document.getElementById('pct-text');
const barFill = document.getElementById('bar-fill');
const eventsEl = document.getElementById('events');
const reportFrame = document.getElementById('report-frame');
const reportEmpty = document.getElementById('report-empty');

const btnRun = document.getElementById('btn-run');
const btnStop = document.getElementById('btn-stop');
const btnPick = document.getElementById('btn-pick');
const btnClear = document.getElementById('btn-clear');
const btnReveal = document.getElementById('btn-reveal');
const btnRefreshReport = document.getElementById('btn-refresh-report');

let lastReportMtime = 0;
/** @type {'idle' | 'running' | 'paused'} */
let scanState = 'idle';

function setTab(name) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
}

function addEvent(type, text) {
  const li = document.createElement('li');
  li.className = type || 'info';
  const time = new Date().toLocaleTimeString();
  li.textContent = `${time}  ${text}`;
  eventsEl.prepend(li);
  while (eventsEl.children.length > 200) eventsEl.removeChild(eventsEl.lastChild);
}

function setProgress({ percent = 0, phase = '', detail = '' } = {}) {
  const pct = Math.max(0, Math.min(100, Number(percent) || 0));
  pctText.textContent = `${pct}%`;
  barFill.style.width = `${pct}%`;
  if (phase) phaseText.textContent = phase;
  if (typeof detail === 'string') detailText.textContent = detail || ' ';
}

function setControls(state) {
  scanState = state;
  btnRun.classList.remove('primary', 'warn', 'danger');
  statusPill.classList.remove('running', 'paused', 'done', 'error');

  if (state === 'running') {
    btnRun.textContent = 'Pause';
    btnRun.classList.add('warn');
    btnRun.disabled = false;
    btnStop.disabled = false;
    statusPill.textContent = 'Scanning';
    statusPill.classList.add('running');
    return;
  }

  if (state === 'paused') {
    btnRun.textContent = 'Resume';
    btnRun.classList.add('primary');
    btnRun.disabled = false;
    btnStop.disabled = false;
    statusPill.textContent = 'Paused';
    statusPill.classList.add('paused');
    return;
  }

  btnRun.textContent = 'Start';
  btnRun.classList.add('primary');
  btnRun.disabled = false;
  btnStop.disabled = true;
  statusPill.textContent = 'Idle';
}

function showReport(url) {
  if (!url) return;
  reportFrame.src = `${url}?t=${Date.now()}`;
  reportFrame.classList.add('visible');
  reportEmpty.classList.add('hidden');
}

async function loadReportIfAny() {
  const res = await window.scannerApi.getReportUrl();
  if (res.ok) showReport(res.url);
}

async function refreshInfo() {
  const info = await window.scannerApi.getAppInfo();
  platformLine.textContent = `${info.platformLabel} · data stored inside the app`;
  if (!info.scriptExists) addEvent('error', 'Scanner script missing from app package.');
  if (info.reportUrl) showReport(info.reportUrl);
  return info;
}

async function startScan() {
  setTab('scan');
  setControls('running');
  setProgress({ percent: 1, phase: 'Starting', detail: 'Launching scanner…' });
  addEvent('meta', 'Scan started');

  const options = {
    highOnly: document.getElementById('opt-high-only').checked,
    skipCache: document.getElementById('opt-skip-cache').checked,
    skipOsv: document.getElementById('opt-skip-osv').checked,
    maxProjects: Number(document.getElementById('opt-max').value || 80),
    driveOrPath: (document.getElementById('opt-path').value || '').trim(),
  };

  const res = await window.scannerApi.startScan(options);
  if (!res.ok) {
    setControls('idle');
    statusPill.textContent = 'Error';
    statusPill.classList.add('error');
    addEvent('error', res.error || 'Failed to start');
  }
}

async function pauseScan() {
  const res = await window.scannerApi.pauseScan();
  if (!res.ok) {
    addEvent('error', res.error || 'Could not pause');
    return;
  }
  setControls('paused');
  addEvent('warn', 'Pause requested');
}

async function resumeScan() {
  const res = await window.scannerApi.resumeScan();
  if (!res.ok) {
    addEvent('error', res.error || 'Could not resume');
    return;
  }
  setControls('running');
  addEvent('meta', 'Resume requested');
}

async function stopScan() {
  const res = await window.scannerApi.stopScan();
  if (!res.ok) addEvent('error', res.error || 'Could not stop');
}

document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => setTab(btn.dataset.tab));
});

btnClear.addEventListener('click', () => {
  eventsEl.innerHTML = '';
});

btnPick.addEventListener('click', async () => {
  const folder = await window.scannerApi.pickFolder();
  if (folder) document.getElementById('opt-path').value = folder;
});

btnReveal.addEventListener('click', async () => {
  await window.scannerApi.revealData();
});

btnRefreshReport.addEventListener('click', () => {
  loadReportIfAny();
});

btnRun.addEventListener('click', async () => {
  if (scanState === 'idle') {
    await startScan();
  } else if (scanState === 'running') {
    await pauseScan();
  } else if (scanState === 'paused') {
    await resumeScan();
  }
});

btnStop.addEventListener('click', async () => {
  if (scanState === 'idle') return;
  await stopScan();
});

window.scannerApi.onScanLog((payload) => {
  addEvent(payload.type || 'info', payload.text || '');
});

window.scannerApi.onScanProgress((payload) => {
  setProgress(payload || {});
  if (payload?.paused === true && scanState === 'running') {
    setControls('paused');
  } else if (payload?.paused === false && scanState === 'paused' && payload?.phase !== 'Paused') {
    setControls('running');
  }
});

window.scannerApi.onReportUpdated((payload) => {
  if (!payload?.url) return;
  if (payload.mtimeMs && payload.mtimeMs === lastReportMtime) return;
  lastReportMtime = payload.mtimeMs || Date.now();
  if (document.getElementById('view-report').classList.contains('active') || scanState === 'idle') {
    showReport(payload.url);
  }
});

window.scannerApi.onScanStatus((payload) => {
  if (payload.running) {
    setControls(payload.paused ? 'paused' : 'running');
    return;
  }

  setControls('idle');

  if (payload.stopped) {
    statusPill.textContent = 'Stopped';
    statusPill.classList.add('error');
    addEvent('warn', 'Scan stopped');
    return;
  }

  if (payload.error) {
    statusPill.textContent = 'Error';
    statusPill.classList.add('error');
    addEvent('error', payload.error);
    return;
  }

  if (payload.reportExists || payload.exitCode === 0) {
    statusPill.textContent = 'Finished';
    statusPill.classList.add('done');
    setProgress({ percent: 100, phase: 'DONE', detail: 'Scan finished' });
    addEvent('done', 'Scan finished — opening report');
    if (payload.reportUrl) showReport(payload.reportUrl);
    setTab('report');
  } else {
    statusPill.textContent = `Exit ${payload.exitCode}`;
    statusPill.classList.add('error');
    addEvent('error', `Scanner exited with code ${payload.exitCode}`);
  }
});

setControls('idle');
refreshInfo().catch((err) => addEvent('error', String(err)));
