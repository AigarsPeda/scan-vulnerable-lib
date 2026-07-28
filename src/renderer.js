const statusPill = document.getElementById('status-pill');
const phaseText = document.getElementById('phase-text');
const detailText = document.getElementById('detail-text');
const pctText = document.getElementById('pct-text');
const barFill = document.getElementById('bar-fill');
const eventsEl = document.getElementById('events');
const liveFindingsEl = document.getElementById('live-findings');
const findingsCountEl = document.getElementById('findings-count');
const findingsEmptyEl = document.getElementById('findings-empty');
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
let findingCount = 0;

function setTab(name) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
  if (name === 'report') loadReportIfAny();
}

function addEvent(type, text) {
  const li = document.createElement('li');
  li.className = type || 'info';
  const time = new Date().toLocaleTimeString();
  li.textContent = `${time}  ${text}`;
  eventsEl.prepend(li);
  while (eventsEl.children.length > 200) eventsEl.removeChild(eventsEl.lastChild);
}

function clearFindings() {
  findingCount = 0;
  liveFindingsEl.innerHTML = '';
  findingsCountEl.textContent = '0';
  findingsEmptyEl.classList.remove('hidden');
}

function addFinding(payload = {}) {
  const sev = String(payload.severity || 'unknown').toLowerCase();
  const pkg = payload.package || 'unknown package';
  const title = payload.title || '';
  const folder = payload.folder || '';
  const eco = payload.ecosystem || '';

  const li = document.createElement('li');
  const sevEl = document.createElement('span');
  sevEl.className = `sev ${sev}`;
  sevEl.textContent = sev;

  const body = document.createElement('div');
  const pkgEl = document.createElement('div');
  pkgEl.className = 'pkg';
  pkgEl.textContent = pkg + (eco ? ` (${eco})` : '');

  const meta = document.createElement('div');
  meta.className = 'meta';
  meta.textContent = [title, folder].filter(Boolean).join(' · ');

  body.appendChild(pkgEl);
  if (meta.textContent) body.appendChild(meta);
  li.appendChild(sevEl);
  li.appendChild(body);
  liveFindingsEl.prepend(li);

  while (liveFindingsEl.children.length > 300) {
    liveFindingsEl.removeChild(liveFindingsEl.lastChild);
  }

  findingCount = Number(payload.count) > 0 ? Number(payload.count) : findingCount + 1;
  findingsCountEl.textContent = String(findingCount);
  findingsEmptyEl.classList.add('hidden');
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
  if (!info.scriptExists) addEvent('error', 'Scanner script missing from app package.');
  if (info.reportUrl) showReport(info.reportUrl);
  return info;
}

async function startScan() {
  setTab('scan');
  clearFindings();
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

document.querySelectorAll('[data-export]').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const format = btn.getAttribute('data-export');
    const res = await window.scannerApi.exportReport(format);
    if (res?.canceled) return;
    if (!res?.ok) {
      addEvent('error', res?.error || `Export ${format} failed`);
      return;
    }
    addEvent('done', `Exported ${String(format).toUpperCase()}: ${res.path}`);
  });
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
  if (typeof payload?.findingCount === 'number' && payload.findingCount > findingCount) {
    findingsCountEl.textContent = String(payload.findingCount);
  }
  if (payload?.paused === true && scanState === 'running') {
    setControls('paused');
  } else if (payload?.paused === false && scanState === 'paused' && payload?.phase !== 'Paused') {
    setControls('running');
  }
});

window.scannerApi.onScanFinding((payload) => {
  addFinding(payload || {});
});

window.scannerApi.onReportUpdated((payload) => {
  if (!payload?.url) return;
  if (payload.mtimeMs && payload.mtimeMs === lastReportMtime) return;
  lastReportMtime = payload.mtimeMs || Date.now();
  // Live-reload report while viewing Report tab (Electron, not browser meta-refresh)
  if (document.getElementById('view-report').classList.contains('active')) {
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
