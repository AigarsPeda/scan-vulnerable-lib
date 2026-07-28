import fs from 'fs'
import path from 'path'

export type ProgressState = {
  percent: number
  phase: string
  detail: string
  paused: boolean
  reportPath: string
  findingsCount: number
  gui: boolean
  controlPath: string
  progressPath: string
  stopped: boolean
}

let lastPaint = 0

export function createProgress(
  outputDir: string,
  reportPath: string,
  gui: boolean
): ProgressState {
  return {
    percent: 0,
    phase: 'Starting',
    detail: '',
    paused: false,
    reportPath,
    findingsCount: 0,
    gui,
    controlPath: path.join(outputDir, 'scan-control.json'),
    progressPath: path.join(outputDir, 'scan-progress.json'),
    stopped: false,
  }
}

function readControl(state: ProgressState): 'run' | 'pause' | 'stop' {
  if (!state.gui) return 'run'
  try {
    if (!fs.existsSync(state.controlPath)) return 'run'
    const raw = JSON.parse(fs.readFileSync(state.controlPath, 'utf8')) as { action?: string }
    if (raw.action === 'pause' || raw.action === 'stop' || raw.action === 'run') return raw.action
  } catch {
    /* ignore */
  }
  return 'run'
}

function writeProgressFile(state: ProgressState): void {
  try {
    fs.writeFileSync(
      state.progressPath,
      JSON.stringify({
        percent: state.percent,
        phase: state.phase,
        detail: state.detail,
        report: state.reportPath,
        paused: state.paused,
        findingCount: state.findingsCount,
        updated: new Date().toISOString(),
      }),
      'utf8'
    )
  } catch {
    /* ignore */
  }
}

export function emitLog(kind: string, message: string, gui: boolean): void {
  if (gui) {
    console.log(`LOG|${kind}|${message.replace(/\|/g, '/')}`)
  } else {
    console.log(`[${kind}] ${message}`)
  }
}

export async function waitIfPaused(state: ProgressState): Promise<void> {
  if (!state.gui) return
  while (true) {
    const action = readControl(state)
    if (action === 'stop') {
      state.stopped = true
      state.phase = 'STOPPED'
      state.detail = 'Stopped by user'
      writeProgressFile(state)
      emitLog('warn', 'Stop requested', true)
      console.log(`DONE|STOPPED|${state.reportPath}`)
      return
    }
    if (action !== 'pause') {
      if (state.paused) {
        state.paused = false
        emitLog('meta', 'Scan resumed', true)
        console.log(
          `PROGRESS|${state.percent}|${state.phase.replace(/\|/g, '/')}|Resumed`
        )
        writeProgressFile(state)
      }
      return
    }
    state.paused = true
    state.phase = 'Paused'
    state.detail = 'Scan paused - press Resume to continue'
    writeProgressFile(state)
    console.log(`PROGRESS|${state.percent}|Paused|Waiting for resume...`)
    await sleep(400)
  }
}

export async function showProgress(
  state: ProgressState,
  percent: number,
  phase: string,
  detail: string,
  force = false
): Promise<void> {
  await waitIfPaused(state)
  if (state.stopped) return

  const now = Date.now()
  const minMs = state.gui ? 200 : 80
  if (!force && now - lastPaint < minMs && percent < 99) return
  lastPaint = now

  state.phase = phase
  state.detail = detail
  state.percent = Math.min(99, Math.max(0, Math.round(percent * 10) / 10))

  if (state.gui) {
    const safePhase = phase.replace(/\|/g, '/')
    const safeDetail = detail.replace(/[\r\n|]/g, ' ')
    console.log(`PROGRESS|${state.percent}|${safePhase}|${safeDetail}`)
    writeProgressFile(state)
  } else {
    process.stdout.write(`\r[${state.percent}%] ${phase} | ${detail}`.slice(0, 120))
  }
}

export function finishProgress(state: ProgressState, phase: string, detail: string): void {
  state.percent = 100
  state.phase = phase
  state.detail = detail
  writeProgressFile(state)
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

export function emitEcoStatus(eco: string, current: number, total: number, gui: boolean): void {
  if (!gui) return
  console.log(`ECOSTATUS|${eco}|${current}|${total}`)
}
