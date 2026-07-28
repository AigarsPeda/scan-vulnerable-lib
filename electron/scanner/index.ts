import fs from 'fs'
import path from 'path'
import { spawn } from 'child_process'
import { parseArgs, resolveOutputDir, osLabel } from './types'
import { augmentPath, defaultRoots } from './platform'
import { FindingsStore } from './findings'
import { OsvClient } from './osv'
import {
  createProgress,
  emitLog,
  finishProgress,
  showProgress,
} from './progress'
import { walkDetect, groupProjects } from './walk'
import { auditAll } from './audit'
import { scanCaches } from './cache'
import { writeHtmlReport } from './report'

async function main(): Promise<void> {
  augmentPath()
  const args = parseArgs(process.argv.slice(2))
  const outputDir = resolveOutputDir(args)
  const reportPath = path.join(outputDir, 'vulnerable-libs-report.html')
  const findingsPath = path.join(outputDir, 'findings.json')
  const controlPath = path.join(outputDir, 'scan-control.json')
  const platform = osLabel()

  if (args.gui) {
    try {
      fs.writeFileSync(controlPath, JSON.stringify({ action: 'run' }), 'utf8')
    } catch {
      /* ignore */
    }
  }

  const state = createProgress(outputDir, reportPath, args.gui)
  const findings = new FindingsStore(findingsPath, platform, args.highOnly, args.gui)
  findings.clearFile()
  const osv = new OsvClient(args.skipOsv, args.gui)

  const roots = defaultRoots(args.roots)
  emitLog('meta', `Scanner runtime: Node ${process.version} on ${platform}`, args.gui)
  emitLog('info', `Roots: ${roots.join(', ')}`, args.gui)
  await showProgress(state, 1, 'Starting', 'Detecting languages…', true)
  if (state.stopped) return process.exit(0)

  const detected = await walkDetect(roots, state)
  if (state.stopped) return process.exit(0)

  if (!Object.keys(detected).length) {
    emitLog('warn', 'No project manifests found', args.gui)
    writeHtmlReport(reportPath, [], platform)
    findings.writeFile()
    finishProgress(state, 'DONE', 'No projects found')
    if (args.gui) console.log(`DONE|SUCCESS|${reportPath}`)
    if (!args.gui && !args.noOpen) openPath(reportPath)
    return process.exit(0)
  }

  emitLog(
    'phase',
    `Detected: ${Object.keys(detected)
      .map((k) => `${k}(${detected[k].manifests.length})`)
      .join(', ')}`,
    args.gui
  )

  await showProgress(state, 15, 'Phase 2/4: Finding projects', 'Grouping manifests…', true)
  const projects = groupProjects(detected, args.maxProjects)
  const projectCount = Object.values(projects).reduce((n, d) => n + d.length, 0)
  emitLog('info', `Projects: ${projectCount} across ${Object.keys(projects).length} ecosystem(s)`, args.gui)
  if (state.stopped) return process.exit(0)

  await showProgress(state, 20, 'Phase 3/4: Auditing libraries', 'Preparing tooling…', true)
  await auditAll(projects, findings, osv, state)
  if (state.stopped) return process.exit(0)

  if (!args.skipCache) {
    await scanCaches(findings, osv, state)
    if (state.stopped) return process.exit(0)
  } else {
    emitLog('info', 'Skipping caches (-SkipCache)', args.gui)
  }

  await osv.flush(findings)
  findings.writeFile()
  writeHtmlReport(reportPath, findings.items, platform)
  finishProgress(state, 'DONE', `${findings.items.length} finding(s)`)
  emitLog('meta', `Finished: ${findings.items.length} finding(s) → ${reportPath}`, args.gui)

  if (args.gui) console.log(`DONE|SUCCESS|${reportPath}`)
  if (!args.gui && !args.noOpen) openPath(reportPath)
  process.exit(0)
}

function openPath(p: string): void {
  try {
    if (process.platform === 'darwin') spawn('open', [p], { detached: true, stdio: 'ignore' })
    else if (process.platform === 'win32') spawn('cmd', ['/c', 'start', '', p], { detached: true, stdio: 'ignore' })
    else spawn('xdg-open', [p], { detached: true, stdio: 'ignore' })
  } catch {
    /* ignore */
  }
}

main().catch((err) => {
  console.error(String(err))
  try {
    console.log(`DONE|FAILED|${String(err)}`)
  } catch {
    /* ignore */
  }
  process.exit(1)
})
