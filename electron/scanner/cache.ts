import fs from 'fs'
import os from 'os'
import path from 'path'
import { resolveTool, runNative } from './native'
import type { FindingsStore } from './findings'
import type { OsvClient } from './osv'
import type { ProgressState } from './progress'
import { emitLog, showProgress } from './progress'

export async function scanCaches(
  findings: FindingsStore,
  osv: OsvClient,
  state: ProgressState
): Promise<void> {
  await showProgress(state, 75, 'Phase 4/4: Checking caches', 'npm / yarn / NuGet', true)
  if (state.stopped) return

  const seen = new Set<string>()
  await scanNpmCaches(osv, seen, state)
  if (state.stopped) return
  await scanYarnCaches(osv, seen, state)
  if (state.stopped) return
  await scanNugetCache(osv, seen, state)

  await osv.flush(findings)
  findings.maybeFlush(state, true)
  await showProgress(state, 88, 'Phase 4/4: Checking caches', 'Cache scan complete', true)
}

async function scanNpmCaches(
  osv: OsvClient,
  seen: Set<string>,
  state: ProgressState
): Promise<void> {
  const roots = new Set<string>()
  const npm = resolveTool('npm')
  if (npm) {
    const res = await runNative(npm, ['config', 'get', 'cache'], { timeoutMs: 15_000 })
    const p = res.stdout.trim()
    if (p && fs.existsSync(p)) roots.add(p)
  }
  const home = os.homedir()
  if (process.platform === 'win32') {
    const local = process.env.LOCALAPPDATA || ''
    const app = process.env.APPDATA || ''
    for (const c of [path.join(local, 'npm-cache'), path.join(app, 'npm-cache'), path.join(home, '.npm')]) {
      if (fs.existsSync(c)) roots.add(c)
    }
  } else {
    for (const c of [
      path.join(home, '.npm'),
      path.join(home, 'Library/Caches/npm'),
      path.join(home, '.local/share/npm-cache'),
    ]) {
      if (fs.existsSync(c)) roots.add(c)
    }
  }

  let checked = 0
  for (const root of roots) {
    if (state.stopped) return
    const indexDirs = [
      path.join(root, '_cacache', 'index-v5'),
      path.join(root, '_cacache', 'index-v6'),
      path.join(root, 'index-v5'),
    ].filter((d) => fs.existsSync(d))

    for (const indexDir of indexDirs) {
      walkFiles(indexDir, 3, (file) => {
        if (state.stopped) return
        let text = ''
        try {
          text = fs.readFileSync(file, 'utf8')
        } catch {
          return
        }
        const re =
          /registry\.npmjs\.org\/(?<pkgPath>@[^/]+\/[^/]+|[^/]+)\/-\/(?<file>[^"'\\\s]+)\.tgz/g
        for (const m of text.matchAll(re)) {
          const pkgPath = m.groups?.pkgPath
          const fname = m.groups?.file
          if (!pkgPath || !fname) continue
          const base = path.basename(fname)
          const name = pkgPath
          const nameTail = name.includes('/') ? name.split('/').pop()! : name
          let version = ''
          if (base.startsWith(nameTail + '-')) {
            version = base.slice(nameTail.length + 1)
          }
          if (!version || !/^\d/.test(version)) continue
          const key = `npm|${name}@${version}`
          if (seen.has(key)) continue
          seen.add(key)
          osv.enqueue('npm', 'npm', name, version, file, 'cache:npm-cache')
          checked++
        }
      })
    }
    await showProgress(state, 78, 'Phase 4/4: Checking caches', `npm cache packages ~${checked}`)
  }
  emitLog('info', `npm cache packages queued: ${checked}`, state.gui)
}

async function scanYarnCaches(
  osv: OsvClient,
  seen: Set<string>,
  state: ProgressState
): Promise<void> {
  const home = os.homedir()
  const candidates: string[] = []
  if (process.platform === 'win32') {
    const local = process.env.LOCALAPPDATA || ''
    candidates.push(path.join(local, 'Yarn', 'Cache'), path.join(local, 'Yarn', 'Cache', 'v6'))
  } else {
    candidates.push(
      path.join(home, '.yarn/berry/cache'),
      path.join(home, 'Library/Caches/Yarn'),
      path.join(home, 'Library/Caches/Yarn/v6')
    )
  }

  let checked = 0
  for (const root of candidates) {
    if (!fs.existsSync(root) || state.stopped) continue
    walkFiles(root, 2, (file) => {
      const base = path.basename(file)
      if (!(base.startsWith('npm-') || base.endsWith('.tgz') || base.endsWith('.zip'))) return
      // npm-lodash-4.17.21-hash
      const m = base.match(/^npm-(.+)-(\d[\w.-]*?)-[a-f0-9]{8,}/i) || base.match(/^npm-(.+)-(\d[^-]*)/i)
      if (!m) return
      let name = m[1]
      const version = m[2]
      if (name.includes('-') && name.startsWith('@')) {
        // @scope-name → @scope/name (best-effort)
        const idx = name.indexOf('-')
        if (idx > 0) name = name.slice(0, idx) + '/' + name.slice(idx + 1)
      }
      const key = `npm|${name}@${version}`
      if (seen.has(key)) return
      seen.add(key)
      osv.enqueue('npm', 'npm', name, version, file, 'cache:yarn-cache')
      checked++
    })
  }
  emitLog('info', `yarn cache packages queued: ${checked}`, state.gui)
  await showProgress(state, 82, 'Phase 4/4: Checking caches', `yarn cache ~${checked}`)
}

async function scanNugetCache(
  osv: OsvClient,
  seen: Set<string>,
  state: ProgressState
): Promise<void> {
  const root = path.join(os.homedir(), '.nuget', 'packages')
  if (!fs.existsSync(root)) return
  let checked = 0
  let ids: string[] = []
  try {
    ids = fs.readdirSync(root)
  } catch {
    return
  }
  for (const id of ids) {
    if (state.stopped) return
    const idDir = path.join(root, id)
    let versions: string[] = []
    try {
      if (!fs.statSync(idDir).isDirectory()) continue
      versions = fs.readdirSync(idDir)
    } catch {
      continue
    }
    for (const ver of versions) {
      const key = `nuget|${id}@${ver}`
      if (seen.has(key)) continue
      seen.add(key)
      osv.enqueue('nuget', 'NuGet', id, ver, path.join(idDir, ver), 'cache:nuget')
      checked++
    }
  }
  emitLog('info', `NuGet cache packages queued: ${checked}`, state.gui)
  await showProgress(state, 86, 'Phase 4/4: Checking caches', `NuGet cache ~${checked}`)
}

function walkFiles(root: string, maxDepth: number, onFile: (file: string) => void): void {
  const stack: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }]
  while (stack.length) {
    const { dir, depth } = stack.pop()!
    let entries: fs.Dirent[]
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name)
      if (ent.isDirectory()) {
        if (depth < maxDepth) stack.push({ dir: full, depth: depth + 1 })
      } else if (ent.isFile()) {
        onFile(full)
      }
    }
  }
}
