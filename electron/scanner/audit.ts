import fs from 'fs'
import path from 'path'
import { resolveTool, runNative } from './native'
import type { FindingsStore } from './findings'
import type { OsvClient } from './osv'
import type { ProgressState } from './progress'
import { emitEcoStatus, emitLog, showProgress } from './progress'

function readText(p: string): string {
  try {
    return fs.readFileSync(p, 'utf8')
  } catch {
    return ''
  }
}

function readJson<T>(p: string): T | null {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8')) as T
  } catch {
    return null
  }
}

export async function auditAll(
  projects: Record<string, string[]>,
  findings: FindingsStore,
  osv: OsvClient,
  state: ProgressState
): Promise<void> {
  const ecos = Object.keys(projects)
  let ecoIndex = 0
  for (const eco of ecos) {
    if (state.stopped) return
    ecoIndex++
    const dirs = projects[eco]
    const basePct = 20 + (50 * (ecoIndex - 1)) / Math.max(1, ecos.length)
    await showProgress(state, basePct, `Phase 3/4: Auditing ${eco}`, `Projects: ${dirs.length}`, true)
    emitEcoStatus(eco, 0, dirs.length, state.gui)

    for (let i = 0; i < dirs.length; i++) {
      if (state.stopped) return
      const dir = dirs[i]
      const pct = basePct + (50 / Math.max(1, ecos.length)) * ((i + 1) / Math.max(1, dirs.length))
      await showProgress(state, pct, `Phase 3/4: Auditing ${eco}`, dir)
      emitEcoStatus(eco, i + 1, dirs.length, state.gui)

      switch (eco) {
        case 'npm':
          await auditNpm(dir, findings, osv)
          break
        case 'nuget':
          await auditNuget(dir, findings, osv)
          break
        case 'PyPI':
          await auditPyPi(dir, findings, osv)
          break
        case 'Go':
          await auditGo(dir, findings, osv)
          break
        case 'crates.io':
          await auditRust(dir, findings)
          break
        case 'Packagist':
          await auditPhp(dir, findings)
          break
        case 'Maven':
          await auditMaven(dir, findings, osv)
          break
        case 'Pub':
          await auditPub(dir, findings, osv)
          break
        case 'Swift':
          await auditSwift(dir, findings, osv)
          break
        case 'Scala':
          await auditScala(dir, findings, osv)
          break
        case 'RubyGems':
          emitLog('info', `RubyGems: native audit not configured (${dir})`, state.gui)
          break
        default:
          break
      }
      findings.maybeFlush(state)
    }
    await osv.flush(findings)
    findings.maybeFlush(state, true)
  }
  emitEcoStatus('', 0, 0, state.gui)
}

async function auditNpm(dir: string, findings: FindingsStore, osv: OsvClient): Promise<void> {
  const npm = resolveTool('npm')
  const yarn = resolveTool('yarn')
  const hasYarnLock = fs.existsSync(path.join(dir, 'yarn.lock'))
  let nativeRan = false

  if (npm) {
    const res = await runNative(npm, ['audit', '--json', '--omit=dev'], { cwd: dir })
    nativeRan = true
    parseNpmAudit(res.stdout, dir, findings, 'npm-audit')
  } else if (yarn && hasYarnLock) {
    const res = await runNative(yarn, ['audit', '--json'], { cwd: dir })
    nativeRan = true
    parseYarnAudit(res.stdout, dir, findings)
  }

  if (!nativeRan) {
    const pkgPath = path.join(dir, 'package.json')
    const pkg = readJson<{
      dependencies?: Record<string, string>
      devDependencies?: Record<string, string>
    }>(pkgPath)
    if (pkg) {
      for (const [name, ver] of Object.entries({
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
      })) {
        const cleaned = String(ver).replace(/^[~^>=<\s]+/, '')
        if (/^\d/.test(cleaned)) osv.enqueue('npm', 'npm', name, cleaned, pkgPath, 'package.json')
      }
    }
  }
}

function parseNpmAudit(stdout: string, dir: string, findings: FindingsStore, source: string): void {
  let audit: Record<string, unknown>
  try {
    audit = JSON.parse(stdout)
  } catch {
    return
  }
  const vulns = (audit as { vulnerabilities?: Record<string, Record<string, unknown>> }).vulnerabilities
  if (vulns) {
    for (const [name, v] of Object.entries(vulns)) {
      const via = Array.isArray(v.via) ? v.via : []
      let severity = String(v.severity || 'unknown').toLowerCase()
      let title = name
      const advParts: string[] = []
      for (const item of via) {
        if (typeof item === 'string') {
          advParts.push(item)
        } else if (item && typeof item === 'object') {
          const o = item as Record<string, unknown>
          if (o.severity) severity = String(o.severity).toLowerCase()
          if (o.title) title = String(o.title)
          if (o.url) advParts.push(String(o.url))
          if (o.source) advParts.push(String(o.source))
        }
      }
      findings.add({
        Ecosystem: 'npm',
        Source: source,
        Severity: severity,
        Package: name,
        Version: String(v.range || ''),
        Title: title,
        Advisory: advParts.join(', '),
        Path: dir,
        Fix: v.fixAvailable ? String(v.fixAvailable) : '',
        HasFix: Boolean(v.fixAvailable),
      })
    }
    return
  }
  const advisories = (audit as { advisories?: Record<string, Record<string, unknown>> }).advisories
  if (advisories) {
    for (const adv of Object.values(advisories)) {
      const findingsArr = Array.isArray(adv.findings) ? adv.findings : []
      const ver =
        findingsArr[0] && typeof findingsArr[0] === 'object'
          ? String((findingsArr[0] as { version?: string }).version || '')
          : ''
      findings.add({
        Ecosystem: 'npm',
        Source: source,
        Severity: String(adv.severity || 'unknown'),
        Package: String(adv.module_name || ''),
        Version: ver,
        Title: String(adv.title || ''),
        Advisory: [adv.url, adv.github_advisory_id, ...(Array.isArray(adv.cves) ? adv.cves : [])]
          .filter(Boolean)
          .map(String)
          .join(', '),
        Path: dir,
        Fix: String(adv.recommendation || ''),
      })
    }
  }
}

function parseYarnAudit(stdout: string, dir: string, findings: FindingsStore): void {
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.trim()) continue
    try {
      const obj = JSON.parse(line) as { type?: string; data?: { advisory?: Record<string, unknown> } }
      if (obj.type !== 'auditAdvisory' || !obj.data?.advisory) continue
      const adv = obj.data.advisory
      findings.add({
        Ecosystem: 'npm',
        Source: 'yarn-audit',
        Severity: String(adv.severity || 'unknown'),
        Package: String(adv.module_name || ''),
        Version: String((Array.isArray(adv.findings) && (adv.findings[0] as { version?: string })?.version) || ''),
        Title: String(adv.title || ''),
        Advisory: String(adv.url || adv.github_advisory_id || ''),
        Path: dir,
        Fix: String(adv.recommendation || ''),
      })
    } catch {
      /* ignore */
    }
  }
}

async function auditNuget(dir: string, findings: FindingsStore, osv: OsvClient): Promise<void> {
  const dotnet = resolveTool('dotnet')
  let nativeRan = false
  if (dotnet) {
    const res = await runNative(
      dotnet,
      ['list', 'package', '--vulnerable', '--include-transitive'],
      { cwd: dir }
    )
    nativeRan = true
    for (const line of res.stdout.split(/\r?\n/)) {
      const m = line.match(/^\s*>\s*(\S+)\s+(\S+)/)
      if (!m) continue
      findings.add({
        Ecosystem: 'nuget',
        Source: 'dotnet-list-vulnerable',
        Severity: 'high',
        Package: m[1],
        Version: m[2],
        Title: 'Vulnerable NuGet package reported by dotnet',
        Advisory: '',
        Path: dir,
        Fix: 'Upgrade to a non-vulnerable version',
      })
    }
  }
  if (!nativeRan) {
    for (const file of listFiles(dir, ['.csproj', '.fsproj', '.vbproj', 'packages.config'])) {
      if (file.endsWith('packages.config')) {
        const text = readText(file)
        for (const m of text.matchAll(/id="([^"]+)"\s+version="([^"]+)"/gi)) {
          osv.enqueue('nuget', 'NuGet', m[1], m[2], file, 'packages.config')
        }
      } else {
        const text = readText(file)
        for (const m of text.matchAll(
          /<PackageReference[^>]*(?:Include|Update)="([^"]+)"[^>]*Version="([^"]+)"/gi
        )) {
          osv.enqueue('nuget', 'NuGet', m[1], m[2], file, path.basename(file))
        }
        for (const m of text.matchAll(
          /<PackageReference[^>]*Version="([^"]+)"[^>]*(?:Include|Update)="([^"]+)"/gi
        )) {
          osv.enqueue('nuget', 'NuGet', m[2], m[1], file, path.basename(file))
        }
      }
    }
  }
}

async function auditPyPi(dir: string, findings: FindingsStore, osv: OsvClient): Promise<void> {
  const pipAudit = resolveTool('pip-audit')
  let nativeRan = false
  if (pipAudit) {
    const req = path.join(dir, 'requirements.txt')
    const args = fs.existsSync(req)
      ? ['-r', req, '-f', 'json']
      : ['-f', 'json']
    const res = await runNative(pipAudit, args, { cwd: dir })
    nativeRan = true
    try {
      const rows = JSON.parse(res.stdout) as {
        name?: string
        version?: string
        vulns?: { id?: string; description?: string; fix_versions?: string[] }[]
      }[]
      if (Array.isArray(rows)) {
        for (const row of rows) {
          for (const v of row.vulns || []) {
            findings.add({
              Ecosystem: 'PyPI',
              Source: 'pip-audit',
              Severity: 'high',
              Package: row.name || '',
              Version: row.version || '',
              Title: v.description || v.id || 'pip-audit finding',
              Advisory: v.id || '',
              Path: dir,
              Fix: (v.fix_versions || []).join(', ') || 'Upgrade to a patched version',
            })
          }
        }
      }
    } catch {
      /* ignore */
    }
  }
  if (!nativeRan) {
    const req = path.join(dir, 'requirements.txt')
    if (fs.existsSync(req)) {
      for (const line of readText(req).split(/\r?\n/)) {
        const m = line.match(/^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)/)
        if (m) osv.enqueue('PyPI', 'PyPI', m[1], m[2], req, 'requirements.txt')
      }
    }
  }
}

async function auditGo(dir: string, findings: FindingsStore, osv: OsvClient): Promise<void> {
  const govuln = resolveTool('govulncheck')
  if (govuln) {
    const res = await runNative(govuln, ['-json', './...'], { cwd: dir })
    for (const line of res.stdout.split(/\r?\n/)) {
      if (!line.trim()) continue
      try {
        const obj = JSON.parse(line) as { finding?: unknown; osv?: { id?: string } }
        if (obj.finding || obj.osv) {
          findings.add({
            Ecosystem: 'Go',
            Source: 'govulncheck',
            Severity: 'high',
            Package: obj.osv?.id || 'govulncheck',
            Version: '',
            Title: obj.osv?.id || 'govulncheck finding',
            Advisory: obj.osv?.id || '',
            Path: dir,
            Fix: 'See govulncheck advisory',
          })
        }
      } catch {
        /* ignore */
      }
    }
  }
  const mod = path.join(dir, 'go.mod')
  if (fs.existsSync(mod)) {
    for (const line of readText(mod).split(/\r?\n/)) {
      const m = line.match(/^\s*([^\s]+)\s+v([0-9][^\s]+)/)
      if (m) osv.enqueue('Go', 'Go', m[1], `v${m[2]}`, mod, 'go.mod')
    }
  }
}

async function auditRust(dir: string, findings: FindingsStore): Promise<void> {
  const cargo = resolveTool('cargo')
  if (!cargo) return
  const res = await runNative(cargo, ['audit', '--json'], { cwd: dir })
  try {
    const raw = JSON.parse(res.stdout) as {
      vulnerabilities?: { list?: { advisory?: Record<string, string> }[] }
    }
    for (const item of raw.vulnerabilities?.list || []) {
      const adv = item.advisory || {}
      findings.add({
        Ecosystem: 'crates.io',
        Source: 'cargo-audit',
        Severity: String(adv.severity || 'unknown'),
        Package: String(adv.package || ''),
        Version: '',
        Title: String(adv.title || ''),
        Advisory: String(adv.id || ''),
        Path: dir,
        Fix: 'Upgrade crate to a patched version',
      })
    }
  } catch {
    /* ignore */
  }
}

async function auditPhp(dir: string, findings: FindingsStore): Promise<void> {
  const composer = resolveTool('composer')
  if (!composer) return
  const res = await runNative(composer, ['audit', '--format=json'], { cwd: dir })
  try {
    const raw = JSON.parse(res.stdout) as {
      advisories?: Record<string, { title?: string; advisoryId?: string }[]>
    }
    for (const [pkg, list] of Object.entries(raw.advisories || {})) {
      for (const adv of list || []) {
        findings.add({
          Ecosystem: 'Packagist',
          Source: 'composer-audit',
          Severity: 'high',
          Package: pkg,
          Version: '',
          Title: adv.title || 'Composer advisory',
          Advisory: adv.advisoryId || '',
          Path: dir,
          Fix: 'Upgrade package to a patched version',
        })
      }
    }
  } catch {
    /* ignore */
  }
}

async function auditMaven(dir: string, findings: FindingsStore, osv: OsvClient): Promise<void> {
  const pom = path.join(dir, 'pom.xml')
  if (!fs.existsSync(pom)) return
  const text = readText(pom)
  const deps = text.matchAll(/<dependency>[\s\S]*?<\/dependency>/gi)
  for (const block of deps) {
    const g = block[0].match(/<groupId>([^<]+)<\/groupId>/i)
    const a = block[0].match(/<artifactId>([^<]+)<\/artifactId>/i)
    const v = block[0].match(/<version>([^<]+)<\/version>/i)
    if (!g || !a || !v) continue
    if (v[1].includes('${')) continue
    osv.enqueue('Maven', 'Maven', `${g[1]}:${a[1]}`, v[1], pom, 'pom.xml')
  }
}

async function auditPub(dir: string, findings: FindingsStore, osv: OsvClient): Promise<void> {
  const lock = path.join(dir, 'pubspec.lock')
  if (!fs.existsSync(lock)) return
  let name = ''
  for (const line of readText(lock).split(/\r?\n/)) {
    const nm = line.match(/^\s{2}([A-Za-z0-9_]+):\s*$/)
    if (nm) {
      name = ['sdks', 'packages'].includes(nm[1]) ? '' : nm[1]
      continue
    }
    const ver = line.match(/^\s+version:\s+"([^"]+)"/)
    if (name && ver) {
      osv.enqueue('Pub', 'Pub', name, ver[1], lock, 'pubspec.lock')
      name = ''
    }
  }
}

async function auditSwift(dir: string, findings: FindingsStore, osv: OsvClient): Promise<void> {
  const resolved = path.join(dir, 'Package.resolved')
  if (!fs.existsSync(resolved)) return
  const data = readJson<{
    object?: { pins?: { location?: string; repositoryURL?: string; state?: { version?: string }; version?: string }[] }
    pins?: { location?: string; repositoryURL?: string; state?: { version?: string }; version?: string }[]
  }>(resolved)
  const pins = data?.object?.pins || data?.pins || []
  for (const pin of pins) {
    const name = pin.location || pin.repositoryURL
    const version = pin.state?.version || pin.version
    if (name && version) osv.enqueue('Swift', 'SwiftURL', name, version, resolved, 'Package.resolved')
  }
}

async function auditScala(dir: string, findings: FindingsStore, osv: OsvClient): Promise<void> {
  for (const file of ['build.sbt', 'plugins.sbt'].map((f) => path.join(dir, f))) {
    if (!fs.existsSync(file)) continue
    const text = readText(file)
    for (const m of text.matchAll(/"([^"]+)"\s*%{1,3}\s*"([^"]+)"\s*%\s*"([^"]+)"/g)) {
      osv.enqueue('Scala', 'Maven', `${m[1]}:${m[2]}`, m[3], file, path.basename(file))
    }
  }
}

function listFiles(dir: string, matchers: string[]): string[] {
  const out: string[] = []
  let entries: string[]
  try {
    entries = fs.readdirSync(dir)
  } catch {
    return out
  }
  for (const name of entries) {
    const full = path.join(dir, name)
    try {
      if (!fs.statSync(full).isFile()) continue
    } catch {
      continue
    }
    for (const m of matchers) {
      if (m.startsWith('.') && name.toLowerCase().endsWith(m.toLowerCase())) out.push(full)
      else if (name.toLowerCase() === m.toLowerCase()) out.push(full)
    }
  }
  return out
}
