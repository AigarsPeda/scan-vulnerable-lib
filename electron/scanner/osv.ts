import type { FindingsStore } from './findings'
import { emitLog } from './progress'
import type { OsvQueueItem } from './types'

type OsvVuln = {
  id?: string
  summary?: string
  aliases?: string[]
  related?: string[]
  severity?: { type?: string; score?: string }[] | unknown
  database_specific?: { severity?: string }
  affected?: {
    package?: { name?: string; ecosystem?: string }
    ranges?: { type?: string; events?: { introduced?: string; fixed?: string; last_affected?: string }[] }[]
  }[]
}

const OSV_QUERY = 'https://api.osv.dev/v1/query'
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch'
const OSV_VULN = 'https://api.osv.dev/v1/vulns'
const BATCH_SIZE = 80

export class OsvClient {
  private cache = new Map<string, OsvVuln[] | null>()
  private vulnCache = new Map<string, OsvVuln>()
  private queue: OsvQueueItem[] = []
  private degraded = false
  skip: boolean
  gui: boolean
  stats = { queries: 0, cacheHits: 0, batchCalls: 0 }

  constructor(skip: boolean, gui: boolean) {
    this.skip = skip
    this.gui = gui
  }

  enqueue(
    ecoLabel: string,
    osvEco: string,
    pkg: string,
    version: string,
    filePath: string,
    source: string
  ): void {
    if (this.skip || !pkg || !version) return
    this.queue.push({ ecoLabel, osvEco, package: pkg, version, path: filePath, source })
  }

  async flush(findings: FindingsStore): Promise<void> {
    if (this.skip || !this.queue.length) return
    const items = this.queue.splice(0, this.queue.length)

    const pending: { item: OsvQueueItem; key: string }[] = []
    for (const item of items) {
      const key = `${item.osvEco}|${item.package}|${item.version}`.toLowerCase()
      if (this.cache.has(key)) {
        this.stats.cacheHits++
        const vulns = this.cache.get(key)
        if (vulns?.length) this.emitFinding(findings, item, vulns)
        continue
      }
      pending.push({ item, key })
    }

    for (let i = 0; i < pending.length; i += BATCH_SIZE) {
      const chunk = pending.slice(i, i + BATCH_SIZE)
      this.stats.batchCalls++
      let results = await this.queryBatch(
        chunk.map((c) => ({
          package: { name: c.item.package, ecosystem: c.item.osvEco },
          version: c.item.version,
        }))
      )
      // querybatch returns id-only stubs — hydrate for severity/summary
      results = await Promise.all(results.map((vulns) => this.hydrateVulns(vulns)))
      for (let j = 0; j < chunk.length; j++) {
        const vulns = results[j] || []
        this.cache.set(chunk[j].key, vulns)
        if (vulns.length) this.emitFinding(findings, chunk[j].item, vulns)
      }
      findings.maybeFlush()
    }
  }

  private emitFinding(findings: FindingsStore, item: OsvQueueItem, vulns: OsvVuln[]): void {
    const severity = getOsvSeverity(vulns)
    const first = vulns[0]
    const title = first?.summary || first?.id || 'OSV vulnerability'
    const ids = vulns
      .flatMap((v) => [v.id, ...(v.aliases || []), ...(v.related || [])])
      .filter(Boolean) as string[]
    const fixed = collectOsvFixedVersions(vulns, item.package)
    findings.add({
      Ecosystem: item.ecoLabel,
      Source: item.source,
      Severity: severity,
      Package: item.package,
      Version: item.version,
      Title: title,
      Advisory: [...new Set(ids)].join(', '),
      Path: item.path,
      Fix: fixed.length
        ? `Upgrade to ${fixed.join(' / ')}`
        : 'Upgrade to a patched version (see advisory)',
      HasFix: true,
    })
  }

  /** querybatch only returns {id, modified} — fetch full vuln records. */
  private async hydrateVulns(stubs: OsvVuln[]): Promise<OsvVuln[]> {
    const ids = stubs.map((s) => s?.id).filter(Boolean) as string[]
    const missing = [...new Set(ids.filter((id) => !this.vulnCache.has(id)))]
    const concurrency = 8
    for (let i = 0; i < missing.length; i += concurrency) {
      const slice = missing.slice(i, i + concurrency)
      await Promise.all(
        slice.map(async (id) => {
          const full = await this.fetchVulnById(id)
          if (full) this.vulnCache.set(id, full)
        })
      )
    }
    return stubs.map((stub) => {
      if (!stub?.id) return stub
      return this.vulnCache.get(stub.id) || stub
    })
  }

  private async fetchVulnById(id: string): Promise<OsvVuln | null> {
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await fetch(`${OSV_VULN}/${encodeURIComponent(id)}`)
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        return (await res.json()) as OsvVuln
      } catch {
        if (attempt === 3) return null
        await new Promise((r) => setTimeout(r, 200 * attempt))
      }
    }
    return null
  }

  private async queryBatch(
    queries: { package: { name: string; ecosystem: string }; version: string }[]
  ): Promise<OsvVuln[][]> {
    this.stats.queries += queries.length
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await fetch(OSV_BATCH, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ queries }),
        })
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = (await res.json()) as { results?: { vulns?: OsvVuln[] }[] }
        return (data.results || []).map((r) => r.vulns || [])
      } catch (err) {
        if (attempt === 3) {
          if (!this.degraded) {
            this.degraded = true
            emitLog('warn', `OSV API degraded: ${String(err)}`, this.gui)
          }
          const out: OsvVuln[][] = []
          for (const q of queries) {
            out.push(await this.queryOne(q.package.name, q.package.ecosystem, q.version))
          }
          return out
        }
        await new Promise((r) => setTimeout(r, 400 * attempt))
      }
    }
    return queries.map(() => [])
  }

  private async queryOne(name: string, ecosystem: string, version: string): Promise<OsvVuln[]> {
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await fetch(OSV_QUERY, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: { name, ecosystem }, version }),
        })
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = (await res.json()) as { vulns?: OsvVuln[] }
        return data.vulns || []
      } catch {
        if (attempt === 3) return []
        await new Promise((r) => setTimeout(r, 250 * attempt))
      }
    }
    return []
  }
}

function getOsvSeverity(vulns: OsvVuln[]): string {
  const rank: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    moderate: 2,
    low: 1,
  }
  let best = 'unknown'
  let n = 0
  for (const v of vulns) {
    let s = 'unknown'
    const dbSev = v.database_specific?.severity
    if (dbSev) {
      s = String(dbSev).toLowerCase()
    } else if (Array.isArray(v.severity) && v.severity.length) {
      s = severityFromCvssList(v.severity)
    } else if (v.severity) {
      s = 'medium'
    }
    if (s === 'moderate') s = 'medium'
    const r = rank[s] || 0
    if (r > n) {
      n = r
      best = s
    }
  }
  return best
}

function severityFromCvssList(
  list: { type?: string; score?: string }[]
): string {
  let bestScore = -1
  for (const item of list) {
    const raw = String(item.score || '')
    // Numeric score: "7.5" or embedded in some payloads
    const numeric = raw.match(/^(\d+(?:\.\d+)?)$/)
    if (numeric) {
      bestScore = Math.max(bestScore, Number(numeric[1]))
      continue
    }
    // CVSS vector — map attack/impact heuristically via known base scores when present
    // e.g. some records include "CVSS:3.1/AV:N/.../SC:N" without numeric; use vector hints
    if (/AV:N.*AC:L.*PR:N/i.test(raw) && /C:H|I:H|A:H/i.test(raw)) {
      bestScore = Math.max(bestScore, 9.0)
    } else if (/C:H|I:H|A:H/i.test(raw)) {
      bestScore = Math.max(bestScore, 7.5)
    } else if (/C:L|I:L|A:L/i.test(raw)) {
      bestScore = Math.max(bestScore, 4.0)
    } else if (raw.includes('CVSS')) {
      bestScore = Math.max(bestScore, 5.0)
    }
  }
  if (bestScore < 0) return 'medium'
  if (bestScore >= 9) return 'critical'
  if (bestScore >= 7) return 'high'
  if (bestScore >= 4) return 'medium'
  return 'low'
}

/** Pull fixed versions from OSV affected ranges for this package. */
function collectOsvFixedVersions(vulns: OsvVuln[], packageName: string): string[] {
  const fixed = new Set<string>()
  const pkgLower = packageName.toLowerCase()
  for (const v of vulns) {
    for (const aff of v.affected || []) {
      const name = String(aff.package?.name || '').toLowerCase()
      if (name && name !== pkgLower) continue
      for (const range of aff.ranges || []) {
        for (const ev of range.events || []) {
          const f = String(ev.fixed || '').trim()
          if (f) fixed.add(f)
        }
      }
    }
  }
  return [...fixed].sort()
}
