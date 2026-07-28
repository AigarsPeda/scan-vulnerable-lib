import type { FindingsStore } from './findings'
import { emitLog } from './progress'
import type { OsvQueueItem } from './types'

type OsvVuln = {
  id?: string
  summary?: string
  aliases?: string[]
  related?: string[]
  severity?: unknown
  database_specific?: { severity?: string }
}

const OSV_QUERY = 'https://api.osv.dev/v1/query'
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch'
const BATCH_SIZE = 80

export class OsvClient {
  private cache = new Map<string, OsvVuln[] | null>()
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

    // Resolve via cache / batch
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
      const results = await this.queryBatch(
        chunk.map((c) => ({
          package: { name: c.item.package, ecosystem: c.item.osvEco },
          version: c.item.version,
        }))
      )
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
    findings.add({
      Ecosystem: item.ecoLabel,
      Source: item.source,
      Severity: severity,
      Package: item.package,
      Version: item.version,
      Title: title,
      Advisory: [...new Set(ids)].join(', '),
      Path: item.path,
      Fix: 'Upgrade to a patched version (see advisory)',
    })
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
          // fallback to single queries
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
    if (v.database_specific?.severity) {
      s = String(v.database_specific.severity).toLowerCase()
    } else if (v.severity) {
      s = 'medium'
    }
    const r = rank[s] || 0
    if (r > n) {
      n = r
      best = s
    }
  }
  return best
}
