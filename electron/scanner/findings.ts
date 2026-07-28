import fs from 'fs'
import path from 'path'
import type { Finding } from './types'
import { isCacheLocation } from './platform'
import type { ProgressState } from './progress'

function sanitize(text: string): string {
  return (text || '').replace(/[\r\n|]/g, ' ').trim()
}

export class FindingsStore {
  readonly items: Finding[] = []
  private keys = new Set<string>()
  private lastWrite = 0
  highOnly: boolean
  findingsPath: string
  platform: string
  gui: boolean

  constructor(findingsPath: string, platform: string, highOnly: boolean, gui: boolean) {
    this.findingsPath = findingsPath
    this.platform = platform
    this.highOnly = highOnly
    this.gui = gui
  }

  clearFile(): void {
    this.writeFile(true)
  }

  add(partial: Omit<Finding, 'HasFix' | 'IsCache'> & { HasFix?: boolean; IsCache?: boolean }): void {
    const sevRaw = (partial.Severity || 'unknown').toLowerCase()
    const sev = sevRaw === 'moderate' ? 'medium' : sevRaw
    if (this.highOnly && sev !== 'high' && sev !== 'critical') return

    const titleClean = sanitize(partial.Title)
    const key = [
      partial.Ecosystem,
      partial.Package,
      partial.Version,
      partial.Path,
      sev,
      titleClean,
    ]
      .join('|')
      .toLowerCase()
    if (this.keys.has(key)) return
    this.keys.add(key)

    const fix = partial.Fix || ''
    const finding: Finding = {
      Ecosystem: partial.Ecosystem,
      Source: partial.Source,
      Severity: sev,
      Package: partial.Package,
      Version: partial.Version || '',
      Title: titleClean,
      Advisory: sanitize(partial.Advisory || ''),
      Path: partial.Path || '',
      Fix: fix,
      HasFix: partial.HasFix ?? Boolean(fix && !/^none$/i.test(fix)),
      IsCache: partial.IsCache ?? isCacheLocation(partial.Source, partial.Path),
    }
    this.items.push(finding)

    if (this.gui) {
      console.log(
        [
          'FINDING',
          finding.Severity,
          `${finding.Package}${finding.Version ? '@' + finding.Version : ''}`,
          finding.Ecosystem,
          finding.Title,
          finding.Path,
          finding.HasFix ? '1' : '0',
          String(this.items.length),
          finding.IsCache ? '1' : '0',
        ].join('|')
      )
    }
  }

  maybeFlush(state?: ProgressState, force = false): void {
    const now = Date.now()
    if (!force && now - this.lastWrite < 600) return
    this.lastWrite = now
    this.writeFile(false)
    if (state) state.findingsCount = this.items.length
  }

  writeFile(_empty = false): void {
    const dir = path.dirname(this.findingsPath)
    fs.mkdirSync(dir, { recursive: true })
    const payload = {
      generated: new Date().toISOString(),
      platform: this.platform,
      count: this.items.length,
      findings: this.items,
    }
    const tmp = this.findingsPath + '.tmp'
    fs.writeFileSync(tmp, JSON.stringify(payload), 'utf8')
    fs.renameSync(tmp, this.findingsPath)
  }
}
