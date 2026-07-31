import fs from 'fs'
import os from 'os'
import path from 'path'
import { afterEach, describe, expect, it } from 'vitest'
import { createProgress } from '../electron/scanner/progress'
import { walkDetect, groupProjects } from '../electron/scanner/walk'
import { auditAll } from '../electron/scanner/audit'
import { FindingsStore } from '../electron/scanner/findings'
import { OsvClient } from '../electron/scanner/osv'

const fixtureNpm = path.resolve(__dirname, 'fixtures/sample-npm')
const fixturePy = path.resolve(__dirname, 'fixtures/sample-python')

function makeState(outputDir: string) {
  return createProgress(outputDir, path.join(outputDir, 'report.html'), false)
}

async function osvReachable(): Promise<boolean> {
  try {
    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: [{ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' }],
      }),
    })
    return res.ok
  } catch {
    return false
  }
}

describe('scanner walk + audit (cross-platform)', () => {
  const temps: string[] = []
  afterEach(() => {
    for (const t of temps) fs.rmSync(t, { recursive: true, force: true })
    temps.length = 0
  })

  it('detects npm and python fixtures under an explicit folder only', async () => {
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vuln-walk-'))
    temps.push(out)
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vuln-workspace-'))
    temps.push(root)

    fs.cpSync(fixtureNpm, path.join(root, 'sample-npm'), { recursive: true })
    fs.cpSync(fixturePy, path.join(root, 'sample-python'), { recursive: true })

    const detected = await walkDetect([root], makeState(out))
    expect(Object.keys(detected).sort()).toEqual(['JavaScript/TypeScript', 'Python'].sort())
    expect(detected['JavaScript/TypeScript'].manifests.some((m) => m.includes('sample-npm'))).toBe(
      true
    )
    expect(detected.Python.manifests.some((m) => m.includes('requirements.txt'))).toBe(true)

    const projects = groupProjects(detected, 80)
    expect(projects.npm).toContain(path.join(root, 'sample-npm'))
    expect(projects.PyPI).toContain(path.join(root, 'sample-python'))
  })

  it('enqueues lockfile packages with project-dir paths (offline)', async () => {
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vuln-offline-'))
    temps.push(out)
    const findings = new FindingsStore(path.join(out, 'findings.json'), process.platform, false, false)
    const enqueued: { pkg: string; version: string; filePath: string; source: string }[] = []

    const osv = new OsvClient(true, false)
    const original = osv.enqueue.bind(osv)
    osv.enqueue = (ecoLabel, osvEco, pkg, version, filePath, source) => {
      enqueued.push({ pkg, version, filePath, source })
      return original(ecoLabel, osvEco, pkg, version, filePath, source)
    }

    await auditAll({ npm: [fixtureNpm], PyPI: [fixturePy] }, findings, osv, makeState(out))

    expect(enqueued.some((e) => e.pkg === 'lodash' && e.version === '4.17.20')).toBe(true)
    expect(enqueued.some((e) => /django/i.test(e.pkg))).toBe(true)
    for (const e of enqueued) {
      expect(path.basename(e.filePath)).not.toMatch(/package\.json|requirements\.txt|package-lock\.json/i)
    }
  })

  it('audits fixture projects with OSV enabled (network)', async () => {
    if (!(await osvReachable())) {
      console.warn('Skipping OSV network test — api.osv.dev unreachable')
      return
    }

    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vuln-audit-'))
    temps.push(out)
    const findings = new FindingsStore(path.join(out, 'findings.json'), process.platform, false, false)
    const osv = new OsvClient(false, false)
    await auditAll({ npm: [fixtureNpm], PyPI: [fixturePy] }, findings, osv, makeState(out))
    await osv.flush(findings)
    findings.writeFile()

    expect(findings.items.length).toBeGreaterThan(0)
    for (const f of findings.items) {
      expect(path.basename(f.Path)).not.toMatch(/package\.json|requirements\.txt/i)
      expect(f.Severity).not.toBe('')
    }
  })
})
