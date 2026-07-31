/**
 * macOS-only suite — skipped on Windows/Linux.
 * GitHub Actions `macos-latest` is the gate that proves these pass on Mac.
 */
import fs from 'fs'
import os from 'os'
import path from 'path'
import { spawn } from 'child_process'
import { describe, expect, it } from 'vitest'
import {
  augmentPath,
  defaultRoots,
  preferredRoots,
  shouldSkipDir,
  isCacheLocation,
} from '../electron/scanner/platform'
import { toolExtras, resolveTool } from '../electron/scanner/native'
import { osLabel } from '../electron/scanner/types'
import { folderLabel, projectKey } from '../src/shared/projectPath'

const isMac = process.platform === 'darwin'

describe.skipIf(!isMac)('macOS platform suite', () => {
  it('reports macOS platform label', () => {
    expect(process.platform).toBe('darwin')
    expect(osLabel()).toBe('macOS')
    expect(path.sep).toBe('/')
    expect(path.delimiter).toBe(':')
  })

  it('defaults to home (+ external Volumes when present)', () => {
    const roots = defaultRoots([])
    expect(roots[0]).toBe(os.homedir())
    expect(roots.every((r) => path.isAbsolute(r))).toBe(true)
    // Drive-letter mapping is Windows-only
    expect(defaultRoots(['c'])[0]).not.toBe('C:\\')
  })

  it('prefers Desktop / Documents / Developer-style folders when present', () => {
    const preferred = preferredRoots()
    expect(preferred).toContain(os.homedir())
    expect(preferred.every((p) => !/^[A-Z]:\\/.test(p))).toBe(true)
  })

  it('skips macOS system / Library / Applications trees', () => {
    expect(shouldSkipDir('/Applications/Xcode.app', 'Xcode.app')).toBe(true)
    expect(shouldSkipDir('/Library/Caches', 'Caches')).toBe(true)
    expect(shouldSkipDir('/Users/me/Library/Application Support', 'Application Support')).toBe(true)
    expect(shouldSkipDir('/Users/me/.Trash', '.Trash')).toBe(true)
    expect(shouldSkipDir('/Users/me/Desktop/BrainPet', 'BrainPet')).toBe(false)
  })

  it('detects macOS npm / yarn cache path shapes', () => {
    const home = os.homedir()
    expect(isCacheLocation('npm-audit', `${home}/.npm/_cacache/index-v5/ab`)).toBe(true)
    expect(isCacheLocation('cache:yarn-cache', `${home}/Library/Caches/Yarn/v6/npm-lodash`)).toBe(true)
    expect(folderLabel(`${home}/.npm/_cacache/index-v5/02/43eb57`, '', true)).toBe('npm cache')
    expect(projectKey(`${home}/Desktop/BrainPet/package.json`)).toBe(`${home}/Desktop/BrainPet`)
  })

  it('augments PATH with Homebrew / local tool dirs (no-op for missing dirs)', () => {
    const before = process.env.PATH || ''
    augmentPath()
    const after = process.env.PATH || ''
    expect(after.length).toBeGreaterThanOrEqual(before.length)
    // Common Mac locations should be considered when they exist on the machine
    for (const p of ['/opt/homebrew/bin', '/usr/local/bin']) {
      if (fs.existsSync(p)) expect(after.split(':')).toContain(p)
    }
  })

  it('resolves macOS tool lookup candidates (Homebrew / nvm)', () => {
    const extras = toolExtras()
    expect(extras.npm?.some((p) => p.includes('homebrew') || p.includes('/usr/local') || p.includes('.nvm'))).toBe(
      true
    )
    expect(extras.python3?.some((p) => p.includes('python3'))).toBe(true)

    const node = resolveTool('node') || process.execPath
    expect(node).toBeTruthy()
    expect(fs.existsSync(node)).toBe(true)
  })

  it('CLI smoke: scanner reports macOS and finishes SUCCESS', async () => {
    const repoRoot = path.resolve(__dirname, '..')
    const scannerJs = path.join(repoRoot, 'out', 'main', 'scanner.js')
    if (!fs.existsSync(scannerJs)) {
      await new Promise<void>((resolve, reject) => {
        const b = spawn('npm', ['run', 'build'], { cwd: repoRoot, shell: true })
        b.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`build failed: ${code}`))))
      })
    }

    const fixture = path.join(repoRoot, 'tests', 'fixtures', 'sample-npm')
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vuln-mac-'))
    const result = await new Promise<{ code: number; stdout: string }>((resolve) => {
      const child = spawn(
        process.execPath,
        [
          scannerJs,
          '--gui',
          '--no-open',
          '--skip-cache',
          '--output-dir',
          out,
          '--drive',
          fixture,
          '--max-projects',
          '5',
        ],
        { cwd: repoRoot, env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' } }
      )
      let stdout = ''
      child.stdout.on('data', (d) => {
        stdout += d.toString()
      })
      child.on('close', (code) => resolve({ code: code ?? 1, stdout }))
    })

    expect(result.code).toBe(0)
    expect(result.stdout).toMatch(/DONE\|SUCCESS/)
    const findings = JSON.parse(fs.readFileSync(path.join(out, 'findings.json'), 'utf8'))
    expect(findings.platform).toBe('macOS')
    fs.rmSync(out, { recursive: true, force: true })
  }, 120_000)
})
