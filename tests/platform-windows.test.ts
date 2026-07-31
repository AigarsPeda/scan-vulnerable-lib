/**
 * Windows-only suite — skipped on macOS/Linux.
 * GitHub Actions `windows-latest` is the gate that proves these pass on Win.
 */
import fs from 'fs'
import os from 'os'
import path from 'path'
import { spawn } from 'child_process'
import { describe, expect, it } from 'vitest'
import { defaultRoots, preferredRoots, shouldSkipDir, isCacheLocation } from '../electron/scanner/platform'
import { toolExtras, resolveTool } from '../electron/scanner/native'
import { osLabel } from '../electron/scanner/types'
import { folderLabel, projectKey } from '../src/shared/projectPath'

const isWindows = process.platform === 'win32'

describe.skipIf(!isWindows)('Windows platform suite', () => {
  it('reports Windows platform label', () => {
    expect(process.platform).toBe('win32')
    expect(osLabel()).toBe('Windows')
    expect(path.sep).toBe('\\')
    expect(path.delimiter).toBe(';')
  })

  it('maps drive letters and discovers existing drives', () => {
    expect(defaultRoots(['c'])).toEqual(['C:\\'])
    expect(defaultRoots(['D'])).toEqual(['D:\\'])

    const roots = defaultRoots([])
    expect(roots.length).toBeGreaterThan(0)
    expect(roots.some((r) => /^[A-Z]:\\$/.test(r))).toBe(true)
    expect(fs.existsSync(roots[0])).toBe(true)
  })

  it('prefers user folders and Windows project roots when present', () => {
    const preferred = preferredRoots()
    expect(preferred.length).toBeGreaterThan(0)
    expect(preferred.every((p) => path.isAbsolute(p))).toBe(true)
    // Home should always exist
    expect(preferred).toContain(os.homedir())
  })

  it('skips Windows system / AppData / Program Files trees', () => {
    expect(shouldSkipDir('C:\\Windows\\System32', 'System32')).toBe(true)
    expect(shouldSkipDir('C:\\Windows', 'Windows')).toBe(true)
    expect(shouldSkipDir('C:\\Users\\me\\AppData\\Local\\Temp', 'Temp')).toBe(true)
    expect(shouldSkipDir('C:\\Program Files\\nodejs', 'nodejs')).toBe(true)
    expect(shouldSkipDir('C:\\Program Files (x86)\\dotnet', 'dotnet')).toBe(true)
    expect(shouldSkipDir('C:\\Users\\me\\source\\repos\\app', 'app')).toBe(false)
  })

  it('detects Windows npm / NuGet cache path shapes', () => {
    const local = process.env.LOCALAPPDATA || 'C:\\Users\\me\\AppData\\Local'
    expect(isCacheLocation('npm-audit', `${local}\\npm-cache\\_cacache\\index-v5\\ab`)).toBe(true)
    expect(isCacheLocation('cache:nuget', 'C:\\Users\\me\\.nuget\\packages\\newtonsoft.json')).toBe(true)
    expect(folderLabel(`${local}\\npm-cache\\_cacache\\index-v5\\02\\43eb57`, '', true)).toBe(
      'npm cache'
    )
    expect(
      projectKey('C:\\Users\\me\\Projects\\dentsu_next\\package.json')
    ).toBe('C:\\Users\\me\\Projects\\dentsu_next')
  })

  it('resolves Windows tool lookup candidates (.cmd / Program Files)', () => {
    const extras = toolExtras()
    expect(extras.npm?.some((p) => /npm\.cmd$/i.test(p))).toBe(true)
    expect(extras.dotnet?.some((p) => /dotnet\.exe$/i.test(p))).toBe(true)
    expect(extras.yarn?.some((p) => /yarn\.cmd$/i.test(p) || /Yarn/i.test(p))).toBe(true)

    // node should be available on CI / developer machines
    const node = resolveTool('node') || process.execPath
    expect(node).toBeTruthy()
    expect(fs.existsSync(node)).toBe(true)
  })

  it('exposes LOCALAPPDATA / APPDATA for cache discovery', () => {
    expect(process.env.LOCALAPPDATA || process.env.APPDATA).toBeTruthy()
  })

  it('CLI smoke: scanner reports Windows and finishes SUCCESS', async () => {
    const repoRoot = path.resolve(__dirname, '..')
    const scannerJs = path.join(repoRoot, 'out', 'main', 'scanner.js')
    if (!fs.existsSync(scannerJs)) {
      await new Promise<void>((resolve, reject) => {
        const b = spawn('npm', ['run', 'build'], { cwd: repoRoot, shell: true })
        b.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`build failed: ${code}`))))
      })
    }

    const fixture = path.join(repoRoot, 'tests', 'fixtures', 'sample-npm')
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vuln-win-'))
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
    expect(findings.platform).toBe('Windows')
    fs.rmSync(out, { recursive: true, force: true })
  }, 120_000)
})
