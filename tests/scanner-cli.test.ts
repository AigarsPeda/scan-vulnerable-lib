import { spawn } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { describe, expect, it } from 'vitest'

const repoRoot = path.resolve(__dirname, '..')
const scannerJs = path.join(repoRoot, 'out', 'main', 'scanner.js')
const fixture = path.join(repoRoot, 'tests', 'fixtures', 'sample-npm')

function runScanner(args: string[], timeoutMs = 90_000): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [scannerJs, ...args], {
      cwd: repoRoot,
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
    })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => {
      child.kill('SIGTERM')
    }, timeoutMs)
    child.stdout.on('data', (d) => {
      stdout += d.toString()
    })
    child.stderr.on('data', (d) => {
      stderr += d.toString()
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve({ code: code ?? 1, stdout, stderr })
    })
  })
}

describe('packaged scanner CLI smoke', () => {
  it('runs against a fixture folder and writes findings/report', async () => {
    if (!fs.existsSync(scannerJs)) {
      // Build once so CI / local `npm test` can rely on out/main/scanner.js
      await new Promise<void>((resolve, reject) => {
        const b = spawn('npm', ['run', 'build'], { cwd: repoRoot, shell: true })
        b.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`build failed: ${code}`))))
      })
    }
    expect(fs.existsSync(scannerJs)).toBe(true)

    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vuln-cli-'))
    const result = await runScanner([
      '--gui',
      '--no-open',
      '--skip-cache',
      '--output-dir',
      out,
      '--drive',
      fixture,
      '--max-projects',
      '5',
    ])

    expect(result.code).toBe(0)
    expect(result.stdout).toMatch(/DONE\|SUCCESS/)
    expect(fs.existsSync(path.join(out, 'findings.json'))).toBe(true)
    expect(fs.existsSync(path.join(out, 'vulnerable-libs-report.html'))).toBe(true)

    const findings = JSON.parse(fs.readFileSync(path.join(out, 'findings.json'), 'utf8'))
    expect(String(findings.platform || '')).toMatch(/macOS|Windows|Linux|darwin|win32/i)
    expect(Array.isArray(findings.findings)).toBe(true)
    // Fixture pins known-vulnerable packages; OSV should return ≥1 finding when online.
    if (findings.findings.length > 0) {
      for (const f of findings.findings) {
        expect(path.basename(String(f.Path || ''))).not.toMatch(
          /package\.json|requirements\.txt|package-lock\.json/i
        )
      }
    }

    fs.rmSync(out, { recursive: true, force: true })
  })
})
