import fs from 'fs'
import os from 'os'
import path from 'path'
import { describe, expect, it } from 'vitest'
import { FindingsStore } from '../electron/scanner/findings'
import { parseArgs, resolveOutputDir } from '../electron/scanner/types'
import { defaultRoots, isCacheLocation, shouldSkipDir } from '../electron/scanner/platform'
import { groupProjects } from '../electron/scanner/walk'

describe('parseArgs', () => {
  it('parses GUI / filter flags used by Electron main', () => {
    const args = parseArgs([
      '--gui',
      '--no-open',
      '--high-only',
      '--skip-cache',
      '--skip-osv',
      '--max-projects',
      '12',
      '--output-dir',
      '/tmp/out',
      '--drive',
      '/tmp/project',
    ])
    expect(args).toMatchObject({
      gui: true,
      noOpen: true,
      highOnly: true,
      skipCache: true,
      skipOsv: true,
      maxProjects: 12,
      outputDir: '/tmp/out',
      roots: ['/tmp/project'],
    })
  })
})

describe('defaultRoots', () => {
  it('resolves an explicit folder to an absolute path', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vuln-root-'))
    const roots = defaultRoots([dir])
    expect(roots).toEqual([path.resolve(dir)])
    fs.rmSync(dir, { recursive: true, force: true })
  })

  it('maps a single drive letter on Windows only', () => {
    const roots = defaultRoots(['c'])
    if (process.platform === 'win32') {
      expect(roots).toEqual(['C:\\'])
    } else {
      expect(roots[0]).toContain('c')
    }
  })
})

describe('shouldSkipDir / isCacheLocation', () => {
  it('skips node_modules and .git on both platforms', () => {
    expect(shouldSkipDir('/a/node_modules', 'node_modules')).toBe(true)
    expect(shouldSkipDir('C:\\a\\.git', '.git')).toBe(true)
  })

  it('detects cache locations with either slash style', () => {
    expect(isCacheLocation('cache:npm-cache', '/tmp/x')).toBe(true)
    expect(isCacheLocation('npm-audit', '/Users/me/.npm/_cacache/index')).toBe(true)
    expect(isCacheLocation('npm-audit', 'C:\\Users\\me\\AppData\\Local\\npm-cache\\x')).toBe(true)
  })
})

describe('FindingsStore', () => {
  it('dedupes, maps moderate→medium, and respects highOnly', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vuln-findings-'))
    const store = new FindingsStore(path.join(dir, 'findings.json'), 'test', false, false)
    store.add({
      Ecosystem: 'npm',
      Source: 'npm-audit',
      Severity: 'moderate',
      Package: 'left-pad',
      Version: '1.0.0',
      Title: 'demo',
      Advisory: 'GHSA-1',
      Path: '/proj',
      Fix: 'Upgrade',
    })
    store.add({
      Ecosystem: 'npm',
      Source: 'npm-audit',
      Severity: 'medium',
      Package: 'left-pad',
      Version: '1.0.0',
      Title: 'demo',
      Advisory: 'GHSA-1',
      Path: '/proj',
      Fix: 'Upgrade',
    })
    expect(store.items).toHaveLength(1)
    expect(store.items[0].Severity).toBe('medium')

    const highOnly = new FindingsStore(path.join(dir, 'findings2.json'), 'test', true, false)
    highOnly.add({
      Ecosystem: 'npm',
      Source: 't',
      Severity: 'low',
      Package: 'x',
      Version: '1',
      Title: 't',
      Advisory: '',
      Path: '/p',
      Fix: '',
    })
    highOnly.add({
      Ecosystem: 'npm',
      Source: 't',
      Severity: 'critical',
      Package: 'y',
      Version: '1',
      Title: 't',
      Advisory: '',
      Path: '/p',
      Fix: 'fix',
    })
    expect(highOnly.items).toHaveLength(1)
    expect(highOnly.items[0].Package).toBe('y')

    store.writeFile()
    const raw = JSON.parse(fs.readFileSync(path.join(dir, 'findings.json'), 'utf8'))
    expect(raw.count).toBe(1)
    expect(raw.platform).toBe('test')
    fs.rmSync(dir, { recursive: true, force: true })
  })
})

describe('groupProjects', () => {
  it('caps projects per ecosystem and prefers shallower dirs', () => {
    const detected = {
      'JavaScript/TypeScript': {
        eco: 'npm',
        manifests: [
          '/a/deep/nested/app/package.json',
          '/a/app/package.json',
          '/a/other/package.json',
        ],
      },
    }
    const projects = groupProjects(detected, 2)
    expect(projects.npm).toHaveLength(2)
    expect(projects.npm[0]).toBe('/a/app')
    expect(projects.npm).toContain('/a/other')
  })
})

describe('resolveOutputDir', () => {
  it('creates an explicit output directory', () => {
    const dir = path.join(os.tmpdir(), `vuln-out-${Date.now()}`)
    const resolved = resolveOutputDir({
      gui: true,
      noOpen: true,
      highOnly: false,
      skipCache: true,
      skipOsv: true,
      maxProjects: 10,
      outputDir: dir,
      roots: [],
    })
    expect(resolved).toBe(dir)
    expect(fs.existsSync(dir)).toBe(true)
    fs.rmSync(dir, { recursive: true, force: true })
  })
})
