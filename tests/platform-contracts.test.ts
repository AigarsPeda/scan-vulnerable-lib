/**
 * Platform contract tests — run on every OS.
 * They mock `process.platform` so Mac CI still validates Windows branching
 * (and Windows CI validates Mac branching) without needing the other host.
 */
import path from 'path'
import { describe, expect, it } from 'vitest'
import { withPlatform } from './helpers/platform'
import { osLabel } from '../electron/scanner/types'
import { folderLabel, projectKey, cacheBucket } from '../src/shared/projectPath'
import { toolExtras } from '../electron/scanner/native'
import { defaultRoots, preferredRoots } from '../electron/scanner/platform'

describe('Windows contracts (mocked platform)', () => {
  it('osLabel → Windows', () => {
    withPlatform('win32', () => {
      expect(osLabel()).toBe('Windows')
    })
  })

  it('drive letter → C:\\', () => {
    withPlatform('win32', () => {
      expect(defaultRoots(['c'])).toEqual(['C:\\'])
      expect(defaultRoots(['e'])).toEqual(['E:\\'])
    })
  })

  it('toolExtras lists Windows npm.cmd / dotnet.exe candidates', () => {
    withPlatform('win32', () => {
      const extras = toolExtras()
      expect(extras.npm?.some((p) => /npm\.cmd$/i.test(p))).toBe(true)
      expect(extras.dotnet?.some((p) => /dotnet\.exe$/i.test(p))).toBe(true)
      expect(extras.python3).toBeUndefined()
    })
  })

  it('preferredRoots returns absolute paths under Windows mode', () => {
    withPlatform('win32', () => {
      const roots = preferredRoots()
      expect(Array.isArray(roots)).toBe(true)
      expect(roots.every((r) => path.win32.isAbsolute(r) || path.posix.isAbsolute(r))).toBe(true)
    })
  })

  it('UI helpers keep Windows backslash project keys', () => {
    expect(folderLabel('C:\\Users\\me\\Projects\\api\\package.json')).toBe('api')
    expect(projectKey('C:\\Users\\me\\Projects\\api\\requirements.txt')).toBe(
      'C:\\Users\\me\\Projects\\api'
    )
    expect(
      cacheBucket(
        'C:\\Users\\me\\AppData\\Local\\npm-cache\\_cacache\\index-v5\\02\\43eb57abcdef',
        '',
        true
      )?.name
    ).toBe('npm cache')
  })
})

describe('macOS contracts (mocked platform)', () => {
  it('osLabel → macOS', () => {
    withPlatform('darwin', () => {
      expect(osLabel()).toBe('macOS')
    })
  })

  it('does not treat bare "c" as a Windows drive', () => {
    withPlatform('darwin', () => {
      const roots = defaultRoots(['c'])
      expect(roots).toHaveLength(1)
      expect(roots[0]).not.toBe('C:\\')
      expect(path.isAbsolute(roots[0])).toBe(true)
    })
  })

  it('toolExtras lists Homebrew / nvm style candidates', () => {
    withPlatform('darwin', () => {
      const extras = toolExtras()
      expect(extras.npm?.some((p) => /homebrew|\/usr\/local|\.nvm/.test(p))).toBe(true)
      expect(extras.python3?.length).toBeGreaterThan(0)
      expect(extras.npm?.every((p) => !/\.cmd$/i.test(p))).toBe(true)
    })
  })

  it('UI helpers keep POSIX project keys', () => {
    expect(folderLabel('/Users/me/Desktop/BrainPet/package.json')).toBe('BrainPet')
    expect(projectKey('/Users/me/Desktop/BrainPet/package.json')).toBe('/Users/me/Desktop/BrainPet')
    expect(cacheBucket('/Users/me/.npm/_cacache/index-v5/ab/cd', '', true)?.name).toBe('npm cache')
  })
})
