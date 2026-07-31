import { describe, expect, it } from 'vitest'
import { cacheBucket, folderLabel, projectKey } from '../src/shared/projectPath'

describe('projectPath helpers (Win + Mac)', () => {
  it('labels project folders, not package.json', () => {
    expect(folderLabel('/Users/me/Desktop/BrainPet/package.json')).toBe('BrainPet')
    expect(folderLabel('C:\\Users\\me\\Projects\\dentsu_next\\package.json')).toBe('dentsu_next')
    expect(folderLabel('/Users/me/code/api/requirements.txt')).toBe('api')
  })

  it('projectKey strips manifests and preserves Windows separators', () => {
    expect(projectKey('/Users/me/Desktop/BrainPet/package.json')).toBe('/Users/me/Desktop/BrainPet')
    expect(projectKey('C:\\Users\\me\\Projects\\app\\requirements.txt')).toBe(
      'C:\\Users\\me\\Projects\\app'
    )
    expect(projectKey('/Users/me/Desktop/BrainPet')).toBe('/Users/me/Desktop/BrainPet')
  })

  it('collapses npm cache hash paths into one bucket', () => {
    const winCache =
      'C:\\Users\\me\\AppData\\Local\\npm-cache\\_cacache\\index-v5\\02\\43eb57abcdef0123456789abcdef0123456789'
    expect(folderLabel(winCache, '', true)).toBe('npm cache')
    expect(projectKey(winCache, 'cache:npm-cache', true)).toBe('cache:npm-cache')
    expect(cacheBucket(winCache, '', true)?.name).toBe('npm cache')
  })

  it('uses source cache tags when present', () => {
    expect(folderLabel('/tmp/anything', 'cache:yarn-cache', false)).toBe('yarn cache')
    expect(projectKey('/tmp/anything', 'cache:nuget', true)).toBe('cache:nuget')
  })
})
