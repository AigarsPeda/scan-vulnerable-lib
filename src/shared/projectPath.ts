/**
 * Shared path helpers for Report grouping / project dropdown labels.
 * Kept pure so Mac + Windows behavior can be unit-tested without Electron.
 */

const MANIFEST_BASENAMES = new Set(
  [
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'requirements.txt',
    'pipfile',
    'pipfile.lock',
    'pyproject.toml',
    'poetry.lock',
    'environment.yml',
    'packages.config',
    'directory.packages.props',
    'pom.xml',
    'build.gradle',
    'build.gradle.kts',
    'go.mod',
    'go.sum',
    'cargo.toml',
    'cargo.lock',
    'composer.json',
    'composer.lock',
    'gemfile',
    'gemfile.lock',
    'pubspec.yaml',
    'pubspec.lock',
    'package.swift',
    'package.resolved',
    'build.sbt',
    'plugins.sbt',
  ].map((s) => s.toLowerCase())
)

const MANIFEST_EXTS = new Set(['.csproj', '.fsproj', '.vbproj', '.sln'])

/**
 * npm/_cacache stores packages under content-addressable hashes. Without collapsing
 * those paths, Windows reports show dozens of "projects" named like 0243eb57….
 */
export function cacheBucket(
  pathValue: string,
  source = '',
  isCache = false
): { key: string; name: string } | null {
  const src = (source || '').trim().toLowerCase()
  if (src === 'cache:npm-cache' || src === 'cache:npm') {
    return { key: 'cache:npm-cache', name: 'npm cache' }
  }
  if (src === 'cache:yarn-cache' || src === 'cache:yarn') {
    return { key: 'cache:yarn-cache', name: 'yarn cache' }
  }
  if (src === 'cache:nuget' || src === 'cache:nuget-cache') {
    return { key: 'cache:nuget', name: 'NuGet cache' }
  }
  if (/^cache:/i.test(src)) {
    const kind = src.slice('cache:'.length) || 'package'
    return { key: src, name: `${kind} cache` }
  }

  const p = (pathValue || '').replace(/\\/g, '/').toLowerCase()
  const base = p.split('/').filter(Boolean).pop() || ''
  const hashLike = /^[a-f0-9]{32,}$/i.test(base)
  const looksCache =
    isCache ||
    hashLike ||
    p.includes('/_cacache/') ||
    p.includes('/npm-cache') ||
    p.includes('/.npm/') ||
    p.includes('/yarn/cache') ||
    p.includes('/berry/cache') ||
    p.includes('/.nuget/packages')

  if (!looksCache) return null

  if (p.includes('/_cacache/') || p.includes('/npm-cache') || p.includes('/.npm/')) {
    return { key: 'cache:npm-cache', name: 'npm cache' }
  }
  if (p.includes('/yarn/') || p.includes('/berry/cache')) {
    return { key: 'cache:yarn-cache', name: 'yarn cache' }
  }
  if (p.includes('/.nuget/packages')) {
    return { key: 'cache:nuget', name: 'NuGet cache' }
  }
  if (isCache || hashLike) {
    return { key: 'cache:package', name: 'Package cache' }
  }
  return null
}

/** Prefer project folder name over manifest filename (package.json, requirements.txt, …). */
export function folderLabel(pathValue: string, source = '', isCache = false): string {
  const cache = cacheBucket(pathValue, source, isCache)
  if (cache) return cache.name
  if (!pathValue) return '(unknown)'
  const parts = pathValue.replace(/\\/g, '/').split('/').filter(Boolean)
  if (!parts.length) return pathValue
  let i = parts.length - 1
  const last = parts[i]
  const lower = last.toLowerCase()
  if (MANIFEST_BASENAMES.has(lower) || [...MANIFEST_EXTS].some((ext) => lower.endsWith(ext))) {
    i -= 1
  }
  return parts[i] || last || pathValue
}

/** Normalize finding path to project folder when it points at a manifest file. */
export function projectKey(pathValue: string, source = '', isCache = false): string {
  const cache = cacheBucket(pathValue, source, isCache)
  if (cache) return cache.key
  if (!pathValue || pathValue === '(unknown)') return pathValue || '(unknown)'
  const normalized = pathValue.replace(/\\/g, '/')
  const parts = normalized.split('/').filter(Boolean)
  if (!parts.length) return pathValue
  const last = parts[parts.length - 1]
  const lower = last.toLowerCase()
  if (MANIFEST_BASENAMES.has(lower) || [...MANIFEST_EXTS].some((ext) => lower.endsWith(ext))) {
    const parent = normalized.slice(0, normalized.length - last.length - 1)
    if (pathValue.includes('\\')) return parent.replace(/\//g, '\\')
    return parent || pathValue
  }
  return pathValue
}
