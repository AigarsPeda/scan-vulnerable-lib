import fs from 'fs'
import os from 'os'
import path from 'path'

const SKIP_DIR_NAMES = new Set(
  [
    'Windows',
    'WinSxS',
    '$Recycle.Bin',
    'System Volume Information',
    'Recovery',
    'PerfLogs',
    'Windows.old',
    'node_modules',
    '.git',
    'bin',
    'obj',
    '.vs',
    '.idea',
    'INetCache',
    'Temporary Internet Files',
    'Chrome',
    'Edge',
    'Firefox',
    'BraveSoftware',
    'Opera Software',
    'AppData',
    '.cursor',
    '.vscode',
    '.nuget',
    '.npm',
    '.yarn',
    '.cache',
    '.codex',
    '.claude',
    '.agents',
    '.gemini',
    '.copilot',
    '.codemoss',
    'extensions',
    'Program Files',
    'Program Files (x86)',
    'ProgramData',
    'Temp',
    'Packages',
    'Package Cache',
    'Microsoft',
    'WindowsApps',
    'Intel',
    'AMD',
    'NVIDIA Corporation',
    'Common Files',
    'Applications',
    'Library',
    'System',
    'private',
    'cores',
    '.Trash',
    'Caches',
    'Containers',
    'Group Containers',
    'Photos Library.photoslibrary',
    'Mail',
    'Messages',
    'iCloud Drive (Archive)',
  ].map((s) => s.toLowerCase())
)

const SKIP_PATH_RE =
  /([\\/](Windows|WinSxS|\$Recycle\.Bin|System Volume Information|Recovery|PerfLogs|Windows\.old|Google[\\/]Chrome|Microsoft[\\/]Edge|Mozilla[\\/]Firefox|BraveSoftware|Opera Software|INetCache|node_modules[\\/]\.cache|AppData|Program Files|Program Files \(x86\)|ProgramData|Applications|Library|System|private|cores|\.Trash|Volumes[\\/]com\.apple|Time Machine|Backups\.backupdb|\.(cursor|vscode|git|nuget|npm|yarn|cache|codex|claude|agents|gemini|copilot)|Temp|Packages|Package Cache)([\\/]|$))/i

export function augmentPath(): void {
  if (process.platform === 'win32') return
  const extras = [
    '/opt/homebrew/bin',
    '/opt/homebrew/sbin',
    '/usr/local/bin',
    '/usr/local/sbin',
    path.join(os.homedir(), '.dotnet', 'tools'),
    path.join(os.homedir(), '.cargo', 'bin'),
    path.join(os.homedir(), 'go', 'bin'),
    '/usr/local/share/dotnet',
  ]
  const current = (process.env.PATH || '').split(path.delimiter).filter(Boolean)
  const merged = [...extras.filter((p) => fs.existsSync(p) && !current.includes(p)), ...current]
  process.env.PATH = merged.join(path.delimiter)
}

export function shouldSkipDir(fullName: string, name: string): boolean {
  if (SKIP_DIR_NAMES.has(name.toLowerCase())) return true
  if (SKIP_PATH_RE.test(fullName)) return true
  if (/[\\/](\.cursor|\.vscode)[\\/]extensions[\\/]/i.test(fullName)) return true
  if (/[\\/]\.nuget[\\/]packages[\\/]/i.test(fullName)) return true
  return false
}

export function defaultRoots(explicit: string[]): string[] {
  if (explicit.length) {
    return explicit.map((r) => {
      if (process.platform === 'win32' && /^[A-Za-z]$/.test(r)) return `${r.toUpperCase()}:\\`
      return path.resolve(r)
    })
  }

  const home = os.homedir()
  if (process.platform === 'darwin') {
    const roots = [home]
    const volumes = '/Volumes'
    if (fs.existsSync(volumes)) {
      for (const name of fs.readdirSync(volumes)) {
        if (/^(Macintosh HD|com\.apple)/i.test(name)) continue
        const p = path.join(volumes, name)
        try {
          if (fs.statSync(p).isDirectory()) roots.push(p)
        } catch {
          /* ignore */
        }
      }
    }
    return roots
  }

  // Windows: common drive letters that exist
  const drives: string[] = []
  for (const letter of 'CDEFGHIJKLMNOPQRSTUVWXYZ') {
    const root = `${letter}:\\`
    try {
      if (fs.existsSync(root)) drives.push(root)
    } catch {
      /* ignore */
    }
  }
  return drives.length ? drives : [home]
}

export function preferredRoots(): string[] {
  const home = os.homedir()
  const candidates = [
    home,
    path.join(home, 'Desktop'),
    path.join(home, 'Documents'),
    path.join(home, 'Downloads'),
    path.join(home, 'source'),
    path.join(home, 'src'),
    path.join(home, 'Projects'),
    path.join(home, 'Developer'),
    path.join(home, 'repos'),
    path.join(home, 'code'),
  ]
  if (process.platform === 'win32') {
    candidates.push('C:\\GeoWeb2', 'C:\\Projects', 'C:\\Dev', 'C:\\src', 'C:\\Repos')
  }
  return [...new Set(candidates.filter((p) => p && fs.existsSync(p)))]
}

export function isCacheLocation(source: string, filePath: string): boolean {
  if (/^cache:/i.test(source)) return true
  const p = filePath.replace(/\\/g, '/').toLowerCase()
  return (
    p.includes('/.npm/') ||
    p.includes('/npm-cache') ||
    p.includes('/.yarn/') ||
    p.includes('/yarn/cache') ||
    p.includes('/.nuget/packages') ||
    p.includes('/pip/cache') ||
    p.includes('/pypoetry/')
  )
}
