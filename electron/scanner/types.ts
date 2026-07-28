import path from 'path'
import os from 'os'
import fs from 'fs'

export type ScanArgs = {
  gui: boolean
  noOpen: boolean
  highOnly: boolean
  skipCache: boolean
  skipOsv: boolean
  maxProjects: number
  outputDir: string
  roots: string[]
}

export type Finding = {
  Ecosystem: string
  Source: string
  Severity: string
  Package: string
  Version: string
  Title: string
  Advisory: string
  Path: string
  Fix: string
  HasFix: boolean
  IsCache: boolean
}

export type OsvQueueItem = {
  ecoLabel: string
  osvEco: string
  package: string
  version: string
  path: string
  source: string
}

export type LangHint = {
  eco: string
  manifestNames: string[]
  manifestExt: string[]
  sourceExt: string[]
}

export const LANG_HINTS: Record<string, LangHint> = {
  'JavaScript/TypeScript': {
    eco: 'npm',
    manifestNames: ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
    manifestExt: [],
    sourceExt: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'],
  },
  'C#/.NET': {
    eco: 'nuget',
    manifestNames: ['packages.config', 'Directory.Packages.props'],
    manifestExt: ['.csproj', '.fsproj', '.vbproj', '.sln'],
    sourceExt: ['.cs', '.fs'],
  },
  Python: {
    eco: 'PyPI',
    manifestNames: [
      'requirements.txt',
      'Pipfile',
      'Pipfile.lock',
      'pyproject.toml',
      'poetry.lock',
      'environment.yml',
    ],
    manifestExt: [],
    sourceExt: ['.py'],
  },
  'Java/Kotlin': {
    eco: 'Maven',
    manifestNames: ['pom.xml', 'build.gradle', 'build.gradle.kts'],
    manifestExt: [],
    sourceExt: ['.java', '.kt'],
  },
  Go: {
    eco: 'Go',
    manifestNames: ['go.mod', 'go.sum'],
    manifestExt: [],
    sourceExt: ['.go'],
  },
  Rust: {
    eco: 'crates.io',
    manifestNames: ['Cargo.toml', 'Cargo.lock'],
    manifestExt: [],
    sourceExt: ['.rs'],
  },
  PHP: {
    eco: 'Packagist',
    manifestNames: ['composer.json', 'composer.lock'],
    manifestExt: [],
    sourceExt: ['.php'],
  },
  Ruby: {
    eco: 'RubyGems',
    manifestNames: ['Gemfile', 'Gemfile.lock'],
    manifestExt: [],
    sourceExt: ['.rb'],
  },
  'Dart/Flutter': {
    eco: 'Pub',
    manifestNames: ['pubspec.yaml', 'pubspec.lock'],
    manifestExt: [],
    sourceExt: ['.dart'],
  },
  Swift: {
    eco: 'Swift',
    manifestNames: ['Package.swift', 'Package.resolved'],
    manifestExt: [],
    sourceExt: ['.swift'],
  },
  Scala: {
    eco: 'Scala',
    manifestNames: ['build.sbt', 'plugins.sbt'],
    manifestExt: [],
    sourceExt: ['.scala', '.sc'],
  },
}

export function parseArgs(argv: string[]): ScanArgs {
  const args: ScanArgs = {
    gui: false,
    noOpen: false,
    highOnly: false,
    skipCache: false,
    skipOsv: false,
    maxProjects: 80,
    outputDir: '',
    roots: [],
  }

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--gui' || a === '-GuiMode') args.gui = true
    else if (a === '--no-open' || a === '-NoOpen') args.noOpen = true
    else if (a === '--high-only' || a === '-HighOnly') args.highOnly = true
    else if (a === '--skip-cache' || a === '-SkipCache') args.skipCache = true
    else if (a === '--skip-osv' || a === '-SkipOsv') args.skipOsv = true
    else if ((a === '--max-projects' || a === '-MaxProjectsPerEco') && argv[i + 1]) {
      args.maxProjects = Math.max(1, Number(argv[++i]) || 80)
    } else if ((a === '--output-dir' || a === '-OutputDir') && argv[i + 1]) {
      args.outputDir = argv[++i]
    } else if ((a === '--drive' || a === '-Drive') && argv[i + 1]) {
      args.roots.push(argv[++i])
    } else if (a.startsWith('--drive=')) {
      args.roots.push(a.slice('--drive='.length))
    }
  }
  return args
}

export function resolveOutputDir(args: ScanArgs): string {
  if (args.outputDir) {
    fs.mkdirSync(args.outputDir, { recursive: true })
    return args.outputDir
  }
  const desktop = path.join(os.homedir(), 'Desktop')
  return fs.existsSync(desktop) ? desktop : os.homedir()
}

export function osLabel(): string {
  if (process.platform === 'darwin') return 'macOS'
  if (process.platform === 'win32') return 'Windows'
  return process.platform
}
