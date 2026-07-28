import { spawn } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'

const DEFAULT_TIMEOUT_MS = 300_000

export function which(name: string, extras: string[] = []): string | null {
  for (const p of extras) {
    if (p && fs.existsSync(p)) return p
  }
  const pathEnv = process.env.PATH || ''
  const exts =
    process.platform === 'win32'
      ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean)
      : ['']
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue
    for (const ext of exts) {
      const candidate = path.join(dir, process.platform === 'win32' ? name + ext : name)
      try {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate
      } catch {
        /* ignore */
      }
    }
    // Windows: also try bare name without forcing ext when file exists
    const bare = path.join(dir, name)
    if (fs.existsSync(bare)) return bare
  }
  return null
}

export type NativeResult = {
  code: number
  stdout: string
  stderr: string
  timedOut: boolean
}

function quoteWin(s: string): string {
  if (!/[\s"]/g.test(s)) return s
  return `"${s.replace(/"/g, '\\"')}"`
}

function resolveNodeExe(): string {
  const fromPath = which('node')
  if (fromPath) return fromPath
  if (process.platform === 'win32') {
    const pf = process.env.ProgramFiles || 'C:\\Program Files'
    const pf86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'
    for (const c of [path.join(pf, 'nodejs', 'node.exe'), path.join(pf86, 'nodejs', 'node.exe')]) {
      if (fs.existsSync(c)) return c
    }
  }
  // Packaged scanner runs under ELECTRON_RUN_AS_NODE — electron.exe can execute JS.
  return process.execPath
}

/** Prefer `node npm-cli.js` over `npm.cmd` so Windows paths with spaces work without cmd quoting bugs. */
function resolveJsCli(command: string): { exe: string; script: string } | null {
  const base = path.basename(command).toLowerCase()
  const dir = path.dirname(command)
  const pf = process.env.ProgramFiles || 'C:\\Program Files'
  if (base === 'npm.cmd' || base === 'npm') {
    const candidates = [
      path.join(dir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
      path.join(pf, 'nodejs', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    ]
    for (const script of candidates) {
      if (fs.existsSync(script)) return { exe: resolveNodeExe(), script }
    }
  }
  if (base === 'npx.cmd' || base === 'npx') {
    const candidates = [
      path.join(dir, 'node_modules', 'npm', 'bin', 'npx-cli.js'),
      path.join(pf, 'nodejs', 'node_modules', 'npm', 'bin', 'npx-cli.js'),
    ]
    for (const script of candidates) {
      if (fs.existsSync(script)) return { exe: resolveNodeExe(), script }
    }
  }
  if (base === 'yarn.cmd' || base === 'yarn') {
    const candidates = [
      path.join(dir, 'yarn.js'),
      path.join(dir, 'yarn.cjs'),
      path.join(dir, 'lib', 'cli.js'),
    ]
    for (const script of candidates) {
      if (fs.existsSync(script)) return { exe: resolveNodeExe(), script }
    }
  }
  return null
}

export function runNative(
  command: string,
  args: string[],
  opts: { cwd?: string; timeoutMs?: number; env?: NodeJS.ProcessEnv } = {}
): Promise<NativeResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const cwd = opts.cwd || process.cwd()

  let file = command
  let spawnArgs = args
  let shell = false

  if (process.platform === 'win32') {
    const lower = command.toLowerCase()
    const needsCmdShell =
      lower.endsWith('.cmd') ||
      lower.endsWith('.bat') ||
      /(^|[\\/])(npm|yarn|npx)(\.cmd)?$/i.test(command)

    if (needsCmdShell) {
      const jsCli = resolveJsCli(command)
      if (jsCli) {
        // Bypass .cmd entirely — no Program Files quoting issues.
        file = jsCli.exe
        spawnArgs = [jsCli.script, ...args]
        shell = false
      } else {
        // Single command-line string with quotes — spawn(file, args, {shell:true})
        // does NOT quote paths that contain spaces.
        file = `${quoteWin(command)} ${args.map(quoteWin).join(' ')}`
        spawnArgs = []
        shell = true
      }
    }
  }

  return new Promise((resolve) => {
    const child = spawn(file, spawnArgs, {
      cwd,
      env: {
        ...process.env,
        ...opts.env,
        // When electron.exe is used as node, keep node-mode for child scripts.
        ...(file === process.execPath ? { ELECTRON_RUN_AS_NODE: '1' } : {}),
      },
      windowsHide: true,
      shell,
    })
    let stdout = ''
    let stderr = ''
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      try {
        child.kill('SIGTERM')
      } catch {
        /* ignore */
      }
    }, timeoutMs)

    child.stdout?.on('data', (d: Buffer) => {
      stdout += d.toString('utf8')
    })
    child.stderr?.on('data', (d: Buffer) => {
      stderr += d.toString('utf8')
    })
    child.on('error', (err) => {
      clearTimeout(timer)
      resolve({ code: 1, stdout, stderr: String(err), timedOut })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve({ code: timedOut ? 124 : code ?? 1, stdout, stderr, timedOut })
    })
  })
}

export function toolExtras(): Record<string, string[]> {
  const home = os.homedir()
  if (process.platform === 'win32') {
    const pf = process.env.ProgramFiles || 'C:\\Program Files'
    const appData = process.env.APPDATA || ''
    const local = process.env.LOCALAPPDATA || ''
    return {
      npm: [path.join(pf, 'nodejs', 'npm.cmd'), path.join(appData, 'npm', 'npm.cmd')],
      yarn: [path.join(appData, 'npm', 'yarn.cmd'), path.join(local, 'Yarn', 'bin', 'yarn.cmd')],
      dotnet: [path.join(pf, 'dotnet', 'dotnet.exe')],
      python: [
        path.join(local, 'Programs', 'Python', 'Python312', 'python.exe'),
        path.join(local, 'Programs', 'Python', 'Python311', 'python.exe'),
      ],
    }
  }
  return {
    npm: ['/usr/local/bin/npm', '/opt/homebrew/bin/npm', path.join(home, '.nvm/current/bin/npm')],
    yarn: ['/usr/local/bin/yarn', '/opt/homebrew/bin/yarn'],
    dotnet: ['/usr/local/share/dotnet/dotnet', '/opt/homebrew/bin/dotnet'],
    python: ['/usr/bin/python3', '/opt/homebrew/bin/python3', '/usr/local/bin/python3'],
    python3: ['/usr/bin/python3', '/opt/homebrew/bin/python3', '/usr/local/bin/python3'],
    go: ['/opt/homebrew/bin/go', '/usr/local/go/bin/go', path.join(home, 'go/bin/go')],
    govulncheck: ['/opt/homebrew/bin/govulncheck', path.join(home, 'go/bin/govulncheck')],
    cargo: [path.join(home, '.cargo/bin/cargo'), '/opt/homebrew/bin/cargo'],
    composer: ['/opt/homebrew/bin/composer', '/usr/local/bin/composer'],
    'pip-audit': ['/opt/homebrew/bin/pip-audit', path.join(home, '.local/bin/pip-audit')],
  }
}

export function resolveTool(name: string): string | null {
  const extras = toolExtras()[name] || []
  return which(name, extras)
}
