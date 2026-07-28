# Vulnerable Library Scanner (Electron)

One GUI for **Windows and macOS**. React + TypeScript UI (electron-vite) that runs the shared PowerShell scanner.

## Requirements

- [Node.js](https://nodejs.org/) 18+
- **Windows:** PowerShell 5.1+ (or PowerShell 7 `pwsh` — parallel project audits need PS7+)
- **macOS:** [PowerShell 7](https://aka.ms/powershell) (`pwsh`)

## Install

```bash
cd ~/Desktop/scan-vulnerable-lib   # or your path
npm install
```

## Run

```bash
npm run dev      # development (hot reload)
npm start        # preview production build
npm run build    # compile main/preload/renderer
npm run typecheck
```

## What it does

- Runs the bundled scanner: `scripts/scan-vulnerable-libs.ps1`
- Live **Progress** (percent, item counts, per-ecosystem bar, elapsed time) and streaming findings
- Native **Report** tab (not an HTML iframe) with live updates from `findings.json`
- Report filters: severity, project/cache, ecosystem, has-fix; Open / Copy path per project
- Start / Pause / Resume / Stop (Stop resets progress immediately; options stay locked while scanning)
- Working files under the **app data folder**
- **Export** JSON / TXT / CSV / Markdown / HTML (disabled while a scan is running)

### Scanner performance notes

- OSV in-memory cache, retries, and `/v1/querybatch`
- Skips OSV when a native audit already ran (npm/yarn, `dotnet list`, pip-audit)
- Finding dedupe + native-command timeouts
- On PowerShell 7+, capped parallel project audits (degree 3) for npm / NuGet / PyPI

## Options in the UI

| Option | Meaning |
|--------|---------|
| High / Critical only | Passes `-HighOnly` |
| Skip caches | Passes `-SkipCache` |
| Skip OSV API | Passes `-SkipOsv` |
| Max projects / ecosystem | Passes `-MaxProjectsPerEco` |
| Optional root folder | Passes `-Drive` |

## Project layout

```
scan-vulnerable-lib/
  electron/main/       # Electron main (TypeScript)
  electron/preload/    # Preload bridge (TypeScript)
  src/                 # React + TypeScript UI
  scripts/             # Bundled scanner (.ps1) for Win + Mac
  assets/              # App icon
  package.json
```

## Notes

- On macOS install PowerShell 7 (`pwsh`) via https://aka.ms/powershell
- Working files live under the Electron app data folder (`findings.json`, progress, etc.)
- Standalone script still supports Desktop output when run without `-GuiMode`
