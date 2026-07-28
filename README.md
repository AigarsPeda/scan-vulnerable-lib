# Vulnerable Library Scanner (Electron)

One GUI for **Windows and macOS**. React + TypeScript UI (electron-vite) that runs the shared PowerShell scanner.

## Requirements

- [Node.js](https://nodejs.org/) 18+
- **Windows:** PowerShell 5.1+ (or PowerShell 7 `pwsh`)
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
```

## What it does

- Runs the bundled scanner: `scripts/scan-vulnerable-libs.ps1`
- Shows live **progress**, **findings**, and status inside the app
- Start / Pause / Resume / Stop controls
- Writes working report data under the **app data folder**
- **Report** tab (HTML viewer) + **export** JSON / TXT / CSV / Markdown / HTML

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
- Use **Open data folder** in the UI to find working report files
- Standalone script still supports Desktop output when run without `-GuiMode`
