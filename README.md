# Vulnerable Library Scanner (Electron)

One GUI for **Windows and macOS**. It runs the shared PowerShell scanner and opens the HTML report on your Desktop.

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
npm start
```

## What it does

- Runs the bundled scanner: `scripts/scan-vulnerable-libs.ps1`
- Shows a **progress bar** and status inside the app (no terminal needed)
- Writes the HTML report into the **app data folder** (not Desktop)
- Displays the **report inside the app** (Report tab)

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
  electron/          # Electron main + preload
  src/               # UI (HTML/CSS/JS)
  scripts/           # Bundled scanner (.ps1) for Win + Mac
  package.json
```

## Notes

- On macOS install PowerShell 7 (`pwsh`) via https://aka.ms/powershell
- Use **Open data folder** in the UI to find the generated report files
- Standalone script still supports Desktop output when run without `-GuiMode`