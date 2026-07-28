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

- Starts `scripts/scan-vulnerable-libs.ps1` with options from the UI
- Streams live console output
- Opens `~/Desktop/vulnerable-libs-report.html` when the scan finishes

## Options in the UI

| Option | Meaning |
|--------|---------|
| High / Critical only | Passes `-HighOnly` |
| Skip package caches | Passes `-SkipCache` |
| Skip OSV API fallback | Passes `-SkipOsv` |
| Max projects per ecosystem | Passes `-MaxProjectsPerEco` |
| Optional root path / drive | Passes `-Drive` (folder or Windows drive letter) |

## Project layout

```
scan-vulnerable-lib/
  electron/          # Electron main + preload
  src/               # UI (HTML/CSS/JS)
  scripts/           # Shared scanner (.ps1) for Win + Mac
  package.json
```

## Notes

- Keep `scripts/scan-vulnerable-libs.ps1` in sync if you change the Desktop copy.
- On macOS the app looks for `pwsh` on your PATH (Homebrew install recommended).
