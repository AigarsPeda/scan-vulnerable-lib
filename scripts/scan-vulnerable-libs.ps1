# =============================================================================
# Multi-language vulnerable library scanner (Windows + macOS)
# =============================================================================
# 1) Detects languages/ecosystems on disk (C#, TS/JS, Python, Java, Go, Rust, PHP, Ruby, Dart, Swift, Scala)
# 2) Finds projects + dependency manifests for those ecosystems
# 3) Checks libraries (native audit tools when available, else OSV API)
# 4) Checks package-manager caches
# 5) Shows live progress (so it never looks frozen)
# 6) Notifies you when finished and opens a Desktop report
#
# Run:
#   Windows:  powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Desktop\scan-vulnerable-libs.ps1"
#   macOS:    pwsh -File "$HOME/Desktop/scan-vulnerable-libs.ps1"
#             (install PowerShell 7 if needed: https://aka.ms/powershell)
#
# Options:
#   -Drive C                 (Windows drive letter, or any absolute path on either OS)
#   -MaxProjectsPerEco 80
#   -HighOnly
#   -SkipCache
#   -SkipOsv
# =============================================================================

param(
  [string[]]$Drive = @(),
  [int]$MaxProjectsPerEco = 80,
  [switch]$HighOnly,
  [switch]$SkipCache,
  [switch]$SkipOsv,
  [string]$OutputDir = '',
  [switch]$GuiMode,
  [switch]$NoOpen
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'   # hide PS progress bar (it breaks single-line UI)

# -------------------- Platform (auto: Windows / macOS) --------------------
if ($PSVersionTable.PSVersion.Major -ge 6) {
  $script:IsWin = [bool]$IsWindows
  $script:IsMac = [bool]$IsMacOS
} else {
  # Windows PowerShell 5.1
  $script:IsWin = $true
  $script:IsMac = $false
}
if (-not $script:IsWin -and -not $script:IsMac) {
  if ("$($PSVersionTable.OS)" -match 'Darwin') { $script:IsMac = $true }
  elseif ("$($env:OS)" -match 'Windows') { $script:IsWin = $true }
}

$script:HomeDir = if ($env:HOME) { $env:HOME } elseif ($env:USERPROFILE) { $env:USERPROFILE } else { (Get-Location).Path }
$script:TempDir = if ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP)) { $env:TEMP }
  elseif ($env:TMPDIR) { $env:TMPDIR }
  else { Join-Path $script:HomeDir 'tmp' }
if (-not (Test-Path -LiteralPath $script:TempDir)) {
  New-Item -ItemType Directory -Path $script:TempDir -Force -ErrorAction SilentlyContinue | Out-Null
}
$script:DevNull = if ($script:IsWin) { 'NUL' } else { '/dev/null' }
$script:OsLabel = if ($script:IsMac) { 'macOS' } elseif ($script:IsWin) { 'Windows' } else { 'Unix' }

if ($script:IsMac -and $PSVersionTable.PSVersion.Major -lt 6) {
  Write-Host 'On macOS this script needs PowerShell 7+.' -ForegroundColor Red
  Write-Host 'Install: https://aka.ms/powershell' -ForegroundColor Yellow
  Write-Host 'Then run:  pwsh -File "$HOME/Desktop/scan-vulnerable-libs.ps1"' -ForegroundColor Yellow
  exit 1
}

function Get-UserDesktop {
  try {
    $d = [Environment]::GetFolderPath('Desktop')
    if ($d -and (Test-Path -LiteralPath $d)) { return $d }
  } catch {}
  foreach ($c in @(
      (Join-Path $script:HomeDir 'Desktop'),
      (Join-Path $script:HomeDir 'desktop')
    )) {
    if ($c -and (Test-Path -LiteralPath $c)) { return $c }
  }
  return $script:HomeDir
}

$desktop = Get-UserDesktop
# Report location: -OutputDir (GUI/app) or Desktop (standalone)
if ($OutputDir) {
  if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
  }
  $outHtml = Join-Path $OutputDir 'vulnerable-libs-report.html'
} else {
  $outHtml = Join-Path $desktop 'vulnerable-libs-report.html'
}
$logPath = $outHtml
$script:GuiMode = [bool]$GuiMode
$script:GuiPaused = $false
$script:progressJsonPath = Join-Path (Split-Path -Parent $outHtml) 'scan-progress.json'
$script:controlJsonPath = Join-Path (Split-Path -Parent $outHtml) 'scan-control.json'
$script:findingsJsonPath = Join-Path (Split-Path -Parent $outHtml) 'findings.json'
$script:lastFindingsJsonWrite = [datetime]::MinValue
if ($script:GuiMode) {
  try {
    $utf8Ctrl = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($script:controlJsonPath, '{"action":"run"}', $utf8Ctrl)
  } catch {}
}
$script:logEntries = New-Object System.Collections.Generic.List[object]
$script:lastHtmlFlush = [datetime]::MinValue
$script:lastProgressJsonWrite = [datetime]::MinValue

# Remove old separate progress file from earlier versions (avoid confusion)
$legacyProgress = Join-Path $desktop 'vulnerable-libs-progress.html'
if ((Test-Path -LiteralPath $legacyProgress) -and ($legacyProgress -ne $outHtml)) {
  Remove-Item -LiteralPath $legacyProgress -Force -ErrorAction SilentlyContinue
}

# Skip noisy / system paths (both \ and / separators)
$skipRegex = [regex]'(?i)([\\/](Windows|WinSxS|\$Recycle\.Bin|System Volume Information|Recovery|PerfLogs|Windows\.old|Google[\\/]Chrome|Microsoft[\\/]Edge|Mozilla[\\/]Firefox|BraveSoftware|Opera Software|INetCache|node_modules[\\/]\.cache|AppData|Program Files|Program Files \(x86\)|ProgramData|Applications|Library|System|private|cores|\.Trash|Volumes[\\/]com\.apple|Time Machine|Backups\.backupdb|\.(cursor|vscode|git|nuget|npm|yarn|cache|codex|claude|agents|gemini|copilot)|Temp|Packages|Package Cache)([\\/]|$))'

$findings = New-Object System.Collections.Generic.List[object]
$detected = [ordered]@{}
$stats = [ordered]@{
  FilesSampled = 0
  Projects = 0
  CachePackagesChecked = 0
  OsvQueries = 0
}

$script:phase = 'Starting'
$script:detail = ''
$script:percent = 0
$script:lastUiWrite = Get-Date
$script:lastUiPaint = [datetime]::MinValue
$script:spinIdx = 0
$script:spinChars = @('|', '/', '-', '\')
$script:progressTop = -1
$start = Get-Date

# -------------------- UI / progress (ONE fixed console line) --------------------
function Get-ConsoleWidth {
  try {
    $w = [Console]::WindowWidth
    if ($w -gt 20) { return $w }
  } catch {}
  return 100
}

function Initialize-ProgressLine {
  # Move to a fresh line and remember its row forever
  try {
    if ([Console]::CursorLeft -ne 0) { [Console]::WriteLine() }
    $script:progressTop = [Console]::CursorTop
    [Console]::WriteLine((' ' * ([Math]::Max(1, (Get-ConsoleWidth) - 1))))  # reserve blank line
    # Cursor is now below the reserved line; keep painting onto progressTop
  } catch {
    $script:progressTop = -1
  }
}

function Write-GuiProgressFile {
  try {
    $obj = [ordered]@{
      percent      = [int]$script:percent
      phase        = [string]$script:phase
      detail       = [string]$script:detail
      report       = [string]$outHtml
      paused       = [bool]$script:GuiPaused
      findingCount = [int]$findings.Count
      updated      = (Get-Date).ToString('o')
    }
    $json = ($obj | ConvertTo-Json -Compress)
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($script:progressJsonPath, $json, $utf8)
  } catch {}
}

function Get-GuiControlAction {
  if (-not $script:GuiMode) { return 'run' }
  try {
    if (-not (Test-Path -LiteralPath $script:controlJsonPath)) { return 'run' }
    $raw = [System.IO.File]::ReadAllText($script:controlJsonPath)
    if (-not $raw) { return 'run' }
    $c = $raw | ConvertFrom-Json
    $a = [string]$c.action
    if ($a -in @('run', 'pause', 'stop')) { return $a }
  } catch {}
  return 'run'
}

function Wait-IfGuiPaused {
  if (-not $script:GuiMode) { return }
  while ($true) {
    $action = Get-GuiControlAction
    if ($action -eq 'stop') {
      Write-Output 'LOG|warn|Stop requested'
      Write-Output ("DONE|STOPPED|{0}" -f $outHtml)
      $script:percent = [int]$script:percent
      $script:phase = 'STOPPED'
      $script:detail = 'Stopped by user'
      Write-GuiProgressFile
      exit 0
    }
    if ($action -ne 'pause') {
      if ($script:GuiPaused) {
        $script:GuiPaused = $false
        Write-Output 'LOG|meta|Scan resumed'
        Write-Output ("PROGRESS|{0}|{1}|{2}" -f $script:percent, ($script:phase -replace '\|', '/'), 'Resumed')
        Write-GuiProgressFile
      }
      return
    }
    $script:GuiPaused = $true
    $script:phase = 'Paused'
    $script:detail = 'Scan paused - press Resume to continue'
    Write-GuiProgressFile
    Write-Output ("PROGRESS|{0}|Paused|Waiting for resume..." -f $script:percent)
    Start-Sleep -Milliseconds 400
  }
}

function Show-LiveProgress {
  param(
    [int]$Percent,
    [string]$Status,
    [string]$Current
  )

  # Cooperative pause/stop for Electron GUI
  Wait-IfGuiPaused

  # throttle paints so terminal/GUI isn't flooded
  $now = Get-Date
  $minMs = if ($script:GuiMode) { 200 } else { 80 }
  if (($now - $script:lastUiPaint).TotalMilliseconds -lt $minMs -and $Percent -lt 99) {
    return
  }
  $script:lastUiPaint = $now

  $script:phase = $Status
  $script:detail = $Current
  $script:percent = [Math]::Min(99, [Math]::Max(0, $Percent))
  $script:spinIdx = ($script:spinIdx + 1) % $script:spinChars.Count
  $spin = $script:spinChars[$script:spinIdx]
  $pct = $script:percent

  if ($script:GuiMode) {
    # Machine-readable line for Electron + JSON file for reliable progress bar
    Write-Output ("PROGRESS|{0}|{1}|{2}" -f $pct, ($Status -replace '\|', '/'), ($Current -replace '[\r\n\|]', ' '))
    if (($now - $script:lastProgressJsonWrite).TotalMilliseconds -ge 250 -or $Percent -ge 99) {
      Write-GuiProgressFile
      $script:lastProgressJsonWrite = $now
    }
  } else {
    $width = Get-ConsoleWidth
    $maxLen = [Math]::Max(20, $width - 1)
    $shown = $Current
    $prefix = (" {0} [{1,3}%] {2} | " -f $spin, $pct, $Status)
    $room = $maxLen - $prefix.Length
    if ($room -lt 10) { $room = 10 }
    if ($shown.Length -gt $room) {
      $shown = '...' + $shown.Substring($shown.Length - ($room - 3))
    }
    $text = ($prefix + $shown)
    if ($text.Length -gt $maxLen) { $text = $text.Substring(0, $maxLen) }
    $text = $text.PadRight($maxLen)

    try {
      if ($script:progressTop -lt 0) { Initialize-ProgressLine }
      $left = [Console]::CursorLeft
      $top = [Console]::CursorTop
      [Console]::SetCursorPosition(0, $script:progressTop)
      [Console]::Write($text)
      $below = [Math]::Min([Console]::BufferHeight - 1, $script:progressTop + 1)
      [Console]::SetCursorPosition(0, [Math]::Max($below, $top))
    } catch {
      Write-Host ("`r" + $text) -NoNewline
    }
  }

  # Refresh HTML progress periodically while scanning
  $htmlEvery = if ($script:GuiMode) { 2 } else { 15 }
  if (-not $script:lastHtmlFlush -or ($now - $script:lastHtmlFlush).TotalSeconds -ge $htmlEvery) {
    Save-ProgressHtml
    $script:lastHtmlFlush = $now
  }
}

function HtmlEncode([string]$s) {
  if ($null -eq $s) { return '' }
  # Also encode apostrophe - otherwise data-search='...title with 'quotes'...' truncates and search misses GHSA/CVE text.
  return [System.Net.WebUtility]::HtmlEncode($s).Replace("'", '&#39;')
}

function Save-HtmlFile([string]$Path, [string]$Content) {
  # Always overwrite the SAME path in place (never create report (1).html / .tmp leftovers).
  $utf8 = New-Object System.Text.UTF8Encoding $false
  $bytes = $utf8.GetBytes($Content)
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }

  $fs = $null
  try {
    # FileMode.Create + ReadWrite share: truncate/replace existing file even if browser has it open
    $fs = [System.IO.File]::Open(
      $Path,
      [System.IO.FileMode]::Create,
      [System.IO.FileAccess]::Write,
      [System.IO.FileShare]::ReadWrite
    )
    $fs.Write($bytes, 0, $bytes.Length)
    $fs.Flush()
  } finally {
    if ($null -ne $fs) { $fs.Dispose() }
  }
}

function Get-ReportStyles {
  return @'
  :root {
    --bg: #0b0b0b;
    --panel: #141414;
    --panel-2: #1a1a1a;
    --line: rgba(255,255,255,.08);
    --line-strong: rgba(255,255,255,.12);
    --text: #ececec;
    --muted: #8b8b8b;
    --muted-2: #6b6b6b;
    --accent: #3b82f6;
    --accent-soft: rgba(59,130,246,.16);
    --danger: #ef4444;
    --warn: #f59e0b;
    --ok: #22c55e;
    --radius: 14px;
    --radius-sm: 10px;
    --pill: 999px;
    --font: "Segoe UI Variable", "Segoe UI", "SF Pro Text", sans-serif;
    --mono: Consolas, "Cascadia Mono", "IBM Plex Mono", monospace;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0;
    background: var(--bg); color: var(--text);
    font-family: var(--font);
    -webkit-font-smoothing: antialiased;
    color-scheme: dark;
  }
  body { padding: 20px 22px 36px; max-width: 1180px; }
  * { scrollbar-width: thin; scrollbar-color: rgba(255,255,255,.18) transparent; }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb {
    background: rgba(255,255,255,.14); border-radius: var(--pill);
    border: 2px solid transparent; background-clip: padding-box;
  }
  ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,.28); border: 2px solid transparent; background-clip: padding-box; }
  h1 {
    margin: 0 0 6px; font-size: 22px; font-weight: 700;
    letter-spacing: -.02em; color: var(--text);
  }
  h2.section-title {
    margin: 28px 0 12px; font-size: 11px; font-weight: 700;
    color: var(--muted-2); text-transform: uppercase; letter-spacing: .08em;
  }
  h2, h3 { color: var(--text); }
  .meta { color: var(--muted); font-size: 13px; margin: 0 0 18px; }
  .summary { font-size: 14px; color: var(--text); }
  .summary strong { color: #fff; }
  .none, .empty { color: var(--muted); }
  .empty { display: none; margin: 12px 0; }
  .empty.show { display: block; }
  .hint { color: var(--muted-2); font-size: 12px; margin-top: 22px; }
  .ok { color: #86efac; font-weight: 600; }

  .live, .project-filter, .project {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
  }
  .live { padding: 14px 16px; margin-bottom: 14px; }
  .live-top { display: flex; gap: 12px; align-items: center; margin-bottom: 8px; }
  .pct {
    min-width: 48px; text-align: center;
    background: var(--accent); color: #fff;
    font-weight: 700; font-size: 12px; border-radius: var(--pill); padding: 4px 10px;
  }
  .phase { color: #93c5fd; font-weight: 650; font-size: 14px; }
  .detail {
    color: var(--muted); font-size: 12px; font-family: var(--mono);
    word-break: break-all; line-height: 1.45;
  }

  .counts, .badges { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 16px; }
  .counts span, .badge {
    display: inline-block; padding: 4px 11px; border-radius: var(--pill);
    font-size: 11px; font-weight: 700; color: #fff; border: 1px solid transparent;
  }
  .counts .total, .badge.total, .sev-filter .all { background: rgba(255,255,255,.08); color: #d4d4d4; }
  .counts .critical, .badge.critical, .sev-filter .critical { background: rgba(239,68,68,.18); color: #fca5a5; border-color: rgba(239,68,68,.28); }
  .counts .high, .badge.high, .sev-filter .high { background: rgba(249,115,22,.16); color: #fdba74; border-color: rgba(249,115,22,.28); }
  .counts .medium, .badge.medium, .sev-filter .medium { background: rgba(245,158,11,.14); color: #fcd34d; border-color: rgba(245,158,11,.28); }
  .counts .low, .badge.low, .sev-filter .low { background: rgba(255,255,255,.06); color: #a3a3a3; border-color: var(--line); }

  .filters { margin: 0 0 18px; }
  .project-filter {
    display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
    margin: 0 0 12px; padding: 12px 14px;
  }
  .project-filter label {
    color: var(--muted-2); font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: .06em;
  }
  .project-filter input, .dd-toggle {
    background: rgba(255,255,255,.03); color: var(--text);
    border: 1px solid var(--line); border-radius: var(--radius-sm);
    padding: 9px 12px; font-size: 13px;
  }
  .project-filter input {
    min-width: 180px; flex: 1 1 180px; outline: none;
  }
  .project-filter input:focus, .dd-toggle:focus {
    border-color: rgba(59,130,246,.55); outline: none;
  }
  .project-filter input::placeholder { color: var(--muted-2); }
  #vuln-search { flex: 2 1 280px; min-width: 220px; }

  .dd { position: relative; flex: 1 1 260px; min-width: 200px; z-index: 20; }
  .dd-toggle {
    width: 100%; display: flex; align-items: center; justify-content: space-between; gap: 14px;
    text-align: left; cursor: pointer; padding-right: 16px;
  }
  .dd-toggle:hover { border-color: var(--line-strong); background: rgba(255,255,255,.05); }
  .dd-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
  .dd-arrow {
    flex: 0 0 auto; width: 8px; height: 8px; margin-right: 4px; margin-top: -3px;
    border-right: 2px solid #a3a3a3; border-bottom: 2px solid #a3a3a3;
    transform: rotate(45deg); transition: transform .18s ease, margin-top .18s ease;
  }
  .dd.open .dd-arrow { transform: rotate(225deg); margin-top: 3px; }
  .dd-menu {
    position: absolute; left: 0; right: 0; top: calc(100% + 6px);
    max-height: 280px; overflow: auto;
    background: #121212; border: 1px solid var(--line-strong); border-radius: var(--radius-sm);
    box-shadow: 0 16px 40px rgba(0,0,0,.55);
    display: none; padding: 6px;
  }
  .dd.open .dd-menu { display: block; }
  .dd-option {
    display: block; width: 100%; text-align: left; border: 0; background: transparent;
    color: var(--text); padding: 8px 10px; border-radius: 8px; cursor: pointer; font-size: 13px;
  }
  .dd-option:hover { background: rgba(255,255,255,.06); }
  .dd-option.selected { background: var(--accent-soft); color: #93c5fd; }

  .pill-row, .kind-filter, .sev-filter { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .kind-filter { margin: 0 0 10px; }
  .kind-filter button, .sev-filter button {
    appearance: none; cursor: pointer;
    border: 1px solid var(--line); border-radius: var(--pill);
    padding: 5px 12px; font-size: 11px; font-weight: 700; letter-spacing: .02em;
    color: #d4d4d4; background: rgba(255,255,255,.05); line-height: 1.2;
    transition: background .15s ease, border-color .15s ease, color .15s ease;
  }
  .kind-filter button:hover, .sev-filter button:hover { background: rgba(255,255,255,.09); }
  .kind-filter button.active, .sev-filter button.active {
    border-color: rgba(255,255,255,.35); box-shadow: inset 0 0 0 1px rgba(255,255,255,.12);
  }
  .kind-filter button[data-kind="project"] { background: var(--accent-soft); color: #93c5fd; border-color: rgba(59,130,246,.28); }
  .kind-filter button[data-kind="cache"] { background: rgba(168,85,247,.14); color: #d8b4fe; border-color: rgba(168,85,247,.28); }

  .project { padding: 16px 18px; margin: 0 0 14px; }
  .project.hidden, li.hidden, li.finding.hidden { display: none; }
  .project[data-kind="cache"] { border-color: rgba(168,85,247,.28); }
  .project-sticky {
    position: sticky; top: 0; z-index: 6;
    background: var(--panel);
    padding: 8px 0 10px; margin: 0 0 4px;
    border-bottom: 1px solid var(--line);
    box-shadow: 0 10px 18px rgba(0,0,0,.55);
  }
  .project-label {
    font-size: 11px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
    color: #93c5fd; margin: 0 0 6px;
  }
  .project[data-kind="cache"] .project-label { color: #d8b4fe; }
  .project-sticky h2, .project-sticky h3, .project h2, .project h3 {
    margin: 0 0 8px; font-size: 17px; font-weight: 700; letter-spacing: -.02em; color: var(--text);
  }
  .folder {
    font-family: var(--mono); font-size: 12px; color: #d4d4d4;
    background: rgba(0,0,0,.35); border: 1px solid var(--line); border-radius: var(--radius-sm);
    padding: 9px 11px; word-break: break-all;
  }
  .count { color: var(--muted); font-size: 12px; margin: 10px 0 4px; }

  ul { list-style: none; margin: 8px 0 0; padding: 0; }
  li, li.finding {
    padding: 12px 0; border-top: 1px solid var(--line);
  }
  .issue-head { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 6px; }
  .badge {
    min-width: 68px; text-align: center; margin-right: 0;
  }
  .fix-badge {
    display: inline-block; padding: 3px 9px; border-radius: var(--pill);
    font-size: 10px; font-weight: 700; border: 1px solid transparent;
  }
  .fix-badge.fix-yes { background: rgba(34,197,94,.14); color: #86efac; border-color: rgba(34,197,94,.28); }
  .fix-badge.fix-no { background: rgba(255,255,255,.06); color: #a3a3a3; border-color: var(--line); }
  code { font-family: var(--mono); font-size: 12.5px; color: #f5f5f5; }
  .meta-line, .detail, .detail.fix { color: var(--muted); font-size: 12.5px; line-height: 1.45; margin-top: 4px; }
  .meta-line.fix, .detail.fix { color: #d4d4d4; }
  .meta-line a, .detail a, .adv-list a { color: #93c5fd; text-decoration: none; }
  .meta-line a:hover, .detail a:hover, .adv-list a:hover { text-decoration: underline; }
  .advisory { margin-top: 8px; }
  .adv-label { color: var(--muted); font-size: 12px; font-weight: 650; margin-bottom: 4px; }
  .adv-list { list-style: none; margin: 0; padding: 0; }
  .adv-list li { padding: 2px 0; border-top: 0 !important; }
  .adv-list a { word-break: break-all; }
'@
}

function Get-ProjectFolderFromPath([string]$path) {
  if (-not $path) { return '(unknown project)' }
  $folder = $path.Trim()
  try {
    if ($folder -and (Test-Path -LiteralPath $folder -PathType Leaf)) {
      $folder = Split-Path -Parent $folder
    }
  } catch {}
  if (-not $folder) { return '(unknown project)' }
  return $folder
}

function Sanitize-DisplayText([string]$s) {
  if ([string]::IsNullOrEmpty($s)) { return '' }
  $s = $s.Replace([string][char]0x2192, '->')
  $s = $s.Replace([string][char]0x2014, '-')
  $s = $s.Replace([string][char]0x2013, '-')
  $s = $s.Replace([string][char]0x00A0, ' ')
  # Drop leftover broken encoding / control junk
  return ($s -replace '[^\x09\x0A\x0D\x20-\x7E\u00A0-\u024F]', ' ').Trim()
}

function Format-FixAdvice {
  param(
    $FixRaw,
    [string]$Package = '',
    [string]$Ecosystem = ''
  )
  $hasFix = $false
  $text = ''

  if ($null -eq $FixRaw -or $FixRaw -eq '') {
    $text = 'No known fix reported by the scanner.'
  } elseif ($FixRaw -is [bool]) {
    if ($FixRaw) {
      $hasFix = $true
      $text = if ($Package) { "Upgrade $Package to a patched version (npm/yarn audit reports a fix is available)." } else { 'A patched version is available. Upgrade the package.' }
    } else {
      $text = 'No fix available yet according to the package audit.'
    }
  } elseif ($FixRaw -is [string]) {
    $s = Sanitize-DisplayText ([string]$FixRaw)
    if ($s -match '^(True|true)$') {
      $hasFix = $true
      $text = if ($Package) { "Upgrade $Package to a patched version (fix available)." } else { 'A patched version is available. Upgrade the package.' }
    } elseif ($s -match '^(False|false)$' -or $s -eq 'None' -or $s -eq 'null') {
      $text = 'No fix available yet according to the package audit.'
    } elseif ($s) {
      $hasFix = $true
      $text = $s
      if ($s -match '^\d' -or $s -match '^[A-Za-z0-9._-]+(,\s*[A-Za-z0-9._-]+)*$') {
        # Likely fix version list from pip-audit / similar
        $text = "Upgrade to fixed version(s): $s"
      }
    } else {
      $text = 'No known fix reported by the scanner.'
    }
  } else {
    # npm audit fixAvailable object: { name, version, isSemVerMajor }
    try {
      $name = if ($FixRaw.name) { [string]$FixRaw.name } else { $Package }
      $ver = if ($FixRaw.version) { [string]$FixRaw.version } else { '' }
      if ($ver) {
        $hasFix = $true
        $major = ''
        if ($FixRaw.isSemVerMajor -eq $true) { $major = ' (may include breaking / major changes)' }
        $text = "Upgrade $name to $ver$major"
      } else {
        $text = 'No known fix reported by the scanner.'
      }
    } catch {
      $text = 'No known fix reported by the scanner.'
    }
  }

  if ($hasFix -and $Ecosystem -eq 'npm' -and $text -notmatch 'npm (install|update|audit)') {
    $text = "$text | Try: npm audit fix  (or npm audit fix --force if needed)"
  }

  return [pscustomobject]@{
    HasFix = $hasFix
    Text   = (Sanitize-DisplayText $text)
  }
}

function Add-LogEntry {
  param(
    [string]$Message,
    [ValidateSet('info','phase','lang','finding','warn','progress','done')]
    [string]$Kind = 'info',
    [string]$Severity = '',
    [string]$Folder = '',
    [string]$Fix = '',
    [bool]$HasFix = $false,
    [string]$Advisory = '',
    [string]$Title = '',
    [string]$Package = '',
    [switch]$IsCache
  )
  $script:logEntries.Add([pscustomobject]@{
    Time = Get-Date
    Kind = $Kind
    Severity = $Severity
    Message = $Message
    Folder = $Folder
    Fix = $Fix
    HasFix = $HasFix
    Advisory = $Advisory
    Title = $Title
    Package = $Package
    IsCache = [bool]$IsCache
  }) | Out-Null

  # refresh HTML / findings JSON often in GUI; slower for standalone HTML viewers
  $now = Get-Date
  $flushEvery = if ($script:GuiMode) { 2 } else { 15 }
  if (($now - $script:lastHtmlFlush).TotalSeconds -ge $flushEvery) {
    Save-ProgressHtml
    $script:lastHtmlFlush = $now
  }
}

function Save-FindingsJson {
  try {
    $payload = [ordered]@{
      generated = (Get-Date).ToString('o')
      platform  = [string]$script:OsLabel
      count     = [int]$findings.Count
      findings  = @($findings)
    }
    $json = ($payload | ConvertTo-Json -Depth 8)
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($script:findingsJsonPath, $json, $utf8)
    $script:lastFindingsJsonWrite = Get-Date
  } catch {}
}

function Save-ProgressHtml {
  function Get-FolderFromFindingMessage([string]$msg) {
    $parts = $msg -split '\s*::\s*'
    if ($parts.Count -ge 2) {
      return (Get-ProjectFolderFromPath ($parts[-1].Trim()))
    }
    return '(unknown project)'
  }

  function Get-PackageLabel([string]$package, [string]$msg) {
    if ($package -and $msg -match ('FINDING\s+\[[^\]]+\]\s+' + [regex]::Escape($package) + '(@[^\s(]+)')) {
      return ($package + $Matches[1])
    }
    if ($msg -match 'FINDING\s+\[[^\]]+\]\s+(\S+)') { return $Matches[1] }
    if ($package) { return $package }
    return $msg
  }

  $findingsByProject = [ordered]@{}
  foreach ($e in $script:logEntries) {
    if ($e.Kind -ne 'finding') { continue }
    $sev = if ($e.Severity) { $e.Severity.ToLowerInvariant() } else { 'unknown' }
    if ($sev -eq 'moderate') { $sev = 'medium' }
    $folder = if ($e.Folder) { $e.Folder } else { Get-FolderFromFindingMessage $e.Message }
    $pkg = Get-PackageLabel -package $e.Package -msg $e.Message
    if (-not $findingsByProject.Contains($folder)) {
      $findingsByProject[$folder] = New-Object System.Collections.Generic.List[object]
    }
    $findingsByProject[$folder].Add([pscustomobject]@{
      Severity = $sev
      Package  = $pkg
      Title    = if ($e.Title) { [string]$e.Title } else { '' }
      Fix      = if ($e.Fix) { [string]$e.Fix } else { 'No known fix reported by the scanner.' }
      HasFix   = [bool]$e.HasFix
      Advisory = if ($e.Advisory) { [string]$e.Advisory } else { '' }
      IsCache  = if ($null -ne $e.IsCache) { [bool]$e.IsCache } else { (Test-IsCacheLocation $folder) }
    }) | Out-Null
  }

  $livePct = if ($null -ne $script:percent) { [int]$script:percent } else { 0 }
  $livePhase = if ($script:phase) { [string]$script:phase } else { 'Starting' }
  $liveDetail = if ($script:detail) { [string]$script:detail } else { '' }

  $projectFolders = New-Object System.Collections.Generic.List[string]
  $cacheFolders = New-Object System.Collections.Generic.List[string]
  foreach ($folder in @($findingsByProject.Keys | Sort-Object)) {
    $isCacheGroup = @($findingsByProject[$folder] | Where-Object { $_.IsCache }).Count -gt 0 -or (Test-IsCacheLocation $folder)
    if ($isCacheGroup) { [void]$cacheFolders.Add($folder) }
    else { [void]$projectFolders.Add($folder) }
  }

  $allItems = New-Object System.Collections.Generic.List[object]
  foreach ($folder in $findingsByProject.Keys) {
    foreach ($it in $findingsByProject[$folder]) { [void]$allItems.Add($it) }
  }
  $cCrit = @($allItems | Where-Object Severity -eq 'critical').Count
  $cHigh = @($allItems | Where-Object Severity -eq 'high').Count
  $cMed  = @($allItems | Where-Object { $_.Severity -in @('medium','moderate') }).Count
  $cLow  = @($allItems | Where-Object Severity -eq 'low').Count
  $cTotal = $allItems.Count

  $projectOptions = New-Object System.Collections.Generic.List[string]
  [void]$projectOptions.Add("<button type='button' class='dd-option selected' role='option' data-value='all'>All locations ($($findingsByProject.Count))</button>")
  if ($projectFolders.Count -gt 0) {
    [void]$projectOptions.Add("<button type='button' class='dd-option' role='option' data-value='kind:project'>All projects ($($projectFolders.Count))</button>")
  }
  if ($cacheFolders.Count -gt 0) {
    [void]$projectOptions.Add("<button type='button' class='dd-option' role='option' data-value='kind:cache'>All caches ($($cacheFolders.Count))</button>")
  }

  function Build-FindingBlocks {
    param($Folders, [string]$Kind, [string]$LabelPrefix)
    $blocks = New-Object System.Collections.Generic.List[string]
    $num = 0
    foreach ($folder in $Folders) {
      $num++
      $items = $findingsByProject[$folder]
      $shortName = [IO.Path]::GetFileName(($folder).TrimEnd('\','/'))
      if (-not $shortName) { $shortName = "$LabelPrefix $num" }
      $projectId = "$Kind$num"
      $searchText = ("$shortName $folder $Kind").ToLowerInvariant()
      $optLabel = "[$LabelPrefix] $shortName ($($items.Count)) - $folder"
      if ($optLabel.Length -gt 120) { $optLabel = $optLabel.Substring(0, 117) + '...' }
      [void]$projectOptions.Add("<button type='button' class='dd-option' role='option' data-value='" + (HtmlEncode $projectId) + "'>" + (HtmlEncode $optLabel) + "</button>")

      $rows = New-Object System.Collections.Generic.List[string]
      foreach ($item in $items) {
        $fixClass = if ($item.HasFix) { 'fix-yes' } else { 'fix-no' }
        $fixLabel = if ($item.HasFix) { 'FIX AVAILABLE' } else { 'NO KNOWN FIX' }
        $titleHtml = if ($item.Title) { "<div class='meta-line'>Issue: " + (HtmlEncode $item.Title) + "</div>" } else { '' }
        $advHtml = Format-AdvisoryHtml -Advisory $item.Advisory -WrapperClass 'meta-line'
        $issueSearch = ("$($item.Package) $($item.Title) $($item.Advisory) $($item.Fix) $($item.Severity)").ToLowerInvariant()
        [void]$rows.Add(@"
<li class="finding" data-sev="$(HtmlEncode $item.Severity)" data-search="$(HtmlEncode $issueSearch)">
  <div class="issue-head">
    <span class="badge $($item.Severity)">$(HtmlEncode $item.Severity.ToUpper())</span>
    <code>$(HtmlEncode $item.Package)</code>
    <span class="fix-badge $fixClass">$fixLabel</span>
  </div>
  $titleHtml
  <div class="meta-line fix">How to solve: $(HtmlEncode $item.Fix)</div>
  $advHtml
</li>
"@)
      }

      [void]$blocks.Add(@"
<section class="project" data-kind="$(HtmlEncode $Kind)" data-project="$(HtmlEncode $projectId)" data-search="$(HtmlEncode $searchText)">
  <div class="project-sticky">
    <div class="project-label">$LabelPrefix $num</div>
    <h3>$(HtmlEncode $shortName)</h3>
    <div class="folder">$(HtmlEncode $folder)</div>
  </div>
  <div class="count">$($items.Count) finding(s)</div>
  <ul>$($rows -join '')</ul>
</section>
"@)
    }
    return ,$blocks
  }

  $projectBlocks = Build-FindingBlocks -Folders $projectFolders -Kind 'project' -LabelPrefix 'Project'
  $cacheBlocks = Build-FindingBlocks -Folders $cacheFolders -Kind 'cache' -LabelPrefix 'Cache'

  $filterBar = ''
  if ($cTotal -gt 0) {
    $allLabel = "All locations ($($findingsByProject.Count))"
    $filterBar = @"
  <div class="filters">
    <div class="project-filter">
      <label id="project-label">Location</label>
      <div class="dd" id="project-dd">
        <button type="button" class="dd-toggle" id="project-select" aria-haspopup="listbox" aria-expanded="false">
          <span class="dd-label">$(HtmlEncode $allLabel)</span>
          <span class="dd-arrow" aria-hidden="true"></span>
        </button>
        <div class="dd-menu" role="listbox">
          $($projectOptions -join "`r`n")
        </div>
      </div>
      <input id="project-search" type="search" placeholder="Search project/cache path..." />
      <input id="vuln-search" type="search" placeholder="Search package / CVE / GHSA / commit (e.g. CVE-2025-55182 or d033885)..." />
    </div>
    <div class="pill-row">
      <div class="kind-filter" id="kind-filters">
        <button type="button" class="kind active" data-kind="all">ALL</button>
        <button type="button" class="kind" data-kind="project">PROJECTS</button>
        <button type="button" class="kind" data-kind="cache">CACHES</button>
      </div>
      <div class="sev-filter" id="sev-filters">
        <button type="button" class="sev active" data-sev="all">ALL SEV</button>
        <button type="button" class="sev critical" data-sev="critical">CRITICAL</button>
        <button type="button" class="sev high" data-sev="high">HIGH</button>
        <button type="button" class="sev medium" data-sev="medium">MEDIUM</button>
        <button type="button" class="sev low" data-sev="low">LOW</button>
      </div>
    </div>
  </div>
"@
  }

  if ($cTotal -eq 0) {
    $findingsHtml = '<p class="none">No findings yet - scanning...</p>'
  } else {
    $projPart = if ($projectBlocks.Count -gt 0) { ($projectBlocks -join "`r`n") } else { '<p class="none">No project findings yet.</p>' }
    $cachePart = if ($cacheBlocks.Count -gt 0) { ($cacheBlocks -join "`r`n") } else { '<p class="none">No cache findings yet.</p>' }
    $findingsHtml = @"
  $filterBar
  <div id="projects">
    <h2 class="section-title">Projects</h2>
    $projPart
    <h2 class="section-title">Package caches</h2>
    $cachePart
  </div>
  <p class="empty" id="empty-findings">No findings match this filter.</p>
"@
  }

  $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Scan progress</title>
<style>
$(Get-ReportStyles)
</style>
</head>
<body>
  <h1>Scan progress</h1>
  <div class="meta">Updated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') · live in app</div>
  <div class="live">
    <div class="live-top">
      <span class="pct">$livePct%</span>
      <span class="phase">$(HtmlEncode $livePhase)</span>
    </div>
    <div class="detail">$(HtmlEncode $liveDetail)</div>
  </div>
  <div class="counts">
    <span class="total">total: $cTotal</span>
    <span class="critical">critical: $cCrit</span>
    <span class="high">high: $cHigh</span>
    <span class="medium">medium: $cMed</span>
    <span class="low">low: $cLow</span>
  </div>
  $findingsHtml
  <p class="hint">View live in the app Report tab. Use Export to save JSON, TXT, CSV, Markdown, or HTML.</p>
<script>
(function () {
  var projects = Array.prototype.slice.call(document.querySelectorAll('#projects .project'));
  var projectDd = document.getElementById('project-dd');
  var projectToggle = document.getElementById('project-select');
  var projectLabel = projectToggle ? projectToggle.querySelector('.dd-label') : null;
  var projectMenu = projectDd ? projectDd.querySelector('.dd-menu') : null;
  var projectOptions = projectMenu ? Array.prototype.slice.call(projectMenu.querySelectorAll('.dd-option')) : [];
  var projectSearch = document.getElementById('project-search');
  var vulnSearch = document.getElementById('vuln-search');
  var sevButtons = Array.prototype.slice.call(document.querySelectorAll('#sev-filters button'));
  var kindButtons = Array.prototype.slice.call(document.querySelectorAll('#kind-filters button'));
  var empty = document.getElementById('empty-findings');
  var currentProject = 'all';
  var currentProjectSearch = '';
  var currentVulnSearch = '';
  var currentSev = 'all';
  var currentKind = 'all';

  function setProjectValue(value, closeMenu) {
    currentProject = value || 'all';
    if (currentProject === 'kind:project') currentKind = 'project';
    else if (currentProject === 'kind:cache') currentKind = 'cache';
    projectOptions.forEach(function (opt) {
      var selected = (opt.getAttribute('data-value') === currentProject);
      opt.classList.toggle('selected', selected);
      if (selected && projectLabel) projectLabel.textContent = opt.textContent;
    });
    kindButtons.forEach(function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-kind') === currentKind);
    });
    if (closeMenu && projectDd) {
      projectDd.classList.remove('open');
      if (projectToggle) projectToggle.setAttribute('aria-expanded', 'false');
    }
  }

  function apply() {
    var projectQ = (currentProjectSearch || '').toLowerCase().trim();
    var vulnQ = (currentVulnSearch || '').toLowerCase().trim();
    var visible = 0;
    projects.forEach(function (project) {
      var pid = project.getAttribute('data-project') || '';
      var pkind = project.getAttribute('data-kind') || 'project';
      var hay = project.getAttribute('data-search') || '';
      var kindMatch = (currentKind === 'all') || (pkind === currentKind);
      var projectMatch = (currentProject === 'all' || currentProject === 'kind:project' || currentProject === 'kind:cache' || currentProject === pid);
      if (currentProject === 'kind:project') kindMatch = (pkind === 'project');
      if (currentProject === 'kind:cache') kindMatch = (pkind === 'cache');
      if (projectQ && hay.indexOf(projectQ) === -1) projectMatch = false;
      var items = Array.prototype.slice.call(project.querySelectorAll('li.finding'));
      var shown = 0;
      items.forEach(function (li) {
        var sev = li.getAttribute('data-sev') || '';
        var issueHay = ((li.getAttribute('data-search') || '') + ' ' + (li.textContent || '')).toLowerCase();
        var sevMatch = (currentSev === 'all') || (sev === currentSev);
        var vulnMatch = !vulnQ || issueHay.indexOf(vulnQ) !== -1;
        var show = projectMatch && kindMatch && sevMatch && vulnMatch;
        li.classList.toggle('hidden', !show);
        if (show) shown++;
      });
      project.classList.toggle('hidden', shown === 0);
      if (shown > 0) visible++;
    });
    if (empty) empty.classList.toggle('show', visible === 0 && projects.length > 0);
    sevButtons.forEach(function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-sev') === currentSev);
    });
    kindButtons.forEach(function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-kind') === currentKind);
    });
  }

  if (projectToggle && projectDd && projectMenu) {
    projectToggle.addEventListener('click', function (e) {
      e.stopPropagation();
      projectDd.classList.toggle('open');
      projectToggle.setAttribute('aria-expanded', projectDd.classList.contains('open') ? 'true' : 'false');
    });
    projectOptions.forEach(function (opt) {
      opt.addEventListener('click', function (e) {
        e.stopPropagation();
        setProjectValue(opt.getAttribute('data-value'), true);
        if (projectSearch) { projectSearch.value = ''; currentProjectSearch = ''; }
        apply();
      });
    });
    document.addEventListener('click', function () {
      projectDd.classList.remove('open');
      if (projectToggle) projectToggle.setAttribute('aria-expanded', 'false');
    });
  }
  if (projectSearch) {
    projectSearch.addEventListener('input', function () {
      currentProjectSearch = projectSearch.value || '';
      if (currentProjectSearch) setProjectValue('all', true);
      apply();
    });
  }
  if (vulnSearch) {
    vulnSearch.addEventListener('input', function () {
      currentVulnSearch = vulnSearch.value || '';
      apply();
    });
  }
  sevButtons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      currentSev = btn.getAttribute('data-sev') || 'all';
      apply();
    });
  });
  kindButtons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      currentKind = btn.getAttribute('data-kind') || 'all';
      if (currentKind === 'project') setProjectValue('kind:project', true);
      else if (currentKind === 'cache') setProjectValue('kind:cache', true);
      else setProjectValue('all', true);
      apply();
    });
  });
  apply();
})();
</script>
</body>
</html>
"@
  Save-FindingsJson
  Save-HtmlFile -Path $logPath -Content $html
}

function Write-QuietLog([string]$msg) {
  Add-LogEntry -Message $msg -Kind 'info'
}

function Write-Log([string]$msg, [string]$color = 'Gray') {
  $kind = 'info'
  if ($msg -match '^(Phase |Folder walk|Detected|Tools|DONE)') { $kind = 'phase' }
  if ($msg -match 'DONE') { $kind = 'done' }
  if ($color -eq 'Yellow') { $kind = 'warn' }
  if ($msg -match '^\s+\S+.*sourceFiles~|projects/manifests=') { $kind = 'lang' }

  if ($script:GuiMode) {
    Write-Output ("LOG|{0}|{1}" -f $kind, ($msg -replace '[\r\n]', ' '))
  } else {
    $line = "$(Get-Date -Format 'HH:mm:ss')  $msg"
    try {
      if ($script:progressTop -ge 0) {
        $below = [Math]::Min([Console]::BufferHeight - 1, $script:progressTop + 1)
        [Console]::SetCursorPosition(0, $below)
      }
    } catch {}
    Write-Host $line -ForegroundColor $color
    try {
      $script:progressTop = [Console]::CursorTop
      [Console]::WriteLine((' ' * ([Math]::Max(1, (Get-ConsoleWidth) - 1))))
    } catch {
      $script:progressTop = -1
    }
  }
  Add-LogEntry -Message $msg -Kind $kind
}

function Test-IsCacheLocation([string]$path, [string]$source = '') {
  if ($source -like 'cache:*') { return $true }
  if (-not $path) { return $false }
  $p = $path.ToLowerInvariant().Replace('/', '\')
  return (
    $p -match '\\npm-cache(\\|$)' -or
    $p -match '\\\.npm(\\|$)' -or
    $p -match '\\yarn\\cache' -or
    $p -match '\\caches\\yarn' -or
    $p -match '\\\.nuget\\packages(\\|$)' -or
    $p -match '\\pip\\cache' -or
    $p -match '\\caches\\pip' -or
    $p -match '\\pypoetry\\cache' -or
    $p -match '\\caches\\pypoetry' -or
    $p -match '\\\.yarn\\berry\\cache'
  )
}

function Add-Finding {
  param(
    [string]$Ecosystem,
    [string]$Source,
    [string]$Severity,
    [string]$Package,
    [string]$Version,
    [string]$Title,
    [string]$Advisory,
    [string]$Path,
    $Fix = ''
  )
  $sev = if ($Severity) { $Severity.ToLowerInvariant() } else { 'unknown' }
  if ($HighOnly -and $sev -notin @('high', 'critical')) { return }

  $titleClean = Sanitize-DisplayText $Title
  $fixInfo = Format-FixAdvice -FixRaw $Fix -Package $Package -Ecosystem $Ecosystem
  $fixText = $fixInfo.Text
  $hasFix = [bool]$fixInfo.HasFix
  $isCache = Test-IsCacheLocation -path $Path -source $Source
  $aliasTags = Get-KnownAdvisoryAliases -Package $Package -Title $titleClean -Advisory $Advisory
  $advisoryText = Join-AdvisoryText -Parts (@($Advisory) + @($aliasTags))

  $findings.Add([pscustomobject]@{
    Ecosystem = $Ecosystem
    Source    = $Source
    Severity  = $sev
    Package   = $Package
    Version   = $Version
    Title     = $titleClean
    Advisory  = $advisoryText
    Path      = $Path
    Fix       = $fixText
    HasFix    = $hasFix
    IsCache   = $isCache
  }) | Out-Null

  # Keep console on one progress row; details go to HTML progress log
  $folder = Get-ProjectFolderFromPath $Path
  Add-LogEntry -Message ("FINDING [$sev] $Package@$Version ($Ecosystem) :: $titleClean :: $Path") `
    -Kind 'finding' -Severity $sev -Folder $folder `
    -Fix $fixText -HasFix $hasFix -Advisory $advisoryText -Title $titleClean -Package $Package `
    -IsCache:$isCache

  if ($script:GuiMode) {
    $sSev = ($sev -replace '[\r\n\|]', ' ').Trim()
    $sPkg = (("$Package@$Version") -replace '[\r\n\|]', ' ').Trim()
    $sEco = ($Ecosystem -replace '[\r\n\|]', ' ').Trim()
    $sTitle = ($titleClean -replace '[\r\n\|]', ' ').Trim()
    $sFolder = ($folder -replace '[\r\n\|]', ' ').Trim()
    $sFix = if ($hasFix) { '1' } else { '0' }
    Write-Output ("FINDING|{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f $sSev, $sPkg, $sEco, $sTitle, $sFolder, $sFix, $findings.Count)
    Write-GuiProgressFile
  }
}

function Show-UserNotification([string]$title, [string]$text) {
  try {
    if ($script:IsMac) {
      $t = ($title -replace '\\', '\\\\' -replace '"', '\"')
      $b = ($text -replace '\\', '\\\\' -replace '"', '\"')
      & osascript -e "display notification `"$b`" with title `"$t`"" | Out-Null
      return
    }
    if ($script:IsWin) {
      Add-Type -AssemblyName System.Windows.Forms
      Add-Type -AssemblyName System.Drawing
      $ni = New-Object System.Windows.Forms.NotifyIcon
      $ni.Icon = [System.Drawing.SystemIcons]::Warning
      $ni.Visible = $true
      $ni.BalloonTipTitle = $title
      $ni.BalloonTipText = $text
      $ni.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
      $ni.ShowBalloonTip(12000)
      Start-Sleep -Seconds 6
      $ni.Dispose()
      return
    }
  } catch {}
  Write-Host "Notification: $title - $text" -ForegroundColor Yellow
}

function Open-ReportFile([string]$path) {
  if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $false }
  try {
    if ($script:IsMac) {
      Start-Process -FilePath 'open' -ArgumentList @($path) | Out-Null
      return $true
    }
    if ($script:IsWin) {
      Invoke-Item -LiteralPath $path
      return $true
    }
    Start-Process -FilePath $path | Out-Null
    return $true
  } catch {
    return $false
  }
}

function Get-Cmd([string]$name, [string[]]$extraPaths) {
  foreach ($p in @($extraPaths)) {
    if ($p -and (Test-Path -LiteralPath $p)) { return $p }
  }
  if ($script:IsWin) {
    $cmdPath = Get-Command "$name.cmd" -ErrorAction SilentlyContinue
    if ($cmdPath) { return $cmdPath.Source }
  }
  $c = Get-Command $name -ErrorAction SilentlyContinue
  if ($c) {
    $src = [string]$c.Source
    if ($script:IsWin -and $src -and $src -notmatch '\.(cmd|exe|bat)$') {
      $sibling = [System.IO.Path]::ChangeExtension($src, '.cmd')
      if (Test-Path -LiteralPath $sibling) { return $sibling }
      $dir = Split-Path -Parent $src
      $alt = Join-Path $dir "$name.cmd"
      if (Test-Path -LiteralPath $alt) { return $alt }
    }
    return $src
  }
  return $null
}

function Invoke-NativeCommand {
  param(
    [Parameter(Mandatory)][string]$Command,
    [string[]]$Arguments = @(),
    [string]$WorkingDirectory = '',
    [string]$OutFile = ''
  )
  $wd = if ($WorkingDirectory) { $WorkingDirectory } else { (Get-Location).Path }
  $errFile = if ($OutFile) { "$OutFile.err" } else { $null }

  # Windows npm/yarn shims must go through cmd.exe
  $leaf = Split-Path -Leaf $Command
  $useCmd = $script:IsWin -and (
    $Command -match '\.(cmd|bat)$' -or
    $leaf -match '^(npm|yarn|npx)(\.cmd|\.bat)?$'
  )
  if ($useCmd) {
    $exe = if ($leaf -match '\.(cmd|bat)$') { $leaf } else { "$leaf.cmd" }
    $argLine = ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
      }) -join ' '
    $sp = @{
      FilePath = 'cmd.exe'
      ArgumentList = @('/d', '/c', "$exe $argLine")
      WorkingDirectory = $wd
      NoNewWindow = $true
      Wait = $true
      PassThru = $true
    }
    if ($OutFile) {
      $sp.RedirectStandardOutput = $OutFile
      $sp.RedirectStandardError = $errFile
    } else {
      $sp.RedirectStandardOutput = $script:DevNull
      $sp.RedirectStandardError = $script:DevNull
    }
    $p = Start-Process @sp
    return $(if ($null -ne $p) { $p.ExitCode } else { 1 })
  }

  # Resolve command path when needed
  $exePath = $Command
  if (-not (Test-Path -LiteralPath $Command)) {
    $gc = Get-Command $Command -ErrorAction SilentlyContinue
    if ($gc) { $exePath = $gc.Source }
  }

  Push-Location -LiteralPath $wd
  try {
    if ($OutFile) {
      $output = & $exePath @Arguments 2> $errFile
      $code = $LASTEXITCODE
      if ($null -eq $code) { $code = 0 }
      if ($null -eq $output) {
        [System.IO.File]::WriteAllText($OutFile, '')
      } elseif ($output -is [array]) {
        [System.IO.File]::WriteAllLines($OutFile, [string[]]$output)
      } else {
        [System.IO.File]::WriteAllText($OutFile, [string]$output)
      }
      return $code
    }
    & $exePath @Arguments 2> $script:DevNull | Out-Null
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    return $code
  } catch {
    if ($OutFile) {
      try { [System.IO.File]::WriteAllText($OutFile, '') } catch {}
    }
    return 1
  } finally {
    Pop-Location
  }
}

function Invoke-JsonCommand {
  param(
    [string]$FilePath,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [string]$OutFile
  )
  return (Invoke-NativeCommand -Command $FilePath -Arguments $Arguments -WorkingDirectory $WorkingDirectory -OutFile $OutFile)
}

# -------------------- OSV helpers --------------------
function Invoke-OsvQuery([string]$ecosystem, [string]$name, [string]$version) {
  if ($SkipOsv) { return @() }
  $stats.OsvQueries++
  try {
    $body = @{
      package = @{ name = $name; ecosystem = $ecosystem }
      version = $version
    } | ConvertTo-Json -Compress
    $resp = Invoke-RestMethod -Uri 'https://api.osv.dev/v1/query' -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 25
    if ($resp.vulns) { return @($resp.vulns) }
  } catch {}
  return @()
}

function Get-OsvSeverity($vulns) {
  $rank = @{ critical = 4; high = 3; medium = 2; moderate = 2; low = 1 }
  $best = 'unknown'; $n = 0
  foreach ($v in $vulns) {
    $s = 'unknown'
    if ($v.database_specific.severity) { $s = ([string]$v.database_specific.severity).ToLowerInvariant() }
    elseif ($v.severity) { $s = 'medium' }
    $r = 0; if ($rank.ContainsKey($s)) { $r = $rank[$s] }
    if ($r -gt $n) { $n = $r; $best = $s }
  }
  return $best
}

# Extra searchable tags for emails / bulletins that mention CVE or fix commits
# (npm audit often only stores GHSA URLs, not CVE / git SHAs).
function Get-KnownAdvisoryAliases([string]$Package, [string]$Title = '', [string]$Advisory = '') {
  $tags = New-Object System.Collections.Generic.List[string]
  $blob = ("$Package $Title $Advisory").ToLowerInvariant()
  $pkg = if ($Package) { $Package.ToLowerInvariant() } else { '' }

  if (
    $pkg -match 'react-server-dom-(webpack|parcel|turbopack)' -or
    $blob -match 'react server components' -or
    $blob -match 'react2shell' -or
    $blob -match 'cve-2025-55182'
  ) {
    foreach ($t in @(
      'CVE-2025-55182', 'CVE-2025-55184', 'CVE-2025-67779', 'React2Shell',
      'React Server Components', 'd031798', 'd032168', 'd033885'
    )) { [void]$tags.Add($t) }
  }
  if ($pkg -eq 'next' -or $blob -match 'cve-2025-66478') {
    foreach ($t in @('CVE-2025-66478', 'CVE-2025-55182', 'React2Shell', 'd031798', 'd032168', 'd033885')) {
      [void]$tags.Add($t)
    }
  }
  return @($tags | Select-Object -Unique)
}

function Join-AdvisoryText {
  param([string[]]$Parts)
  $items = Get-AdvisoryItems -Parts $Parts
  return (($items | ForEach-Object { $_.Label }) -join ', ')
}

function Get-AdvisoryItems {
  param([string[]]$Parts)
  $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $items = New-Object System.Collections.Generic.List[object]

  function Add-AdvItem([string]$label, [string]$href) {
    if (-not $label) { return }
    $key = if ($href) { $href } else { $label }
    # Normalize GHSA keys so URL and bare id dedupe together
    if ($label -match '(GHSA-[a-z0-9-]+)') { $key = $Matches[1].ToUpperInvariant() }
    elseif ($label -match '(CVE-\d{4}-\d+)') { $key = $Matches[1].ToUpperInvariant() }
    elseif ($label -match '^(CWE-\d+)$') { $key = $Matches[1].ToUpperInvariant() }
    if (-not $seen.Add($key)) { return }
    [void]$items.Add([pscustomobject]@{ Label = $label; Href = $href })
  }

  foreach ($p in $Parts) {
    if (-not $p) { continue }
    # Pull URLs first (they may contain commas if poorly joined - match http(s) tokens)
    [regex]::Matches($p, 'https?://[^\s,;]+') | ForEach-Object {
      $url = $_.Value.TrimEnd('.,);]')
      $label = $url
      if ($url -match '(GHSA-[a-z0-9-]+)') { $label = $Matches[1].ToUpperInvariant() }
      elseif ($url -match '(CVE-\d{4}-\d+)') { $label = $Matches[1].ToUpperInvariant() }
      Add-AdvItem $label $url
    }
    foreach ($bit in ($p -split '[,;\s]+')) {
      $t = $bit.Trim().TrimEnd('.,);]')
      if (-not $t) { continue }
      if ($t -match '^https?://') { continue } # already handled
      if ($t -match '^(GHSA-[a-z0-9-]+)$') {
        $id = $Matches[1].ToUpperInvariant()
        Add-AdvItem $id ("https://github.com/advisories/$id")
      } elseif ($t -match '^(CVE-\d{4}-\d+)$') {
        $id = $Matches[1].ToUpperInvariant()
        Add-AdvItem $id ("https://www.cve.org/CVERecord?id=$id")
      } elseif ($t -match '^(CWE-\d+)$') {
        $id = $Matches[1].ToUpperInvariant()
        Add-AdvItem $id ("https://cwe.mitre.org/data/definitions/$($id.Substring(4)).html")
      } elseif ($t -match '^[A-Za-z].{2,}' -and $t -notmatch '^\d+$') {
        # Keep textual aliases (React2Shell, commit SHAs, etc.) - no link
        Add-AdvItem $t ''
      }
      # Skip bare numeric npm advisory source ids (e.g. 1115549) - not useful as a line
    }
  }
  return ,$items
}

function Format-AdvisoryHtml {
  param(
    [string]$Advisory,
    [string]$WrapperClass = 'detail'
  )
  if (-not $Advisory) { return '' }
  $items = Get-AdvisoryItems -Parts @($Advisory)
  if ($items.Count -eq 0) { return '' }
  $lis = New-Object System.Collections.Generic.List[string]
  foreach ($it in $items) {
    if ($it.Href) {
      [void]$lis.Add("<li><a href='" + (HtmlEncode $it.Href) + "' target='_blank' rel='noopener'>" + (HtmlEncode $it.Label) + "</a></li>")
    } else {
      [void]$lis.Add("<li><span>" + (HtmlEncode $it.Label) + "</span></li>")
    }
  }
  return "<div class='$WrapperClass advisory'><div class='adv-label'>Advisories</div><ul class='adv-list'>" + ($lis -join '') + "</ul></div>"
}

function Add-OsvFindings([string]$ecoLabel, [string]$osvEco, [string]$pkg, [string]$ver, [string]$path, [string]$source) {
  $vulns = Invoke-OsvQuery -ecosystem $osvEco -name $pkg -version $ver
  if ($vulns.Count -eq 0) { return }
  $sev = Get-OsvSeverity $vulns
  $idBits = New-Object System.Collections.Generic.List[string]
  foreach ($v in $vulns) {
    if ($v.id) { [void]$idBits.Add([string]$v.id) }
    foreach ($a in @($v.aliases)) { if ($a) { [void]$idBits.Add([string]$a) } }
    foreach ($a in @($v.related)) { if ($a) { [void]$idBits.Add([string]$a) } }
  }
  $title = ($vulns | ForEach-Object { if ($_.summary) { $_.summary } else { $_.id } } | Select-Object -First 1)
  $aliases = Get-KnownAdvisoryAliases -Package $pkg -Title ([string]$title) -Advisory ($idBits -join ', ')
  $ids = Join-AdvisoryText -Parts (@($idBits) + @($aliases))
  Add-Finding -Ecosystem $ecoLabel -Source $source -Severity $sev -Package $pkg -Version $ver -Title $title -Advisory $ids -Path $path -Fix 'Upgrade to a patched version (see advisory)'
}

function Get-NpmCacheRoots {
  $roots = New-Object System.Collections.Generic.List[string]
  try {
    $tmp = Join-Path $script:TempDir ("npm-cache-path-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    $npmBin = if ($script:IsWin) { 'npm.cmd' } else { 'npm' }
    [void](Invoke-NativeCommand -Command $npmBin -Arguments @('config', 'get', 'cache') -OutFile $tmp)
    if (Test-Path -LiteralPath $tmp) {
      $cfg = (Get-Content -LiteralPath $tmp -Raw).Trim()
      Remove-Item $tmp,"$tmp.err" -Force -ErrorAction SilentlyContinue
      if ($cfg -and $cfg -ne 'undefined' -and $cfg -ne 'null') { [void]$roots.Add($cfg) }
    }
  } catch {}
  $candidates = New-Object System.Collections.Generic.List[string]
  if ($script:IsWin) {
    foreach ($d in @(
        (Join-Path $env:LOCALAPPDATA 'npm-cache'),
        (Join-Path $env:APPDATA 'npm-cache'),
        (Join-Path $script:HomeDir '.npm')
      )) { if ($d) { [void]$candidates.Add($d) } }
  } else {
    foreach ($d in @(
        (Join-Path $script:HomeDir '.npm'),
        (Join-Path $script:HomeDir 'Library/Caches/npm'),
        (Join-Path $script:HomeDir '.local/share/npm-cache')
      )) { if ($d) { [void]$candidates.Add($d) } }
  }
  foreach ($d in $candidates) {
    if ($d -and (Test-Path -LiteralPath $d) -and ($roots -notcontains $d)) { [void]$roots.Add($d) }
  }
  return @($roots)
}

function Get-PackagesFromNpmCacache([string]$cacheRoot) {
  # Modern npm stores metadata in _cacache/index-v5 (hashed files), not node_modules trees.
  $found = New-Object System.Collections.Generic.List[object]
  $seenLocal = New-Object System.Collections.Generic.HashSet[string]
  $indexRoots = @(
    (Join-Path (Join-Path $cacheRoot '_cacache') 'index-v5'),
    (Join-Path (Join-Path $cacheRoot '_cacache') 'index-v6'),
    (Join-Path $cacheRoot 'index-v5')
  ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

  # registry.npmjs.org/<pkg>/-/<file>.tgz  (pkg may be scoped @scope/name)
  $rx = [regex]'registry\.npmjs\.org/(?<pkgPath>@[^/\"\s]+/[^/\"\s]+|[^/@\"\s]+)/-/(?<file>[^/\"\s]+?)\.tgz'

  foreach ($indexRoot in $indexRoots) {
    $files = @(Get-ChildItem -LiteralPath $indexRoot -File -Recurse -Force -ErrorAction SilentlyContinue)
    $i = 0
    foreach ($f in $files) {
      $i++
      if (($i % 200) -eq 0) {
        Show-LiveProgress 82 'Phase 4/4: Checking npm-cache' "cacache index $i/$($files.Count)"
      }
      try {
        $raw = [System.IO.File]::ReadAllText($f.FullName)
        if ($raw -notmatch '\.tgz') { continue }
        foreach ($m in $rx.Matches($raw)) {
          $pkgPath = [uri]::UnescapeDataString($m.Groups['pkgPath'].Value)
          $file = $m.Groups['file'].Value
          $base = ($pkgPath -split '/')[-1]
          $ver = $null
          if ($file.StartsWith("$base-")) {
            $ver = $file.Substring($base.Length + 1)
          } elseif ($file -match '-(\d+\.\d+\.\d+.*)$') {
            $ver = $Matches[1]
          }
          if (-not $pkgPath -or -not $ver) { continue }
          $key = "$pkgPath@$ver"
          if (-not $seenLocal.Add($key)) { continue }
          $found.Add([pscustomobject]@{ Name = $pkgPath; Version = $ver; SourcePath = $f.FullName }) | Out-Null
        }
      } catch {}
    }
  }
  return $found
}

function Get-PackagesFromYarnCache([string]$cacheRoot) {
  $found = New-Object System.Collections.Generic.List[object]
  $seenLocal = New-Object System.Collections.Generic.HashSet[string]
  # Yarn classic / berry often names archives like:
  #   npm-lodash-4.17.21-hash
  #   npm-@babel-core-7.22.0-hash.zip
  $files = @(Get-ChildItem -LiteralPath $cacheRoot -File -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^npm-' -and ($_.Extension -in @('.zip','.tgz','') -or $_.Name -match '^npm-.+-[0-9a-f]{8,}') })
  # Also plain .tgz with registry-style names
  $files += @(Get-ChildItem -LiteralPath $cacheRoot -Filter '*.tgz' -Recurse -Force -ErrorAction SilentlyContinue)

  foreach ($f in $files) {
    $pkg = $null; $ver = $null
    $base = [IO.Path]::GetFileNameWithoutExtension($f.Name)

    if ($base -match '^npm-(@?[^-].*)$') {
      # Strip trailing integrity hash: -deadbeef... (8+ hex)
      $body = $base.Substring(4) # after npm-
      if ($body -match '^(?<name>.+)-(?<ver>\d+\.\d+\.\d+[^-]*)-(?<hash>[0-9a-f]{8,})$') {
        $rawName = $Matches.name
        $ver = $Matches.ver
        if ($rawName.StartsWith('@') -and $rawName -match '^@([^-]+)-(.+)$') {
          $pkg = "@$($Matches[1])/$($Matches[2])"
        } else {
          $pkg = $rawName
        }
      }
    } elseif ($base -match '^(?<name>.+)-(?<ver>\d+\.\d+\.\d+.*)$' -and $f.Extension -eq '.tgz') {
      $pkg = $Matches.name
      $ver = $Matches.ver
    }

    if (-not $pkg -or -not $ver) { continue }
    $key = "$pkg@$ver"
    if (-not $seenLocal.Add($key)) { continue }
    $found.Add([pscustomobject]@{ Name = $pkg; Version = $ver; SourcePath = $f.FullName }) | Out-Null
  }
  return $found
}

# -------------------- roots --------------------
if ($Drive.Count -eq 0) {
  if ($script:IsMac) {
    # Default to home + mounted volumes (avoid scanning entire /)
    $roots = New-Object System.Collections.Generic.List[string]
    [void]$roots.Add($script:HomeDir)
    $volRoot = '/Volumes'
    if (Test-Path -LiteralPath $volRoot) {
      Get-ChildItem -LiteralPath $volRoot -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name -notmatch '^(Macintosh HD|com\.apple)') { [void]$roots.Add($_.FullName) }
      }
    }
    $roots = @($roots)
  } else {
    $roots = @(Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } | ForEach-Object { $_.Root })
  }
} else {
  $roots = @($Drive | ForEach-Object {
      if ($script:IsWin -and $_ -match '^[A-Za-z]$') { "${_}:\" }
      else { $_ }
    })
}

$script:logEntries.Clear()
Add-LogEntry -Message 'Scan started' -Kind 'phase'
Save-ProgressHtml
if ($script:GuiMode) {
  Write-Output 'LOG|phase|Scan started'
  Write-Output ("LOG|info|Platform: {0}" -f $script:OsLabel)
  Write-Output ("LOG|info|HTML report: {0}" -f $outHtml)
  Write-GuiProgressFile
} else {
  Write-Host ''
  Write-Host '============================================================' -ForegroundColor Green
  Write-Host '  MULTI-LANGUAGE VULNERABLE LIBRARY SCANNER' -ForegroundColor Green
  Write-Host ("  Platform: {0}" -f $script:OsLabel) -ForegroundColor Green
  Write-Host '============================================================' -ForegroundColor Green
  Write-Log "Roots: $($roots -join ', ')" 'White'
  Write-Log "HTML report: $outHtml" 'White'
  Write-Host 'Progress stays on ONE line below (spinner + %). Please wait...' -ForegroundColor DarkGray
  Initialize-ProgressLine
}
Show-LiveProgress -Percent 1 -Status 'Phase 1/4: Detecting languages' -Current 'Starting...'

# =============================================================================
# PHASE 1 — Detect languages by walking folders and finding manifests
# =============================================================================

$langHints = [ordered]@{
  'JavaScript/TypeScript' = @{
    Eco = 'npm'
    ManifestNames = @('package.json','package-lock.json','yarn.lock','pnpm-lock.yaml')
    SourceExt = @('.ts','.tsx','.js','.jsx','.mjs','.cjs')
  }
  'C#/.NET' = @{
    Eco = 'nuget'
    ManifestNames = @('packages.config','Directory.Packages.props')
    ManifestExt = @('.csproj','.fsproj','.vbproj','.sln')
    SourceExt = @('.cs','.fs')
  }
  'Python' = @{
    Eco = 'PyPI'
    ManifestNames = @('requirements.txt','Pipfile','Pipfile.lock','pyproject.toml','poetry.lock','environment.yml')
    SourceExt = @('.py')
  }
  'Java/Kotlin' = @{
    Eco = 'Maven'
    ManifestNames = @('pom.xml','build.gradle','build.gradle.kts')
    SourceExt = @('.java','.kt')
  }
  'Go' = @{
    Eco = 'Go'
    ManifestNames = @('go.mod','go.sum')
    SourceExt = @('.go')
  }
  'Rust' = @{
    Eco = 'crates.io'
    ManifestNames = @('Cargo.toml','Cargo.lock')
    SourceExt = @('.rs')
  }
  'PHP' = @{
    Eco = 'Packagist'
    ManifestNames = @('composer.json','composer.lock')
    SourceExt = @('.php')
  }
  'Ruby' = @{
    Eco = 'RubyGems'
    ManifestNames = @('Gemfile','Gemfile.lock')
    SourceExt = @('.rb')
  }
  'Dart/Flutter' = @{
    Eco = 'Pub'
    ManifestNames = @('pubspec.yaml','pubspec.lock')
    SourceExt = @('.dart')
  }
  'Swift' = @{
    Eco = 'Swift'
    ManifestNames = @('Package.swift','Package.resolved')
    SourceExt = @('.swift')
  }
  'Scala' = @{
    Eco = 'Scala'
    ManifestNames = @('build.sbt','plugins.sbt')
    SourceExt = @('.scala','.sc')
  }
}

$fileCounts = @{}
$manifestHits = @{}
foreach ($k in $langHints.Keys) {
  $fileCounts[$k] = 0
  $manifestHits[$k] = New-Object System.Collections.Generic.List[string]
}

# Build skip name set for fast checks (editor extensions, caches, system junk)
$skipDirNames = [System.Collections.Generic.HashSet[string]]::new([string[]]@(
  'Windows','WinSxS','$Recycle.Bin','System Volume Information','Recovery','PerfLogs','Windows.old',
  'node_modules','.git','bin','obj','.vs','.idea','INetCache','Temporary Internet Files',
  'Chrome','Edge','Firefox','BraveSoftware','Opera Software',
  'AppData','.cursor','.vscode','.nuget','.npm','.yarn','.cache','.codex','.claude','.agents','.gemini','.copilot',
  '.codemoss','extensions','Program Files','Program Files (x86)','ProgramData','Temp','Packages','Package Cache',
  'Microsoft','WindowsApps','Intel','AMD','NVIDIA Corporation','Common Files',
  # macOS
  'Applications','Library','System','private','cores','.Trash','Caches','Containers','Group Containers',
  'Photos Library.photoslibrary','Mail','Messages','iCloud Drive (Archive)'
), [StringComparer]::OrdinalIgnoreCase)

function Test-ShouldSkipDir([string]$fullName, [string]$name) {
  if ($skipDirNames.Contains($name)) { return $true }
  if ($skipRegex.IsMatch($fullName)) { return $true }
  if ($fullName -match '(?i)[\\/](\.cursor|\.vscode)[\\/]extensions[\\/]') { return $true }
  if ($fullName -match '(?i)[\\/]\.nuget[\\/]packages[\\/]') { return $true }
  return $false
}

# Prefer useful roots first
$preferredCandidates = @(
  $script:HomeDir,
  (Join-Path $script:HomeDir 'Desktop'),
  (Join-Path $script:HomeDir 'Documents'),
  (Join-Path $script:HomeDir 'Downloads'),
  (Join-Path $script:HomeDir 'source'),
  (Join-Path $script:HomeDir 'src'),
  (Join-Path $script:HomeDir 'Projects'),
  (Join-Path $script:HomeDir 'Developer'),
  (Join-Path $script:HomeDir 'repos'),
  (Join-Path $script:HomeDir 'code')
)
if ($script:IsWin) {
  $preferredCandidates += @('C:\GeoWeb2','C:\Projects','C:\Dev','C:\src','C:\Repos')
}
$preferred = @($preferredCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)

$walkRoots = New-Object System.Collections.Generic.List[string]
foreach ($p in $preferred) { if ($walkRoots -notcontains $p) { $walkRoots.Add($p) | Out-Null } }
foreach ($r in $roots) {
  # If root is C:\, still walk it but after preferred paths; avoid duplicate preferred
  if ($walkRoots -notcontains $r) { $walkRoots.Add($r) | Out-Null }
}

$foldersSeen = 0
$manifestsFound = 0
$sourceHits = 0
$maxSourceSamplesPerLang = 200
$queue = New-Object System.Collections.Generic.Queue[string]
$visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

foreach ($wr in $walkRoots) {
  if ($visited.Add($wr)) { $queue.Enqueue($wr) }
}

Write-Log "Phase 1 folder walk started..." 'White'
Show-LiveProgress -Percent 1 -Status 'Phase 1/4: Detecting languages' -Current 'Walking folders...'

while ($queue.Count -gt 0) {
  $dir = $queue.Dequeue()
  $foldersSeen++

  # Update the single progress line (throttled inside Show-LiveProgress)
  $pct = 1 + [Math]::Min(13, [int](13 * [Math]::Log(1 + $foldersSeen) / [Math]::Log(1 + 5000)))
  Show-LiveProgress -Percent $pct -Status 'Phase 1/4: Detecting languages' -Current ("folders=$foldersSeen projects=$manifestsFound now=$dir")

  # List files in this folder only (no deep recurse) so UI can update between folders
  $files = @()
  try { $files = @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue) } catch {}
  foreach ($f in $files) {
    $name = $f.Name
    $ext = $f.Extension

    foreach ($lang in $langHints.Keys) {
      $meta = $langHints[$lang]
      $isManifest = $false
      if ($meta.ManifestNames -contains $name) { $isManifest = $true }
      if ($meta.ManifestExt -and ($meta.ManifestExt -contains $ext)) { $isManifest = $true }

      if ($isManifest) {
        if ($f.FullName -match '[\\/]node_modules[\\/]') { continue }
        if ($f.FullName -match '(?i)\\(\.cursor|\.vscode)\\extensions\\') { continue }
        $manifestHits[$lang].Add($f.FullName) | Out-Null
        $manifestsFound++
      }

      if ($fileCounts[$lang] -lt $maxSourceSamplesPerLang -and $meta.SourceExt -contains $ext) {
        $fileCounts[$lang]++
        $sourceHits++
        $stats.FilesSampled++
      }
    }
  }

  # Enqueue children
  $subs = @()
  try { $subs = @(Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue) } catch {}
  foreach ($sub in $subs) {
    if (Test-ShouldSkipDir $sub.FullName $sub.Name) { continue }
    if ($visited.Add($sub.FullName)) {
      $queue.Enqueue($sub.FullName)
    }
  }
}

Show-LiveProgress -Percent 14 -Status 'Phase 1/4: Detecting languages' -Current "Done walking. folders=$foldersSeen manifests=$manifestsFound"
Write-Host ''
Write-Log "Folder walk complete: folders=$foldersSeen manifests=$manifestsFound sourceSamples=$sourceHits" 'Green'

Write-Host ''
Write-Host '--- Detected languages ---' -ForegroundColor Green
foreach ($lang in $langHints.Keys) {
  $files = $fileCounts[$lang]
  $mans = @($manifestHits[$lang] | Select-Object -Unique)
  $active = ($files -gt 0) -or ($mans.Count -gt 0)
  if ($active) {
    $detected[$lang] = @{
      Eco = $langHints[$lang].Eco
      Files = $files
      Manifests = $mans
    }
    Write-Log ("  {0,-22} sourceFiles~{1,-5} projects/manifests={2}" -f $lang, $files, $mans.Count) 'Green'
  }
  # intentionally hide languages with no hits
}
Write-Host ''

if ($detected.Count -eq 0) {
  Write-Log 'No development languages detected. Exiting.' 'Yellow'
  Add-LogEntry -Message 'No development languages detected. Exiting.' -Kind 'warn'
  Save-ProgressHtml
  Show-UserNotification 'Vulnerability scan' 'No programming projects detected on this computer.'
  Write-Progress -Activity 'Vulnerable library scan' -Completed
  try { [void](Open-ReportFile $outHtml) } catch {}
  return
}

# =============================================================================
# PHASE 2 — Collect project folders per ecosystem
# =============================================================================
Show-LiveProgress 15 'Phase 2/4: Finding projects' 'Grouping manifests into projects...'
$projects = [ordered]@{}
foreach ($lang in $detected.Keys) {
  $eco = $detected[$lang].Eco
  if (-not $projects.Contains($eco)) { $projects[$eco] = New-Object System.Collections.Generic.List[string] }
  foreach ($m in $detected[$lang].Manifests) {
    $dir = Split-Path -Parent $m
    # For csproj, project dir is fine; for package.json same
    if ($projects[$eco] -notcontains $dir -and $projects[$eco].Count -lt $MaxProjectsPerEco) {
      $projects[$eco].Add($dir) | Out-Null
    }
  }
  Show-LiveProgress 18 'Phase 2/4: Finding projects' "$lang / $eco => $($projects[$eco].Count) project folder(s)"
}
foreach ($eco in @($projects.Keys)) { $stats.Projects += $projects[$eco].Count }

# =============================================================================
# PHASE 3 — Audit each ecosystem
# =============================================================================
Show-LiveProgress 20 'Phase 3/4: Auditing libraries' 'Preparing tooling...'

$npmExtra = if ($script:IsWin) {
  @("$env:ProgramFiles\nodejs\npm.cmd", "$env:APPDATA\npm\npm.cmd")
} else {
  @('/usr/local/bin/npm', '/opt/homebrew/bin/npm', (Join-Path $script:HomeDir '.nvm/current/bin/npm'))
}
$yarnExtra = if ($script:IsWin) {
  @("$env:APPDATA\npm\yarn.cmd", "$env:LOCALAPPDATA\Yarn\bin\yarn.cmd")
} else {
  @('/usr/local/bin/yarn', '/opt/homebrew/bin/yarn')
}
$dotnetExtra = if ($script:IsWin) {
  @("$env:ProgramFiles\dotnet\dotnet.exe")
} else {
  @('/usr/local/share/dotnet/dotnet', '/opt/homebrew/bin/dotnet')
}
$pythonExtra = if ($script:IsWin) {
  @("$env:LOCALAPPDATA\Programs\Python\Python312\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe")
} else {
  @('/usr/bin/python3', '/opt/homebrew/bin/python3', '/usr/local/bin/python3')
}

$npmCmd     = Get-Cmd 'npm' $npmExtra
$yarnCmd    = Get-Cmd 'yarn' $yarnExtra
$dotnetCmd  = Get-Cmd 'dotnet' $dotnetExtra
$pythonCmd  = Get-Cmd $(if ($script:IsMac) { 'python3' } else { 'python' }) $pythonExtra
if (-not $pythonCmd) { $pythonCmd = Get-Cmd 'python3' $pythonExtra }
if (-not $pythonCmd) { $pythonCmd = Get-Cmd 'python' $pythonExtra }
$pipCmd     = Get-Cmd 'pip' @()
if (-not $pipCmd) { $pipCmd = Get-Cmd 'pip3' @() }
$pipAudit   = Get-Cmd 'pip-audit' @()
$goCmd      = Get-Cmd 'go' @()
$govuln     = Get-Cmd 'govulncheck' @()
$cargoCmd   = Get-Cmd 'cargo' @()
$composer   = Get-Cmd 'composer' @()
$bundleCmd  = Get-Cmd 'bundle' @()

Write-QuietLog "Tools: npm=$(!!$npmCmd) yarn=$(!!$yarnCmd) dotnet=$(!!$dotnetCmd) python=$(!!$pythonCmd) pip-audit=$(!!$pipAudit) go=$(!!$goCmd) govulncheck=$(!!$govuln) cargo=$(!!$cargoCmd) composer=$(!!$composer)"
Show-LiveProgress 20 'Phase 3/4: Auditing libraries' 'Starting audits...'

$ecoList = @($projects.Keys)
$ecoIndex = 0
foreach ($eco in $ecoList) {
  $ecoIndex++
  $dirs = @($projects[$eco])
  $basePct = 20 + [int](50 * ($ecoIndex - 1) / [Math]::Max(1, $ecoList.Count))

  Show-LiveProgress $basePct "Phase 3/4: Auditing $eco" "Projects: $($dirs.Count)"

  # ----- npm / JS/TS -----
  if ($eco -eq 'npm') {
    $di = 0
    foreach ($dir in $dirs) {
      $di++
      $pct = $basePct + [int]((50 / [Math]::Max(1,$ecoList.Count)) * $di / [Math]::Max(1,$dirs.Count))
      Show-LiveProgress $pct 'Phase 3/4: Auditing npm/JS/TS' "[$di/$($dirs.Count)] $dir"

      $ran = $false
      if ($npmCmd -and ((Test-Path (Join-Path $dir 'package-lock.json')) -or (Test-Path (Join-Path $dir 'node_modules')) -or (Test-Path (Join-Path $dir 'package.json')))) {
        try {
          $tmp = Join-Path $script:TempDir ("audit-npm-{0}.json" -f [guid]::NewGuid().ToString('N'))
          $err = "$tmp.err"
          [void](Invoke-NativeCommand -Command $(if ($npmCmd) { $npmCmd } else { 'npm' }) -Arguments @('audit','--json') -WorkingDirectory $dir -OutFile $tmp)
          if (Test-Path $tmp) {
            $raw = Get-Content -LiteralPath $tmp -Raw
            Remove-Item $tmp,$err -Force -ErrorAction SilentlyContinue
            if ($raw -and $raw.Trim().StartsWith('{')) {
              $audit = $raw | ConvertFrom-Json
              $ran = $true
              if ($audit.vulnerabilities) {
                foreach ($p in $audit.vulnerabilities.PSObject.Properties) {
                  $v = $p.Value
                  $sev = [string]$v.severity
                  $title = $p.Name
                  $fix = $v.fixAvailable
                  $advBits = New-Object System.Collections.Generic.List[string]
                  if ($v.via -is [Array]) {
                    foreach ($item in $v.via) {
                      if ($item -isnot [string]) {
                        if ($item.title) { $title = [string]$item.title }
                        if ($item.url) { [void]$advBits.Add([string]$item.url) }
                        if ($item.source) { [void]$advBits.Add([string]$item.source) }
                        if ($item.severity) { $sev = [string]$item.severity }
                        foreach ($cwe in @($item.cwe)) { if ($cwe) { [void]$advBits.Add([string]$cwe) } }
                      } else {
                        [void]$advBits.Add([string]$item)
                      }
                    }
                  }
                  $url = Join-AdvisoryText -Parts @($advBits)
                  Add-Finding -Ecosystem 'npm' -Source 'npm-audit' -Severity $sev -Package $p.Name -Version ([string]$v.range) -Title $title -Advisory $url -Path $dir -Fix $fix
                }
              } elseif ($audit.advisories) {
                foreach ($p in $audit.advisories.PSObject.Properties) {
                  $a = $p.Value
                  $advBits = New-Object System.Collections.Generic.List[string]
                  if ($a.url) { [void]$advBits.Add([string]$a.url) }
                  if ($a.github_advisory_id) { [void]$advBits.Add([string]$a.github_advisory_id) }
                  if ($a.cves) { foreach ($c in @($a.cves)) { if ($c) { [void]$advBits.Add([string]$c) } } }
                  if ($a.cve) { [void]$advBits.Add([string]$a.cve) }
                  Add-Finding -Ecosystem 'npm' -Source 'npm-audit' -Severity ([string]$a.severity) -Package ([string]$a.module_name) -Version ([string]$a.findings[0].version) -Title ([string]$a.title) -Advisory (Join-AdvisoryText -Parts @($advBits)) -Path $dir -Fix ([string]$a.recommendation)
                }
              }
            } else {
              Write-QuietLog "npm audit produced no JSON in $dir"
            }
          }
        } catch {
          Write-QuietLog "npm audit error in $dir : $($_.Exception.Message)"
          Show-LiveProgress $pct 'Phase 3/4: Auditing npm/JS/TS' "[$di/$($dirs.Count)] audit failed, continuing..."
        }
      }

      if (-not $ran -and $yarnCmd -and (Test-Path (Join-Path $dir 'yarn.lock'))) {
        try {
          $tmp = Join-Path $script:TempDir ("audit-yarn-{0}.json" -f [guid]::NewGuid().ToString('N'))
          $err = "$tmp.err"
          [void](Invoke-NativeCommand -Command $(if ($yarnCmd) { $yarnCmd } else { 'yarn' }) -Arguments @('audit','--json') -WorkingDirectory $dir -OutFile $tmp)
          if (Test-Path $tmp) {
            Get-Content $tmp | ForEach-Object {
              try {
                $line = $_ | ConvertFrom-Json
                if ($line.type -eq 'auditAdvisory') {
                  $a = $line.data.advisory
                  Add-Finding -Ecosystem 'npm' -Source 'yarn-audit' -Severity ([string]$a.severity) -Package ([string]$a.module_name) -Version ([string]$a.findings[0].version) -Title ([string]$a.title) -Advisory ([string]$a.url) -Path $dir -Fix ([string]$a.recommendation)
                }
              } catch {}
            }
            Remove-Item $tmp,$err -Force -ErrorAction SilentlyContinue
            $ran = $true
          }
        } catch {
          Write-QuietLog "yarn audit error in $dir : $($_.Exception.Message)"
        }
      }

      # Fallback: parse package.json deps and OSV-check direct deps (best effort)
      if (-not $SkipOsv) {
        $pj = Join-Path $dir 'package.json'
        if (Test-Path $pj) {
          try {
            $j = Get-Content $pj -Raw | ConvertFrom-Json
            foreach ($sec in @('dependencies','devDependencies')) {
              if (-not $j.$sec) { continue }
              foreach ($prop in $j.$sec.PSObject.Properties) {
                $ver = ([string]$prop.Value) -replace '^[~^>=<\s]+',''
                if ($ver -match '^\d') {
                  Show-LiveProgress $pct 'Phase 3/4: Auditing npm via OSV' "$($prop.Name)@$ver"
                  Add-OsvFindings 'npm' 'npm' $prop.Name $ver $pj 'osv-package.json'
                }
              }
            }
          } catch {}
        }
      }
    }
  }

  # ----- NuGet / .NET -----
  elseif ($eco -eq 'nuget') {
    $di = 0
    foreach ($dir in $dirs) {
      $di++
      $pct = $basePct + [int]((50 / [Math]::Max(1,$ecoList.Count)) * $di / [Math]::Max(1,$dirs.Count))
      Show-LiveProgress $pct 'Phase 3/4: Auditing NuGet/.NET' "[$di/$($dirs.Count)] $dir"

      if ($dotnetCmd) {
        try {
          $tmp = Join-Path $script:TempDir ("dotnet-vuln-{0}.txt" -f [guid]::NewGuid().ToString('N'))
          Start-Process -FilePath $dotnetCmd -ArgumentList @('list','package','--vulnerable','--include-transitive') -WorkingDirectory $dir -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmp -RedirectStandardError $script:DevNull | Out-Null
          if (Test-Path $tmp) {
            $content = Get-Content $tmp
            Remove-Item $tmp -Force
            $currentPkg = ''
            foreach ($line in $content) {
              if ($line -match '^\s*>\s*(\S+)\s+(\S+)') {
                $currentPkg = $Matches[1]
                $ver = $Matches[2]
                Add-Finding -Ecosystem 'nuget' -Source 'dotnet-list-vulnerable' -Severity 'high' -Package $currentPkg -Version $ver -Title 'Vulnerable NuGet package reported by dotnet' -Advisory '' -Path $dir -Fix 'dotnet add package with patched version'
              } elseif ($line -match '^\s+(\S+)\s+(\S+)' -and $currentPkg) {
                # advisory line variants - keep simple
              }
            }
            if ($content -match 'has the following vulnerable packages|Vulnerable') {
              Write-QuietLog "dotnet reported vulnerable packages in $dir"
              Show-LiveProgress $pct 'Phase 3/4: Auditing NuGet/.NET' "[$di/$($dirs.Count)] vulns found in $dir"
            } else {
              Write-QuietLog "dotnet: no vulnerable packages listed in $dir"
            }
          }
        } catch {
          Write-QuietLog "dotnet list failed in $dir : $($_.Exception.Message)"
        }
      }

      # Parse PackageReference from csproj for OSV
      if (-not $SkipOsv) {
        Get-ChildItem -LiteralPath $dir -Filter '*.csproj' -File -ErrorAction SilentlyContinue | ForEach-Object {
          Show-LiveProgress $pct 'Phase 3/4: Auditing NuGet via OSV' $_.Name
          try {
            [xml]$xml = Get-Content -LiteralPath $_.FullName -Raw
            $refs = $xml.SelectNodes('//PackageReference')
            foreach ($r in $refs) {
              $id = $r.GetAttribute('Include'); if (-not $id) { $id = $r.GetAttribute('Update') }
              $ver = $r.GetAttribute('Version')
              if ($id -and $ver) { Add-OsvFindings 'nuget' 'NuGet' $id $ver $_.FullName 'osv-csproj' }
            }
          } catch {}
        }
        $pkgConfig = Join-Path $dir 'packages.config'
        if (Test-Path $pkgConfig) {
          try {
            [xml]$xml = Get-Content $pkgConfig -Raw
            foreach ($p in $xml.packages.package) {
              Add-OsvFindings 'nuget' 'NuGet' $p.id $p.version $pkgConfig 'osv-packages.config'
            }
          } catch {}
        }
      }
    }
  }

  # ----- Python -----
  elseif ($eco -eq 'PyPI') {
    $di = 0
    foreach ($dir in $dirs) {
      $di++
      $pct = $basePct + [int]((50 / [Math]::Max(1,$ecoList.Count)) * $di / [Math]::Max(1,$dirs.Count))
      Show-LiveProgress $pct 'Phase 3/4: Auditing Python' "[$di/$($dirs.Count)] $dir"

      if ($pipAudit) {
        try {
          $tmp = Join-Path $script:TempDir ("pip-audit-{0}.json" -f [guid]::NewGuid().ToString('N'))
          $req = Join-Path $dir 'requirements.txt'
          $args = @('-f','json')
          if (Test-Path $req) { $args = @('-r', $req, '-f', 'json') }
          Start-Process -FilePath $pipAudit -ArgumentList $args -WorkingDirectory $dir -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmp -RedirectStandardError $script:DevNull | Out-Null
          if (Test-Path $tmp) {
            $data = Get-Content $tmp -Raw | ConvertFrom-Json
            Remove-Item $tmp -Force
            foreach ($row in @($data)) {
              $pkg = [string]$row.name
              $ver = [string]$row.version
              foreach ($v in @($row.vulns)) {
                Add-Finding -Ecosystem 'PyPI' -Source 'pip-audit' -Severity 'high' -Package $pkg -Version $ver -Title ([string]$v.description) -Advisory (($v.id) -join ', ') -Path $dir -Fix $(
                  $fixed = @($v.fix_versions | Where-Object { $_ })
                  if ($fixed.Count -gt 0) { ($fixed -join ', ') } else { 'No fixed version listed by pip-audit yet. Check the advisory and pin a safe release when available.' }
                )
              }
            }
          }
        } catch { Write-QuietLog "pip-audit failed in $dir" }
      }

      if (-not $SkipOsv) {
        $req = Join-Path $dir 'requirements.txt'
        if (Test-Path $req) {
          Get-Content $req | ForEach-Object {
            $line = $_.Trim()
            if ($line -match '^\s*#' -or -not $line) { return }
            if ($line -match '^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)') {
              Show-LiveProgress $pct 'Phase 3/4: Auditing Python via OSV' "$($Matches[1])==$($Matches[2])"
              Add-OsvFindings 'PyPI' 'PyPI' $Matches[1] $Matches[2] $req 'osv-requirements'
            }
          }
        }
      }
    }
  }

  # ----- Go -----
  elseif ($eco -eq 'Go') {
    foreach ($dir in $dirs) {
      Show-LiveProgress ($basePct + 5) 'Phase 3/4: Auditing Go' $dir
      if ($govuln) {
        try {
          $tmp = Join-Path $script:TempDir ("govuln-{0}.json" -f [guid]::NewGuid().ToString('N'))
          Start-Process -FilePath $govuln -ArgumentList @('-json','./...') -WorkingDirectory $dir -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmp -RedirectStandardError $script:DevNull | Out-Null
          if (Test-Path $tmp) {
            Get-Content $tmp | ForEach-Object {
              try {
                $o = $_ | ConvertFrom-Json
                if ($o.finding -or $o.osv) {
                  $id = if ($o.osv) { [string]$o.osv } else { 'govulncheck' }
                  Add-Finding -Ecosystem 'Go' -Source 'govulncheck' -Severity 'high' -Package $id -Version '' -Title 'Go vulnerability finding' -Advisory $id -Path $dir -Fix 'Run: go get -u <module>  then go mod tidy. Check https://pkg.go.dev/vuln for patched versions.'
                }
              } catch {}
            }
            Remove-Item $tmp -Force
          }
        } catch { Write-QuietLog "govulncheck failed in $dir" }
      }
      $gomod = Join-Path $dir 'go.mod'
      if ((Test-Path $gomod) -and -not $SkipOsv) {
        Get-Content $gomod | ForEach-Object {
          if ($_ -match '^\s*([^\s]+)\s+v([0-9][^\s]+)') {
            Add-OsvFindings 'Go' 'Go' $Matches[1] ("v" + $Matches[2]) $gomod 'osv-go.mod'
          }
        }
      }
    }
  }

  # ----- Rust -----
  elseif ($eco -eq 'crates.io') {
    foreach ($dir in $dirs) {
      Show-LiveProgress ($basePct + 5) 'Phase 3/4: Auditing Rust' $dir
      if ($cargoCmd) {
        $cargoAudit = Get-Cmd 'cargo-audit' @()
        # `cargo audit` if installed as subcommand
        try {
          $tmp = Join-Path $script:TempDir ("cargo-audit-{0}.json" -f [guid]::NewGuid().ToString('N'))
          Start-Process -FilePath $cargoCmd -ArgumentList @('audit','--json') -WorkingDirectory $dir -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmp -RedirectStandardError $script:DevNull | Out-Null
          if ((Test-Path $tmp) -and (Get-Item $tmp).Length -gt 2) {
            $raw = Get-Content $tmp -Raw | ConvertFrom-Json
            Remove-Item $tmp -Force
            foreach ($v in @($raw.vulnerabilities.list)) {
              Add-Finding -Ecosystem 'crates.io' -Source 'cargo-audit' -Severity ([string]$v.advisory.severity) -Package ([string]$v.advisory.package) -Version '' -Title ([string]$v.advisory.title) -Advisory ([string]$v.advisory.id) -Path $dir -Fix 'Run: cargo update -p <package>  (or bump version in Cargo.toml to a patched release)'
            }
          }
        } catch { Write-QuietLog "cargo audit not available or failed in $dir" }
      }
    }
  }

  # ----- PHP -----
  elseif ($eco -eq 'Packagist') {
    foreach ($dir in $dirs) {
      Show-LiveProgress ($basePct + 5) 'Phase 3/4: Auditing PHP' $dir
      if ($composer) {
        try {
          $tmp = Join-Path $script:TempDir ("composer-audit-{0}.json" -f [guid]::NewGuid().ToString('N'))
          Start-Process -FilePath $composer -ArgumentList @('audit','--format=json') -WorkingDirectory $dir -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmp -RedirectStandardError $script:DevNull | Out-Null
          if (Test-Path $tmp) {
            $raw = Get-Content $tmp -Raw | ConvertFrom-Json
            Remove-Item $tmp -Force
            if ($raw.advisories) {
              foreach ($prop in $raw.advisories.PSObject.Properties) {
                foreach ($a in @($prop.Value)) {
                  Add-Finding -Ecosystem 'Packagist' -Source 'composer-audit' -Severity 'high' -Package $prop.Name -Version '' -Title ([string]$a.title) -Advisory ([string]$a.advisoryId) -Path $dir -Fix 'Run: composer update <package>  (or set a safe constraint in composer.json)'
                }
              }
            }
          }
        } catch { Write-QuietLog "composer audit failed in $dir" }
      }
    }
  }

  # ----- Ruby -----
  elseif ($eco -eq 'RubyGems') {
    foreach ($dir in $dirs) {
      Show-LiveProgress ($basePct + 5) 'Phase 3/4: Auditing Ruby' $dir
      Write-QuietLog "Ruby: bundler-audit not used; skipping deep check in $dir"
    }
  }

  # ----- Maven -----
  elseif ($eco -eq 'Maven') {
    foreach ($dir in $dirs) {
      Show-LiveProgress ($basePct + 5) 'Phase 3/4: Auditing Java/Maven' $dir
      $pom = Join-Path $dir 'pom.xml'
      if ((Test-Path $pom) -and -not $SkipOsv) {
        try {
          [xml]$xml = Get-Content $pom -Raw
          foreach ($dep in $xml.SelectNodes('//dependency')) {
            $g = $dep.groupId.'#text'; if (-not $g) { $g = $dep.groupId }
            $a = $dep.artifactId.'#text'; if (-not $a) { $a = $dep.artifactId }
            $v = $dep.version.'#text'; if (-not $v) { $v = $dep.version }
            if ($g -and $a -and $v -and $v -notmatch '^\$\{') {
              Add-OsvFindings 'Maven' 'Maven' "${g}:${a}" $v $pom 'osv-pom'
            }
          }
        } catch { Write-QuietLog "pom parse/OSV failed in $dir" }
      }
    }
  }

  elseif ($eco -eq 'Pub') {
    foreach ($dir in $dirs) {
      Show-LiveProgress ($basePct + 5) 'Phase 3/4: Auditing Dart/Flutter' $dir
      $lock = Join-Path $dir 'pubspec.lock'
      if ((Test-Path $lock) -and -not $SkipOsv) {
        $name = $null
        Get-Content -LiteralPath $lock | ForEach-Object {
          if ($_ -match '^\s{2}([A-Za-z0-9_]+):\s*$') { $name = $Matches[1]; return }
          if ($name -and $_ -match '^\s+version:\s*"([^"]+)"') {
            if ($name -notin @('sdks','packages')) {
              Add-OsvFindings 'Pub' 'Pub' $name $Matches[1] $lock 'osv-pubspec.lock'
            }
            $name = $null
          }
        }
      }
    }
  }

  elseif ($eco -eq 'Swift') {
    foreach ($dir in $dirs) {
      Show-LiveProgress ($basePct + 5) 'Phase 3/4: Auditing Swift' $dir
      $resolved = Join-Path $dir 'Package.resolved'
      if ((Test-Path $resolved) -and -not $SkipOsv) {
        try {
          $json = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
          $pins = @()
          if ($json.object.pins) { $pins = @($json.object.pins) }
          elseif ($json.pins) { $pins = @($json.pins) }
          foreach ($pin in $pins) {
            $pkg = if ($pin.package) { [string]$pin.package } elseif ($pin.identity) { [string]$pin.identity } else { $null }
            $ver = $null
            if ($pin.state.version) { $ver = [string]$pin.state.version }
            elseif ($pin.version) { $ver = [string]$pin.version }
            $loc = if ($pin.location) { [string]$pin.location } elseif ($pin.repositoryURL) { [string]$pin.repositoryURL } else { $pkg }
            if ($loc -and $ver) {
              Add-OsvFindings 'Swift' 'SwiftURL' $loc $ver $resolved 'osv-Package.resolved'
            }
          }
        } catch { Write-QuietLog "Swift Package.resolved parse failed in $dir" }
      }
    }
  }

  elseif ($eco -eq 'Scala') {
    foreach ($dir in $dirs) {
      Show-LiveProgress ($basePct + 5) 'Phase 3/4: Auditing Scala' $dir
      $sbt = Join-Path $dir 'build.sbt'
      if ((Test-Path $sbt) -and -not $SkipOsv) {
        Get-Content -LiteralPath $sbt | ForEach-Object {
          if ($_ -match '"([^"]+)"\s*%{1,3}\s*"([^"]+)"\s*%\s*"([^"]+)"') {
            Add-OsvFindings 'Scala' 'Maven' "$($Matches[1]):$($Matches[2])" $Matches[3] $sbt 'osv-build.sbt'
          }
        }
      }
    }
  }
}

# =============================================================================
# PHASE 4 — Package manager caches
# =============================================================================
if (-not $SkipCache) {
  Show-LiveProgress 75 'Phase 4/4: Checking caches' 'Looking for npm / Yarn / NuGet / pip caches...'

  $npmCacheRoots = @(Get-NpmCacheRoots)
  $cacheTargets = New-Object System.Collections.Generic.List[object]
  foreach ($root in $npmCacheRoots) {
    $cacheTargets.Add(@{ Path = $root; Eco = 'npm-cacache'; Osv = 'npm'; Label = 'npm-cache' }) | Out-Null
  }
  $yarnPaths = New-Object System.Collections.Generic.List[string]
  if ($env:LOCALAPPDATA) {
    [void]$yarnPaths.Add((Join-Path $env:LOCALAPPDATA 'Yarn\Cache'))
    [void]$yarnPaths.Add((Join-Path $env:LOCALAPPDATA 'Yarn\Cache\v6'))
  }
  [void]$yarnPaths.Add((Join-Path $script:HomeDir '.yarn/berry/cache'))
  [void]$yarnPaths.Add((Join-Path $script:HomeDir 'Library/Caches/Yarn'))
  [void]$yarnPaths.Add((Join-Path $script:HomeDir 'Library/Caches/Yarn/v6'))
  foreach ($yp in $yarnPaths) {
    if ($yp -and (Test-Path -LiteralPath $yp)) {
      $cacheTargets.Add(@{ Path = $yp; Eco = 'yarn-cache'; Osv = 'npm'; Label = 'yarn-cache' }) | Out-Null
    }
  }
  $cacheTargets.Add(@{ Path = (Join-Path $script:HomeDir '.nuget/packages'); Eco = 'nuget'; Osv = 'NuGet'; Label = 'nuget-cache' }) | Out-Null
  $pipPaths = New-Object System.Collections.Generic.List[string]
  if ($env:LOCALAPPDATA) { [void]$pipPaths.Add((Join-Path $env:LOCALAPPDATA 'pip\Cache')) }
  [void]$pipPaths.Add((Join-Path $script:HomeDir 'Library/Caches/pip'))
  [void]$pipPaths.Add((Join-Path $script:HomeDir '.cache/pip'))
  foreach ($pipPath in $pipPaths) {
    if ($pipPath -and (Test-Path -LiteralPath $pipPath)) {
      $cacheTargets.Add(@{ Path = $pipPath; Eco = 'PyPI'; Osv = 'PyPI'; Label = 'pip-cache' }) | Out-Null
    }
  }
  $poetryPaths = New-Object System.Collections.Generic.List[string]
  if ($env:LOCALAPPDATA) { [void]$poetryPaths.Add((Join-Path $env:LOCALAPPDATA 'pypoetry\Cache')) }
  [void]$poetryPaths.Add((Join-Path $script:HomeDir 'Library/Caches/pypoetry'))
  [void]$poetryPaths.Add((Join-Path $script:HomeDir '.cache/pypoetry'))
  foreach ($poetryPath in $poetryPaths) {
    if ($poetryPath -and (Test-Path -LiteralPath $poetryPath)) {
      $cacheTargets.Add(@{ Path = $poetryPath; Eco = 'PyPI'; Osv = 'PyPI'; Label = 'poetry-cache' }) | Out-Null
    }
  }

  $seen = New-Object System.Collections.Generic.HashSet[string]
  foreach ($c in $cacheTargets) {
    if (-not (Test-Path -LiteralPath $c.Path)) {
      Write-QuietLog "cache miss (not present): $($c.Label) ($($c.Path))"
      continue
    }
    Show-LiveProgress 80 "Phase 4/4: Checking $($c.Label)" $c.Path

    if ($c.Eco -eq 'npm-cacache') {
      # 1) Modern npm _cacache index (tarball URLs) — this is where installs land
      $cachedPkgs = @(Get-PackagesFromNpmCacache -cacheRoot $c.Path)
      Write-QuietLog "npm-cache cacache packages discovered: $($cachedPkgs.Count) at $($c.Path)"
      foreach ($pkg in $cachedPkgs) {
        $key = "$($c.Label)|$($pkg.Name)@$($pkg.Version)"
        if (-not $seen.Add($key)) { continue }
        $stats.CachePackagesChecked++
        if (($stats.CachePackagesChecked % 25) -eq 0) {
          Show-LiveProgress 85 "Phase 4/4: Checking npm-cache" "OSV $($pkg.Name)@$($pkg.Version)  (checked $($stats.CachePackagesChecked))"
        }
        # Path = cache root so report groups under the npm-cache folder
        Add-OsvFindings 'npm' 'npm' $pkg.Name $pkg.Version $c.Path "cache:$($c.Label)"
      }

      # 2) Legacy fallback: extracted node_modules trees inside cache (rare)
      Get-ChildItem -LiteralPath $c.Path -Filter 'package.json' -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '[\\/]node_modules[\\/]' } |
        ForEach-Object {
          try {
            $j = Get-Content $_.FullName -Raw | ConvertFrom-Json
            if (-not $j.name -or -not $j.version) { return }
            $key = "$($c.Label)|$($j.name)@$($j.version)"
            if (-not $seen.Add($key)) { return }
            $stats.CachePackagesChecked++
            Add-OsvFindings 'npm' 'npm' $j.name $j.version $c.Path "cache:$($c.Label)"
          } catch {}
        }
    }
    elseif ($c.Eco -eq 'yarn-cache') {
      $cachedPkgs = @(Get-PackagesFromYarnCache -cacheRoot $c.Path)
      Write-QuietLog "yarn-cache packages discovered: $($cachedPkgs.Count) at $($c.Path)"
      foreach ($pkg in $cachedPkgs) {
        $key = "$($c.Label)|$($pkg.Name)@$($pkg.Version)"
        if (-not $seen.Add($key)) { continue }
        $stats.CachePackagesChecked++
        if (($stats.CachePackagesChecked % 25) -eq 0) {
          Show-LiveProgress 86 "Phase 4/4: Checking yarn-cache" "OSV $($pkg.Name)@$($pkg.Version)"
        }
        Add-OsvFindings 'npm' 'npm' $pkg.Name $pkg.Version $c.Path "cache:$($c.Label)"
      }
    }
    elseif ($c.Eco -eq 'nuget') {
      # structure: packages/<id>/<version>/
      Get-ChildItem -LiteralPath $c.Path -Directory -ErrorAction SilentlyContinue |
        ForEach-Object {
          $pkgId = $_.Name
          Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
              $ver = $_.Name
              $key = "$($c.Label)|$pkgId@$ver"
              if (-not $seen.Add($key)) { return }
              $stats.CachePackagesChecked++
              if (($stats.CachePackagesChecked % 20) -eq 0) {
                Show-LiveProgress 88 "Phase 4/4: Checking nuget-cache" "$pkgId@$ver"
              }
              Add-OsvFindings 'nuget' 'NuGet' $pkgId $ver $c.Path 'cache:nuget'
            }
        }
    }
    else {
      Write-QuietLog "$($c.Label): present; deep wheel parsing skipped. Path=$($c.Path)"
    }
  }
} else {
  Write-QuietLog 'Skipping caches (-SkipCache)'
}

# =============================================================================
# REPORT + NOTIFY  (dangerous findings only, grouped by project)
# =============================================================================
Show-LiveProgress 95 'Finishing' 'Writing report and notifying you...'
Write-Progress -Activity 'Vulnerable library scan' -Completed

$elapsed = (Get-Date) - $start

function Get-ProjectFolder([string]$path) {
  $folder = Get-ProjectFolderFromPath $path
  if ($folder -eq '(unknown project)') { return '(unknown)' }
  return $folder
}

function Get-SeverityRank([string]$sev) {
  switch ($sev) {
    'critical' { 0 }
    'high' { 1 }
    'medium' { 2 }
    'moderate' { 2 }
    'low' { 3 }
    default { 4 }
  }
}

# Report findings (all severities except ignored unknowns; -HighOnly still filters at Add-Finding)
$dangerous = @($findings | Where-Object {
  $_.Severity -in @('critical', 'high', 'medium', 'moderate', 'low')
} | ForEach-Object {
  [pscustomobject]@{
    Severity  = $_.Severity
    Package   = $_.Package
    Version   = $_.Version
    Ecosystem = $_.Ecosystem
    Source    = $_.Source
    Title     = $_.Title
    Advisory  = $_.Advisory
    Fix       = $_.Fix
    HasFix    = [bool]$_.HasFix
    IsCache   = if ($null -ne $_.IsCache) { [bool]$_.IsCache } else { (Test-IsCacheLocation $_.Path $_.Source) }
    Folder    = (Get-ProjectFolder $_.Path)
  }
})

$critical = @($dangerous | Where-Object Severity -eq 'critical').Count
$high = @($dangerous | Where-Object Severity -eq 'high').Count
$medium = @($dangerous | Where-Object { $_.Severity -in @('medium','moderate') }).Count
$low = @($dangerous | Where-Object Severity -eq 'low').Count
$total = $dangerous.Count

$projectFindings = @($dangerous | Where-Object { -not $_.IsCache })
$cacheFindings = @($dangerous | Where-Object { $_.IsCache })
$byProject = $projectFindings | Group-Object Folder | Sort-Object Name
$byCache = $cacheFindings | Group-Object Folder | Sort-Object Name

# ---- HTML report (projects and caches separated) ----
$htmlBody = New-Object System.Collections.Generic.List[string]
$projectOptions = New-Object System.Collections.Generic.List[string]
if ($total -eq 0) {
  $htmlBody.Add('<p class="ok">No dangerous libraries found.</p>') | Out-Null
} else {
  $htmlBody.Add("<p class='summary'>Found <strong>$total</strong> dangerous libraries in <strong>$($byProject.Count)</strong> projects and <strong>$($byCache.Count)</strong> cache location(s).</p>") | Out-Null
  $htmlBody.Add("<p class='badges'><span class='badge critical'>critical: $critical</span> <span class='badge high'>high: $high</span> <span class='badge medium'>medium: $medium</span> <span class='badge low'>low: $low</span></p>") | Out-Null

  $allLabel = "All locations ($($byProject.Count + $byCache.Count))"
  $projectOptions.Add("<button type='button' class='dd-option selected' role='option' data-value='all'>" + (HtmlEncode $allLabel) + "</button>") | Out-Null
  if ($byProject.Count -gt 0) {
    $projectOptions.Add("<button type='button' class='dd-option' role='option' data-value='kind:project'>All projects ($($byProject.Count))</button>") | Out-Null
  }
  if ($byCache.Count -gt 0) {
    $projectOptions.Add("<button type='button' class='dd-option' role='option' data-value='kind:cache'>All caches ($($byCache.Count))</button>") | Out-Null
  }

  function Add-ReportCards {
    param($Groups, [string]$Kind, [string]$LabelPrefix)
    $num = 0
    foreach ($group in $Groups) {
      $num++
      $shortName = [IO.Path]::GetFileName(($group.Name).TrimEnd('\','/'))
      if (-not $shortName) { $shortName = "$LabelPrefix $num" }
      $projectId = "$Kind$num"
      $searchText = ("$shortName $($group.Name) $Kind").ToLowerInvariant()
      $optLabel = "[$LabelPrefix] $shortName ($($group.Count)) - $($group.Name)"
      if ($optLabel.Length -gt 120) { $optLabel = $optLabel.Substring(0, 117) + '...' }
      $script:projectOptions.Add("<button type='button' class='dd-option' role='option' data-value='" + (HtmlEncode $projectId) + "'>" + (HtmlEncode $optLabel) + "</button>") | Out-Null

      $script:htmlBody.Add("<section class='project' data-kind='" + (HtmlEncode $Kind) + "' data-project='" + (HtmlEncode $projectId) + "' data-search='" + (HtmlEncode $searchText) + "'>") | Out-Null
      $script:htmlBody.Add("<div class='project-sticky'>") | Out-Null
      $script:htmlBody.Add("<div class='project-label'>$LabelPrefix $num</div>") | Out-Null
      $script:htmlBody.Add("<h2>" + (HtmlEncode $shortName) + "</h2>") | Out-Null
      $script:htmlBody.Add("<div class='folder'>" + (HtmlEncode $group.Name) + "</div>") | Out-Null
      $script:htmlBody.Add("</div>") | Out-Null
      $script:htmlBody.Add("<p class='count'>$($group.Count) issue(s)</p>") | Out-Null
      $script:htmlBody.Add('<ul>') | Out-Null
      foreach ($f in @($group.Group | Sort-Object @{ Expression = { Get-SeverityRank $_.Severity } }, Package)) {
        $ver = if ($f.Version) { "@$($f.Version)" } else { '' }
        $sev = $f.Severity.ToLowerInvariant()
        if ($sev -eq 'moderate') { $sev = 'medium' }
        $fixClass = if ($f.HasFix) { 'fix-yes' } else { 'fix-no' }
        $fixLabel = if ($f.HasFix) { 'FIX AVAILABLE' } else { 'NO KNOWN FIX' }
        $advHtml = Format-AdvisoryHtml -Advisory $f.Advisory -WrapperClass 'detail'
        $titleHtml = if ($f.Title) { "<div class='detail'>Issue: " + (HtmlEncode $f.Title) + "</div>" } else { '' }
        $issueSearch = ("$($f.Package) $ver $($f.Title) $($f.Advisory) $($f.Fix) $($f.Severity)").ToLowerInvariant()
        $script:htmlBody.Add(@"
<li data-sev='$(HtmlEncode $sev)' data-search='$(HtmlEncode $issueSearch)'>
  <div class='issue-head'>
    <span class='badge $sev'>$(HtmlEncode $f.Severity.ToUpper())</span>
    <code>$(HtmlEncode ($f.Package + $ver))</code>
    <span class='fix-badge $fixClass'>$fixLabel</span>
  </div>
  $titleHtml
  <div class='detail fix'>How to solve: $(HtmlEncode $f.Fix)</div>
  $advHtml
</li>
"@) | Out-Null
      }
      $script:htmlBody.Add('</ul>') | Out-Null
      $script:htmlBody.Add('</section>') | Out-Null
    }
  }

  $script:htmlBody = $htmlBody
  $script:projectOptions = $projectOptions

  $htmlBody.Add('<h2 class="section-title">Projects</h2>') | Out-Null
  if ($byProject.Count -eq 0) {
    $htmlBody.Add('<p class="none">No project findings.</p>') | Out-Null
  } else {
    Add-ReportCards -Groups $byProject -Kind 'project' -LabelPrefix 'Project'
  }

  $htmlBody.Add('<h2 class="section-title">Package caches</h2>') | Out-Null
  if ($byCache.Count -eq 0) {
    $htmlBody.Add('<p class="none">No cache findings.</p>') | Out-Null
  } else {
    Add-ReportCards -Groups $byCache -Kind 'cache' -LabelPrefix 'Cache'
  }
}

$projectFilterHtml = ''
if ($total -gt 0) {
  $projectFilterHtml = @"
  <div class="filters">
    <div class="project-filter">
      <label id="project-label">Location</label>
      <div class="dd" id="project-dd">
        <button type="button" class="dd-toggle" id="project-select" aria-haspopup="listbox" aria-expanded="false" aria-labelledby="project-label">
          <span class="dd-label">$(HtmlEncode $allLabel)</span>
          <span class="dd-arrow" aria-hidden="true"></span>
        </button>
        <div class="dd-menu" role="listbox">
          $($projectOptions -join "`r`n")
        </div>
      </div>
      <input id="project-search" type="search" placeholder="Search project/cache path..." />
      <input id="vuln-search" type="search" placeholder="Search package / CVE / GHSA / commit (e.g. CVE-2025-55182 or d033885)..." />
    </div>
    <div class="kind-filter" id="kind-filters">
      <button type="button" class="kind active" data-kind="all">ALL</button>
      <button type="button" class="kind" data-kind="project">PROJECTS</button>
      <button type="button" class="kind" data-kind="cache">CACHES</button>
    </div>
    <div class="sev-filter" id="sev-filters">
      <button type="button" class="all active" data-sev="all">ALL SEVERITIES</button>
      <button type="button" class="critical" data-sev="critical">CRITICAL</button>
      <button type="button" class="high" data-sev="high">HIGH</button>
      <button type="button" class="medium" data-sev="medium">MEDIUM</button>
      <button type="button" class="low" data-sev="low">LOW</button>
    </div>
  </div>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Dangerous libraries report</title>
<style>
$(Get-ReportStyles)
/* Final report dropdown uses animated open state */
.dd-menu {
  display: block;
  opacity: 0; visibility: hidden; transform: translateY(-8px);
  transition: opacity .18s ease, transform .18s ease, visibility .18s;
}
.dd.open .dd-menu { opacity: 1; visibility: visible; transform: translateY(0); }
</style>
</head>
<body>
  <h1>Dangerous libraries</h1>
  <div class="meta">Scanned $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &middot; $([int]$elapsed.TotalSeconds)s</div>
  $projectFilterHtml
  <div id="projects">
  $($htmlBody -join "`r`n")
  </div>
  <p class="empty" id="empty-projects">No locations match this filter.</p>
<script>
(function () {
  var projects = Array.prototype.slice.call(document.querySelectorAll('#projects .project'));
  var projectDd = document.getElementById('project-dd');
  var projectToggle = document.getElementById('project-select');
  var projectLabel = projectToggle ? projectToggle.querySelector('.dd-label') : null;
  var projectMenu = projectDd ? projectDd.querySelector('.dd-menu') : null;
  var projectOptions = projectMenu ? Array.prototype.slice.call(projectMenu.querySelectorAll('.dd-option')) : [];
  var projectSearch = document.getElementById('project-search');
  var vulnSearch = document.getElementById('vuln-search');
  var sevButtons = Array.prototype.slice.call(document.querySelectorAll('#sev-filters button'));
  var kindButtons = Array.prototype.slice.call(document.querySelectorAll('#kind-filters button'));
  var empty = document.getElementById('empty-projects');
  var currentProject = 'all';
  var currentProjectSearch = '';
  var currentVulnSearch = '';
  var currentSev = 'all';
  var currentKind = 'all';

  function setProjectValue(value, closeMenu) {
    currentProject = value || 'all';
    if (currentProject === 'kind:project') currentKind = 'project';
    else if (currentProject === 'kind:cache') currentKind = 'cache';
    projectOptions.forEach(function (opt) {
      var selected = (opt.getAttribute('data-value') === currentProject);
      opt.classList.toggle('selected', selected);
      if (selected && projectLabel) projectLabel.textContent = opt.textContent;
    });
    kindButtons.forEach(function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-kind') === currentKind);
    });
    if (closeMenu && projectDd) {
      projectDd.classList.remove('open');
      if (projectToggle) projectToggle.setAttribute('aria-expanded', 'false');
    }
  }

  function apply() {
    var projectQ = (currentProjectSearch || '').toLowerCase().trim();
    var vulnQ = (currentVulnSearch || '').toLowerCase().trim();
    var visibleProjects = 0;

    projects.forEach(function (project) {
      var pid = project.getAttribute('data-project') || '';
      var pkind = project.getAttribute('data-kind') || 'project';
      var projectHay = project.getAttribute('data-search') || '';
      var kindMatch = (currentKind === 'all') || (pkind === currentKind);
      var projectMatch = (currentProject === 'all' || currentProject === 'kind:project' || currentProject === 'kind:cache' || currentProject === pid);
      if (currentProject === 'kind:project') kindMatch = (pkind === 'project');
      if (currentProject === 'kind:cache') kindMatch = (pkind === 'cache');
      if (projectQ && projectHay.indexOf(projectQ) === -1) projectMatch = false;

      var items = Array.prototype.slice.call(project.querySelectorAll('li'));
      var shown = 0;
      items.forEach(function (li) {
        var sev = li.getAttribute('data-sev') || '';
        var issueHay = ((li.getAttribute('data-search') || '') + ' ' + (li.textContent || '')).toLowerCase();
        var sevMatch = (currentSev === 'all') || (sev === currentSev);
        var vulnMatch = !vulnQ || issueHay.indexOf(vulnQ) !== -1;
        var show = projectMatch && kindMatch && sevMatch && vulnMatch;
        li.classList.toggle('hidden', !show);
        if (show) shown++;
      });
      project.classList.toggle('hidden', shown === 0);
      if (shown > 0) visibleProjects++;
    });
    if (empty) {
      empty.textContent = vulnQ
        ? ('No findings match "' + currentVulnSearch + '".')
        : 'No locations match this filter.';
      empty.classList.toggle('show', visibleProjects === 0 && projects.length > 0);
    }
    sevButtons.forEach(function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-sev') === currentSev);
    });
    kindButtons.forEach(function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-kind') === currentKind);
    });
    try {
      sessionStorage.setItem('vulnReportProject', currentProject);
      sessionStorage.setItem('vulnReportProjectSearch', currentProjectSearch);
      sessionStorage.setItem('vulnReportVulnSearch', currentVulnSearch);
      sessionStorage.setItem('vulnReportSev', currentSev);
      sessionStorage.setItem('vulnReportKind', currentKind);
    } catch (e) {}
  }

  if (projectToggle && projectDd && projectMenu) {
    projectToggle.addEventListener('click', function (e) {
      e.stopPropagation();
      var open = !projectDd.classList.contains('open');
      projectDd.classList.toggle('open', open);
      projectToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    projectOptions.forEach(function (opt) {
      opt.addEventListener('click', function (e) {
        e.stopPropagation();
        setProjectValue(opt.getAttribute('data-value'), true);
        if (projectSearch) {
          projectSearch.value = '';
          currentProjectSearch = '';
        }
        apply();
      });
    });
    document.addEventListener('click', function () {
      projectDd.classList.remove('open');
      projectToggle.setAttribute('aria-expanded', 'false');
    });
  }
  if (projectSearch) {
    projectSearch.addEventListener('input', function () {
      currentProjectSearch = projectSearch.value || '';
      if (currentProjectSearch) setProjectValue('all', true);
      apply();
    });
  }
  if (vulnSearch) {
    vulnSearch.addEventListener('input', function () {
      currentVulnSearch = vulnSearch.value || '';
      apply();
    });
  }
  sevButtons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      currentSev = btn.getAttribute('data-sev') || 'all';
      apply();
    });
  });
  kindButtons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      currentKind = btn.getAttribute('data-kind') || 'all';
      if (currentKind === 'project') setProjectValue('kind:project', true);
      else if (currentKind === 'cache') setProjectValue('kind:cache', true);
      else setProjectValue('all', true);
      apply();
    });
  });

  try {
    currentProject = sessionStorage.getItem('vulnReportProject') || 'all';
    currentProjectSearch = sessionStorage.getItem('vulnReportProjectSearch') || '';
    currentVulnSearch = sessionStorage.getItem('vulnReportVulnSearch') || '';
    currentSev = sessionStorage.getItem('vulnReportSev') || 'all';
    currentKind = sessionStorage.getItem('vulnReportKind') || 'all';
  } catch (e) {}
  var hasOpt = projectOptions.some(function (o) { return o.getAttribute('data-value') === currentProject; });
  setProjectValue(hasOpt ? currentProject : 'all', true);
  if (projectSearch) projectSearch.value = currentProjectSearch;
  if (vulnSearch) vulnSearch.value = currentVulnSearch;
  apply();
})();
</script>
</body>
</html>
"@
$reportOk = $false
try {
  Save-FindingsJson
  Save-HtmlFile -Path $outHtml -Content $html
  $reportOk = $true
} catch {
  $reportOk = $false
}

# Short terminal finish only (details are in the HTML report)
try {
  if ($script:progressTop -ge 0) {
    $below = [Math]::Min([Console]::BufferHeight - 1, $script:progressTop + 1)
    [Console]::SetCursorPosition(0, $below)
  }
} catch {}

$openedHtml = $false
if ($reportOk -and -not $script:GuiMode -and -not $NoOpen) {
  try {
    $openedHtml = [bool](Open-ReportFile $outHtml)
  } catch {
    $openedHtml = $false
  }
}

if ($script:GuiMode) {
  $script:percent = 100
  $script:phase = if ($reportOk) { 'DONE' } else { 'FAILED' }
  $script:detail = if ($reportOk) { 'Scan finished' } else { 'HTML report write failed' }
  Write-GuiProgressFile
  Write-Output ("DONE|{0}|{1}" -f $(if ($reportOk) { 'SUCCESS' } else { 'FAILED' }), $outHtml)
} else {
  Write-Host ''
  if ($reportOk) {
    Write-Host 'Finished: SUCCESS' -ForegroundColor Green
    if ($openedHtml) {
      Write-Host "Opening HTML report: $outHtml" -ForegroundColor Green
    } else {
      Write-Host "HTML report saved (could not auto-open): $outHtml" -ForegroundColor Yellow
    }
  } else {
    Write-Host 'Finished: FAILED' -ForegroundColor Red
    Write-Host 'Could not write the HTML report.' -ForegroundColor Red
  }
}

$toastTitle = if (-not $reportOk) {
  'Library scan: failed'
} elseif ($total -eq 0) {
  'Library scan: clean'
} else {
  "Dangerous libraries: $total"
}
$toastText  = if (-not $reportOk) {
  'Scan finished but HTML report could not be written.'
} elseif ($total -eq 0) {
  'No dangerous libraries found. Opening HTML report.'
} else {
  "critical=$critical high=$high. Opening HTML report."
}
if (-not $script:GuiMode) {
  Show-UserNotification -title $toastTitle -text $toastText
}
Add-LogEntry -Message $(if ($reportOk) { 'DONE' } else { 'FAILED to write HTML report' }) -Kind $(if ($reportOk) { 'done' } else { 'warn' })
$script:percent = 100
$script:phase = if ($reportOk) { 'DONE' } else { 'FAILED' }
$script:detail = if ($reportOk) { 'Scan finished' } else { 'HTML report write failed' }
Save-ProgressHtml
