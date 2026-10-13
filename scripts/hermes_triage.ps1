<#
.SYNOPSIS
  Collects Hermes Agent artifacts from a Windows host for triage.
.DESCRIPTION
  Copies the files an analyst needs (config, scheduled jobs, launchers, logs, the session
  database with its WAL/SHM files) into an output folder, and writes a summary of the
  approval settings, Defender exclusions and gateway state. Secrets in .env are NOT copied;
  only the variable names are recorded.
.PARAMETER HermesHome
  Hermes home folder. Defaults to $env:HERMES_HOME, then %LOCALAPPDATA%\hermes.
.PARAMETER OutDir
  Where to write the collection.
.EXAMPLE
  .\hermes_triage.ps1 -OutDir C:\Triage\hermes
#>
param(
    [string]$HermesHome = $(if ($env:HERMES_HOME) { $env:HERMES_HOME } else { Join-Path $env:LOCALAPPDATA 'hermes' }),
    [string]$OutDir = (Join-Path $env:PUBLIC "hermes_triage_$(Get-Date -Format yyyyMMdd_HHmmss)")
)

$ErrorActionPreference = 'Continue'
if (-not (Test-Path $HermesHome)) { Write-Warning "Hermes home not found: $HermesHome"; return }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$summary = Join-Path $OutDir 'summary.txt'

function Add-Summary([string]$Title, $Body) {
    "`n== $Title ==" | Out-File $summary -Append -Encoding utf8
    ($Body | Out-String).TrimEnd() | Out-File $summary -Append -Encoding utf8
}

# Files to copy as-is (no secrets)
$files = @(
    'config.yaml', 'gateway_state.json', 'gateway-starts.log', 'channel_directory.json',
    'SOUL.md', 'state.db', 'state.db-wal', 'state.db-shm', 'cron\jobs.json',
    'gateway-service\Hermes_Gateway.vbs'
)
foreach ($f in $files) {
    $src = Join-Path $HermesHome $f
    if (Test-Path $src) {
        $dst = Join-Path $OutDir $f
        New-Item -ItemType Directory -Path (Split-Path $dst) -Force | Out-Null
        Copy-Item $src $dst -Force
    }
}
foreach ($d in 'logs', 'sessions', 'memories', 'skills') {
    $src = Join-Path $HermesHome $d
    if (Test-Path $src) { Copy-Item $src (Join-Path $OutDir $d) -Recurse -Force }
}

# Startup-folder launcher (fallback persistence)
$startupVbs = if ($env:APPDATA) { Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\Hermes_Gateway.vbs' } else { $null }
$startupFound = [bool]($startupVbs -and (Test-Path $startupVbs))
if ($startupFound) { Copy-Item $startupVbs (Join-Path $OutDir 'Startup_Hermes_Gateway.vbs') -Force }

# Summary
Add-Summary 'Hermes home' $HermesHome
$cfg = Join-Path $HermesHome 'config.yaml'
if (Test-Path $cfg) {
    Add-Summary 'config.yaml approvals block' (Select-String -Path $cfg -Pattern '^\s*approvals:' -Context 0, 6 | ForEach-Object { $_.Line; $_.Context.PostContext })
    Add-Summary 'protected_instruction_files' (Select-String -Path $cfg -Pattern 'protected_instruction_files' | ForEach-Object Line)
}
$envFile = Join-Path $HermesHome '.env'
if (Test-Path $envFile) {
    Add-Summary '.env variable names (values not collected)' (Get-Content $envFile | Where-Object { $_ -match '^\s*[A-Z0-9_]+\s*=' } | ForEach-Object { ($_ -split '=')[0].Trim() })
}
$task = try { schtasks /query /tn Hermes_Gateway /v /fo list 2>&1 } catch { 'schtasks unavailable' }
Add-Summary 'Scheduled task Hermes_Gateway' $task
Add-Summary 'Startup launcher present' $startupFound
try { Add-Summary 'Defender exclusion paths' ((Get-MpPreference).ExclusionPath) } catch { Add-Summary 'Defender exclusion paths' 'Get-MpPreference unavailable' }
Add-Summary 'File hashes' (Get-ChildItem $OutDir -Recurse -File |
    Where-Object Name -ne 'summary.txt' |
    ForEach-Object { Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 } |
    Format-Table Hash, Path -AutoSize | Out-String -Width 400)

Write-Host "Collected to $OutDir"
Write-Host "Open state.db with DB Browser for SQLite. Start with: SELECT * FROM sessions;  then messages for the session you care about."
