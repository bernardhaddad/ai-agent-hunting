<#
.SYNOPSIS
  One-shot validation of the Sigma rules against real events on the Hermes lab VM.
.DESCRIPTION
  Run elevated on the lab VM while the Hermes gateway is connected to your Telegram bot.
    1. Enables Security 5156 auditing (Filtering Platform Connection) and checks 4688.
    2. Checks the Hermes gateway is running.
    3. Installs pySigma if needed.
    4. Waits for you to send hostname, whoami and ipconfig /all to the bot.
    5. Exports the events, collects Hermes triage, replays the events through every rule,
       replays a copy with the agent renamed, runs the execution check and the unit tests.
    6. Writes a PASS/FAIL summary and a shareable zip (no state.db, no .env values).
  Lab use only. The audit policy change stays until you revert the VM snapshot.
.PARAMETER OutDir
  Results folder. Default C:\Lab\results
.PARAMETER WaitMinutes
  How long to wait for the Telegram commands. Default 15.
.PARAMETER ReuseEvents
  Skip waiting, exporting and triage; re-run the analysis on the events already in OutDir.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\run_lab_validation.ps1
#>
param(
    [string]$OutDir = 'C:\Lab\results',
    [int]$WaitMinutes = 15,
    [switch]$ReuseEvents
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
$Correlations = @(
    'Chat-Controlled Agent - Telegram Connection And Shell Execution',
    'AI Agent Style Recon - Interpreter Shell And Discovery Together',
    'Burst Of Processes From A Bundled POSIX Shell Under AppData'
)
$HermesRules = @(
    'Command Executed By Hermes Agent Terminal Tool',
    'Hermes Agent Gateway Launched Via VBScript'
)

function Step([string]$Text) { Write-Host "`n=== $Text" -ForegroundColor Cyan }

# Run python without letting its stderr abort the script (Windows PowerShell 5.1 turns
# native stderr into terminating errors under ErrorActionPreference=Stop).
function Invoke-Py([string]$LogFile, [string[]]$PyArgs) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $py @PyArgs 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $LogFile
    } finally { $ErrorActionPreference = $old }
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this from an elevated PowerShell (Run as administrator).' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$started = Get-Date

Step '1/6 Audit policy'
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable | Out-Null
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
$cmdline = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue
if (-not $cmdline -or $cmdline.ProcessCreationIncludeCmdLine_Enabled -ne 1) {
    New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1 -Type DWord
}
auditpol /get /subcategory:"Filtering Platform Connection","Process Creation"

Step '2/6 Hermes gateway'
$gw = Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -match 'gateway run' -and $_.ExecutablePath -match '\\hermes\\' }
if (-not $gw) {
    $vbs = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\Hermes_Gateway.vbs'
    if (Test-Path $vbs) {
        Write-Host 'Gateway not running; starting it through its Startup launcher.'
        Start-Process wscript.exe -ArgumentList "`"$vbs`""
        Start-Sleep -Seconds 20
        $gw = Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
            Where-Object { $_.CommandLine -match 'gateway run' -and $_.ExecutablePath -match '\\hermes\\' }
    }
}
if (-not $gw) { throw 'Hermes gateway is not running. Sign out and back in, or start it, then rerun.' }
Write-Host "Gateway PID $($gw.ProcessId): $($gw.ExecutablePath)"

Step '3/6 Python and pySigma'
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { throw 'python not found on PATH.' }
# -I (isolated): without it, the repo's own sigma\ rules folder shadows the pySigma package.
# Native stderr must not abort the script here (Windows PowerShell 5.1), so relax errors.
$ErrorActionPreference = 'Continue'
& $py -I -c "import sigma.collection" *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Installing pySigma...'
    & $py -m pip install --quiet --disable-pip-version-check pysigma 2>&1 | ForEach-Object { "$_" }
    & $py -I -c "import sigma.collection" *> $null
}
$ok = $LASTEXITCODE -eq 0
$ErrorActionPreference = 'Stop'
if (-not $ok) { throw "pySigma did not install for $py" }
& $py -I -c "import sigma, importlib.metadata as m; print('pySigma', m.version('pysigma'), 'at', sigma.__path__[0])"

$events = Join-Path $OutDir 'lab_events.jsonl'
$seen = @{}
if ($ReuseEvents -and (Test-Path $events)) {
    Write-Host "Reusing $events"
    foreach ($n in 'hostname.exe', 'whoami.exe', 'ipconfig.exe') {
        if (Select-String -LiteralPath $events -SimpleMatch "\\$n" -Quiet) { $seen[$n] = $true }
    }
} else {
    Step "4/6 Send these to your Telegram bot now: hostname, whoami, ipconfig /all (waiting up to $WaitMinutes min)"
    $wanted = @('hostname.exe', 'whoami.exe', 'ipconfig.exe')
    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    while ((Get-Date) -lt $deadline -and $seen.Count -lt $wanted.Count) {
        Start-Sleep -Seconds 10
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $started } -ErrorAction SilentlyContinue |
            ForEach-Object {
                $x = [xml]$_.ToXml()
                $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
                $leaf = Split-Path $d.NewProcessName -Leaf
                if ($wanted -contains $leaf.ToLower() -and $d.ParentProcessName -match '\\AppData\\') { $seen[$leaf.ToLower()] = $d.NewProcessName }
            }
        Write-Host ("  seen: {0}" -f (($seen.Keys | Sort-Object) -join ', '))
    }
    if ($seen.Count -lt $wanted.Count) { Write-Warning 'Not all three commands were seen; continuing with what was captured.' }
    Start-Sleep -Seconds 30

    Step '5/6 Export, triage, replay, verify, tests'
    $hours = [math]::Ceiling(((Get-Date) - $started).TotalHours) + 1
    & (Join-Path $PSScriptRoot 'export_lab_events.ps1') -Hours $hours -OutFile $events
    & (Join-Path $PSScriptRoot 'hermes_triage.ps1') -OutDir (Join-Path $OutDir 'triage')
}

$renamed = Join-Path $OutDir 'lab_events_renamed.jsonl'
(Get-Content -LiteralPath $events -Raw) `
    -replace '\\\\hermes\\\\', '\\notes-sync\\' `
    -replace '\\\\hermes(["\s])', '\\notes-sync$1' `
    -replace 'hermes_cli', 'nsync' `
    -replace 'Hermes_Gateway', 'NotesSync' |
    Set-Content -LiteralPath $renamed -Encoding utf8

$replayPy = Join-Path $Root 'tests\replay.py'
Invoke-Py (Join-Path $OutDir 'replay.txt') @($replayPy, $events)
Write-Host '--- renamed agent ---'
Invoke-Py (Join-Path $OutDir 'replay_renamed.txt') @($replayPy, $renamed)
$db = Join-Path $OutDir 'triage\state.db'
if (Test-Path $db) {
    Invoke-Py (Join-Path $OutDir 'verify.txt') @((Join-Path $PSScriptRoot 'verify_execution.py'), $db, $events)
}
Invoke-Py (Join-Path $OutDir 'unit_tests.txt') @('-m', 'unittest', 'discover', '-s', (Join-Path $Root 'tests')) | Out-Null

Step '6/6 Summary'
$r = Get-Content (Join-Path $OutDir 'replay.txt') -Raw
$rr = Get-Content (Join-Path $OutDir 'replay_renamed.txt') -Raw
$t = Get-Content (Join-Path $OutDir 'unit_tests.txt') -Raw
$rows = foreach ($c in $Correlations) {
    [pscustomobject]@{ Check = "fires on real events: $c"; Result = if ($r -match [regex]::Escape($c)) { 'PASS' } else { 'FAIL' } }
    [pscustomobject]@{ Check = "fires with agent renamed: $c"; Result = if ($rr -match [regex]::Escape($c)) { 'PASS' } else { 'FAIL' } }
}
$rows += foreach ($h in $HermesRules) {
    [pscustomobject]@{ Check = "Hermes rule silent when renamed: $h"; Result = if ($rr -match [regex]::Escape($h)) { 'FAIL' } else { 'PASS' } }
}
$rows += [pscustomobject]@{ Check = 'discovery commands captured'; Result = "$($seen.Count)/3" }
$rows += [pscustomobject]@{ Check = 'unit tests'; Result = if ($t -match '(?m)^OK' -and $t -notmatch 'skipped') { 'PASS' } else { 'FAIL' } }
$rows | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Tee-Object (Join-Path $OutDir 'summary.txt')

$share = Join-Path $OutDir 'share'
New-Item -ItemType Directory -Path $share -Force | Out-Null
'summary.txt', 'replay.txt', 'replay_renamed.txt', 'verify.txt', 'unit_tests.txt' |
    ForEach-Object { $p = Join-Path $OutDir $_; if (Test-Path $p) { Copy-Item $p $share } }
$zip = Join-Path $OutDir 'results_to_share.zip'
Compress-Archive -Path (Join-Path $share '*') -DestinationPath $zip -Force
Write-Host "`nDone. Results: summary.txt, replay.txt, replay_renamed.txt, verify.txt"
Write-Host "verify.txt contains your controller's Telegram user ID: blur it before posting."
Write-Host "Shareable files: $zip   (full evidence incl. state.db stays in $OutDir\triage)"
