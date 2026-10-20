# Lab VM only, run elevated with the Hermes gateway connected to your bot.
# Turns on 5156 + 4688 command line auditing, waits for you to send hostname, whoami and
# ipconfig /all over Telegram, exports the events, runs triage, replays them through the
# rules (and again with the agent renamed), runs verify_execution and the tests, then
# zips the results without state.db or .env. -ReuseEvents skips the waiting part.
# Revert the snapshot afterwards, the audit policy changes stay.
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

function Step([string]$Text) { Write-Host "`n-- $Text" }

# PS 5.1 treats python's stderr as an error under Stop
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

Step 'audit policy'
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable | Out-Null
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
$cmdline = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue
if (-not $cmdline -or $cmdline.ProcessCreationIncludeCmdLine_Enabled -ne 1) {
    New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1 -Type DWord
}
auditpol /get /subcategory:"Filtering Platform Connection","Process Creation"

Step 'gateway'
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

Step 'pysigma'
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { throw 'python not found on PATH.' }
# -I or the sigma\ folder in this repo shadows the pysigma package
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
    Step "send to the bot now: hostname, whoami, ipconfig /all (waiting up to $WaitMinutes min)"
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

    Step 'export, triage, replay'
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

Step 'summary'
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
