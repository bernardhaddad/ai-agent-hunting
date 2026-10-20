# Exports 4688, 5156, Defender 5007 and Sysmon 1 (if there) as jsonl with Sigma field names,
# for tests\replay.py. Needs admin for the Security log.
#   .\export_lab_events.ps1 -Hours 48 -OutFile C:\Triage\lab_events.jsonl
param(
    [int]$Hours = 24,
    [string]$OutFile = (Join-Path (Get-Location) 'lab_events.jsonl')
)

# EventData name -> Sigma field name, per event ID. Unlisted names are kept as-is.
$FieldMap = @{
    4688 = @{ NewProcessName = 'Image'; ParentProcessName = 'ParentImage' }
    5007 = @{ 'New Value' = 'NewValue'; 'Old Value' = 'OldValue' }
}

function ConvertFrom-EventXml([string]$Xml) {
    $doc = [xml]$Xml
    $sys = $doc.Event.System
    $id = [int]$sys.EventID.'#text'
    if (-not $id) { $id = [int]$sys.EventID }
    $out = [ordered]@{
        TimeCreated = ([datetime]$sys.TimeCreated.SystemTime).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'")
        Channel     = [string]$sys.Channel
        EventID     = $id
        Computer    = [string]$sys.Computer
    }
    $map = $FieldMap[$id]
    foreach ($d in $doc.Event.EventData.Data) {
        $name = [string]$d.Name
        if (-not $name) { continue }
        if ($map -and $map.ContainsKey($name)) { $name = $map[$name] }
        $out[$name] = [string]$d.'#text'
    }
    [pscustomobject]$out
}

$since = (Get-Date).AddHours(-$Hours)
$queries = @(
    @{ LogName = 'Security'; Id = 4688, 5156; StartTime = $since },
    @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5007; StartTime = $since },
    @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $since }
)

$lines = foreach ($q in $queries) {
    try {
        Get-WinEvent -FilterHashtable $q -ErrorAction Stop |
            ForEach-Object { ConvertFrom-EventXml $_.ToXml() | ConvertTo-Json -Compress -Depth 3 }
    } catch {
        Write-Warning "$($q.LogName): $($_.Exception.Message)"
    }
}
$lines | Set-Content -LiteralPath $OutFile -Encoding utf8
Write-Host "Wrote $(@($lines).Count) events to $OutFile"
