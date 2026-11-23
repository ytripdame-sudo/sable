$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# Session 0 driver: stage the probe, register it as an interactive task so it lands in
# session 1 beside explorer, then read what it wrote.

$base = 'C:\guest'
$out = "$base\probe.json"
Remove-Item $out -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force $base | Out-Null
curl.exe -s -S --max-time 60 -o "$base\probe.ps1" 'http://192.168.1.151:8099/probe.ps1'
'probe.ps1  ' + (Get-Item "$base\probe.ps1" -ErrorAction SilentlyContinue).Length

Unregister-ScheduledTask -TaskName 'SABLE-PROBE' -Confirm:$false -ErrorAction SilentlyContinue
$principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\bench" -LogonType Interactive -RunLevel Limited
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -ExecutionPolicy Bypass -File ' + $base + '\probe.ps1')
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'SABLE-PROBE' -Action $action -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'SABLE-PROBE'

$started = Get-Date
while (((Get-Date) - $started).TotalSeconds -lt 220) {
    if (Test-Path $out) { break }
    Start-Sleep -Seconds 2
}
'waited     ' + [math]::Round(((Get-Date) - $started).TotalSeconds, 1) + ' s'
$info = Get-ScheduledTaskInfo -TaskName 'SABLE-PROBE' -ErrorAction SilentlyContinue
'lastresult ' + $info.LastTaskResult
Unregister-ScheduledTask -TaskName 'SABLE-PROBE' -Confirm:$false -ErrorAction SilentlyContinue

if (Test-Path $out) {
    $fs = [IO.File]::Open($out, 'Open', 'Read', 'ReadWrite')
    $sr = New-Object IO.StreamReader($fs)
    $body = $sr.ReadToEnd()
    $sr.Close(); $fs.Close()
    $body
} else {
    'MISSING    ' + $out
}
