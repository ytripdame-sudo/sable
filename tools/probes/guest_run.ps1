$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$base = 'C:\guest'
$out = "$base\run.json"
if (Test-Path $out) { Remove-Item $out -Force }

Unregister-ScheduledTask -TaskName 'SABLE-WATCH' -Confirm:$false -ErrorAction SilentlyContinue

# LogonType Interactive is the point: session 0 has a window station nobody is looking
# at, so a message box there is invisible. Interactive binds the task to the console
# session the user is actually sitting in.
$principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\bench" -LogonType Interactive -RunLevel Limited
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -ExecutionPolicy Bypass -File ' + $base + '\watch.ps1')
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew

try {
    Register-ScheduledTask -TaskName 'SABLE-WATCH' -Action $action -Principal $principal `
        -Settings $settings -Force -ErrorAction Stop | Out-Null
    'registered True'
} catch {
    'registered False: ' + $_.Exception.Message
}

try {
    Start-ScheduledTask -TaskName 'SABLE-WATCH' -ErrorAction Stop
    'started    True'
} catch {
    'started    False: ' + $_.Exception.Message
}

$started = Get-Date
while (((Get-Date) - $started).TotalSeconds -lt 240) {
    if (Test-Path $out) { break }
    Start-Sleep -Seconds 2
}
$waited = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)

$info = Get-ScheduledTaskInfo -TaskName 'SABLE-WATCH' -ErrorAction SilentlyContinue
'waited     ' + $waited + ' s'
'lastresult ' + $info.LastTaskResult + '  lastrun ' + $info.LastRunTime

Unregister-ScheduledTask -TaskName 'SABLE-WATCH' -Confirm:$false -ErrorAction SilentlyContinue

if (Test-Path $out) {
    Get-Content $out -Raw
} else {
    'MISSING    ' + $out
}
