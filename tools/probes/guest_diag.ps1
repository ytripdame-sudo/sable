$ErrorActionPreference = 'Continue'
'--- staging ---'
foreach ($p in 'C:\guest\run.json', 'C:\guest\watch.ps1', 'C:\guest\SableRuntime.exe', 'C:\guest\py\python.exe') {
    '{0,-32} {1}' -f $p, (Test-Path $p)
}
if (Test-Path 'C:\guest\watch.ps1') { 'watch.ps1 bytes ' + (Get-Item 'C:\guest\watch.ps1').Length }

'--- task ---'
schtasks /query /tn SABLE-WATCH /v /fo LIST 2>&1 | Select-String -Pattern 'TaskName|Status|Last Run Time|Last Result|Run As User|Logon Mode|Task To Run' | ForEach-Object { '  ' + $_.Line.Trim() }

'--- sessions ---'
quser 2>&1 | ForEach-Object { '  ' + $_ }
'explorer sessions : ' + ((Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SessionId) -join ',')
'current session   : ' + (Get-Process -Id $PID).SessionId

'--- task scheduler events ---'
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; StartTime=(Get-Date).AddMinutes(-30)} -ErrorAction SilentlyContinue |
    Select-Object -First 12 |
    ForEach-Object { '  {0:HH:mm:ss} id={1} {2}' -f $_.TimeCreated, $_.Id, ($_.Message -split "`n")[0] }
