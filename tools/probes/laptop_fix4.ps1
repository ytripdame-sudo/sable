$ErrorActionPreference = 'Continue'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:SABLE_HEAD = '7d2373f'
Set-Location C:\sable\_harness

& C:\sable\py312\python.exe C:\sable\_harness\gui_audit.py *> C:\sable\_harness\matrix.log
'matrix exit ' + $LASTEXITCODE
'--- tail ---'
Get-Content C:\sable\_harness\matrix.log -Tail 30 | ForEach-Object { '  | ' + $_ }
