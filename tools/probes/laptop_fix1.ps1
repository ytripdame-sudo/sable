$ErrorActionPreference = 'Continue'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:QT_QPA_PLATFORM = 'offscreen'
Set-Location C:\sable\_harness

& C:\sable\py312\python.exe C:\sable\_harness\sable_fixture.py *> C:\sable\_harness\fixture.log
'fixture exit ' + $LASTEXITCODE
Get-Content C:\sable\_harness\fixture.log -Tail 25 | ForEach-Object { '  | ' + $_ }
