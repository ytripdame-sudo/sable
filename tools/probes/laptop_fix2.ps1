$ErrorActionPreference = 'Continue'
'--- paths ---'
foreach ($p in @('C:\sable\sable', 'C:\sable\sable\agent', 'C:\sable\sable\agent\__init__.py',
                 'C:\sable\sable\core', 'C:\sable\_harness\sable_fixture.py',
                 'C:\sable\sable\agent\sources\browsers\chromium.py')) {
  if (Test-Path $p) { 'OK   ' + $p } else { 'MISS ' + $p }
}
'--- top of C:\sable\sable ---'
Get-ChildItem C:\sable\sable -Force | ForEach-Object { '  ' + $_.Name }
'--- what the fixture computes ---'
& C:\sable\py312\python.exe -c "from pathlib import Path; p=Path(r'C:\sable\_harness\sable_fixture.py'); print('parents', p.parents[0], '|', p.parents[1]); print('root/sable', p.parents[1] / 'sable')"
'--- import probe ---'
& C:\sable\py312\python.exe -c "import sys; sys.path.insert(0, r'C:\sable\sable'); import agent; print('agent at', agent.__file__)" 2>&1 | ForEach-Object { '  ' + $_ }
