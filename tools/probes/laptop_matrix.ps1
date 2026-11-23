$ErrorActionPreference = 'Stop'

# --- layout: _harness and sable must be siblings, the way the audit expects ---
if ((Test-Path C:\sable\src) -and -not (Test-Path C:\sable\sable)) {
  Rename-Item C:\sable\src C:\sable\sable
}
New-Item -ItemType Directory -Force C:\sable\sable\tools\dist | Out-Null
New-Item -ItemType Directory -Force C:\sable\_harness | Out-Null

foreach ($name in @('gui_audit.py', 'pecheck.py', 'sable_fixture.py')) {
  $from = Join-Path 'C:\Users\fydral' $name
  if (Test-Path $from) { Move-Item $from (Join-Path 'C:\sable\_harness' $name) -Force }
}
$stub = 'C:\Users\fydral\sable-launcher.exe'
if (Test-Path $stub) { Move-Item $stub 'C:\sable\sable\tools\dist\sable-launcher.exe' -Force }

'--- layout ---'
foreach ($p in @('C:\sable\sable\core\schema.py', 'C:\sable\sable\app\main.py',
                 'C:\sable\sable\tools\dist\sable-launcher.exe',
                 'C:\sable\_harness\gui_audit.py', 'C:\sable\_harness\pecheck.py',
                 'C:\sable\py312\python.exe')) {
  if (Test-Path $p) { 'OK   ' + $p } else { 'MISS ' + $p }
}

# --- the fixture: translators, on this machine, with known plaintext ---
'--- fixture ---'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
& C:\sable\py312\python.exe C:\sable\_harness\sable_fixture.py 2>&1 | Select-String -Pattern 'PASS|FAIL|run_profile' | ForEach-Object { '  ' + $_.Line }
'fixture exit ' + $LASTEXITCODE

# --- the matrix ---
'--- matrix ---'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:SABLE_HEAD = '7d2373f'
Set-Location C:\sable\_harness
& C:\sable\py312\python.exe C:\sable\_harness\gui_audit.py 2>&1 | ForEach-Object { '  ' + $_ }
'matrix exit ' + $LASTEXITCODE
