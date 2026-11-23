$ErrorActionPreference = 'Stop'
$home_dir = 'C:\Users\fydral'
foreach ($name in @('sable-src.zip', 'py312.tar')) {
  $path = Join-Path $home_dir $name
  if (Test-Path $path) { 'FILE ' + $name + ' ' + (Get-Item $path).Length } else { 'MISSING ' + $name }
}

New-Item -ItemType Directory -Force C:\sable | Out-Null
New-Item -ItemType Directory -Force C:\sable\src | Out-Null

if (Test-Path C:\sable\py312\python.exe) {
  'py312    already extracted'
} else {
  $ProgressPreference = 'SilentlyContinue'
  tar -xf (Join-Path $home_dir 'py312.tar') -C C:\sable
  if (Test-Path C:\sable\py312\python.exe) { 'py312    extracted' } else { 'py312    FAILED' }
}

if (Test-Path C:\sable\src\sable\core\schema.py) {
  'src      already extracted'
} else {
  Expand-Archive -Path (Join-Path $home_dir 'sable-src.zip') -DestinationPath C:\sable\src -Force
  if (Test-Path C:\sable\src\core\schema.py) { 'src      extracted (root)' }
  elseif (Test-Path C:\sable\src\sable\core\schema.py) { 'src      extracted (nested)' }
  else { 'src      FAILED' }
}

'--- tree ---'
Get-ChildItem C:\sable | ForEach-Object { 'DIR  ' + $_.Name }
'--- python ---'
& C:\sable\py312\python.exe -c "import sys,PySide6,Crypto;print('python',sys.version.split()[0]);print('pyside',PySide6.__version__)"
