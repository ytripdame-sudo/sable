$ErrorActionPreference = 'Continue'
"host      : " + $env:COMPUTERNAME
"user      : " + $env:USERNAME
"ps        : " + $PSVersionTable.PSVersion

"--- python ---"
$py = @(
  'C:\Users\fydral\AppData\Local\Programs\Python\Python312\python.exe',
  'C:\Python312\python.exe',
  'C:\Users\fydral\AppData\Local\Temp\opencode\py312\python.exe'
)
foreach ($p in $py) { if (Test-Path $p) { "found     : $p  (" + (& $p -c "import sys;print(sys.version.split()[0])") + ")" } }
$cmd = Get-Command python -ErrorAction SilentlyContinue
if ($cmd) { "python    : " + $cmd.Source; "version   : " + (& python -c "import sys;print(sys.version.split()[0])" 2>&1) }

"--- sable trees ---"
foreach ($root in @('C:\Users\fydral\Desktop','C:\Users\fydral\Documents','C:\Users\fydral','C:\sable','C:\Work','C:\Users\fydral\Downloads')) {
  if (Test-Path $root) {
    Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match 'sable|55555|bench' } |
      ForEach-Object { "dir       : " + $_.FullName }
  }
}

"--- any MANIFEST ---"
Get-ChildItem 'C:\Users\fydral' -Filter MANIFEST.txt -Recurse -Depth 4 -ErrorAction SilentlyContinue |
  Select-Object -First 5 | ForEach-Object { "manifest  : " + $_.FullName }

"--- hyper-v ---"
try { (Get-VM -ErrorAction Stop | Select-Object Name,State | Out-String).Trim() } catch { "vm err    : " + $_.Exception.Message }

"--- sshd ---"
try { (Get-Service sshd | Select-Object Status,StartType | Out-String).Trim() } catch { "sshd err" }
"--- free ---"
"free GB   : " + [math]::Round((Get-PSDrive C).Free / 1GB, 1)
