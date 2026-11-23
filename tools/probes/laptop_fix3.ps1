$ErrorActionPreference = 'Continue'
Set-Location C:\sable\_harness
& C:\sable\py312\python.exe -c @"
import sys
from pathlib import Path
ROOT = Path(r'C:\sable\_harness\sable_fixture.py').resolve().parents[1]
p = str(ROOT / 'sable')
print('insert', p, 'isdir', Path(p).is_dir())
sys.path.insert(0, p)
print('path0', sys.path[0])
try:
    from agent.sources.browsers import chromium
    print('import ok', chromium.__file__)
except Exception as exc:
    print('import failed', type(exc).__name__, exc)
    import agent
"@ 2>&1 | ForEach-Object { '  ' + $_ }
'--- head of the file on disk ---'
Get-Content C:\sable\_harness\sable_fixture.py -TotalCount 30 | ForEach-Object { '  | ' + $_ }
