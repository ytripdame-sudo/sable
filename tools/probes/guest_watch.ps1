$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# Runs inside the guest's interactive session (session 1), started from a scheduled task
# registered with -LogonType Interactive.
#
# The launcher is a stub: it spawns a child and the child is what owns the sample and the
# dialog. Watching only the pid we started therefore misses every window. This watcher
# scans the whole desktop and matches the caption instead.

$base = 'C:\guest'
$exe = "$base\SableRuntime.exe"
$out = "$base\run.json"
$caption = 'Northline'
$profile = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default'
$queue = Join-Path $env:LOCALAPPDATA 'DeliveryQueue'
$results = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Sable Results'

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class SableWatch
{
    public delegate bool EnumProc(IntPtr h, IntPtr p);

    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);

    // The task starts this script with a console, and a console in session 1 sits on top
    // of the desktop the thumbnail is taken from. Hidden, the screenshot shows the sample
    // instead of the watcher.
    public static void HideConsole()
    {
        IntPtr h = GetConsoleWindow();
        if (h != IntPtr.Zero) ShowWindow(h, 0);
    }
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr p);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);

    public static List<string> Match(string needle)
    {
        var found = new List<string>();
        EnumWindows((h, p) =>
        {
            if (IsWindowVisible(h))
            {
                var txt = new StringBuilder(512);
                GetWindowTextW(h, txt, 512);
                if (txt.Length > 0 && txt.ToString().IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var cls = new StringBuilder(256);
                    GetClassNameW(h, cls, 256);
                    uint owner;
                    GetWindowThreadProcessId(h, out owner);
                    found.Add(owner + "|" + cls + "|" + txt);
                }
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
'@

function TempSable { @(Get-ChildItem $env:TEMP -Directory -Filter 'sable-*' -ErrorAction SilentlyContinue) }
function TempMei { @(Get-ChildItem $env:TEMP -Directory -Filter '_MEI*' -ErrorAction SilentlyContinue) }

[SableWatch]::HideConsole()

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

function GrabScreen([string]$path) {
    try {
        $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
        $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $bmp.Dispose()
    } catch { }
}

$r = [ordered]@{}
$r.session_user = "$env:USERDOMAIN\$env:USERNAME"
$r.watch_session = (Get-Process -Id $PID).SessionId
$r.explorer_session = (Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1).SessionId
$r.exe_before = (Test-Path $exe)
$r.temp_before = @(TempSable).Count
$r.mei_before = @(TempMei).Count
$r.queue_before = if (Test-Path $queue) { @(Get-ChildItem $queue -Recurse -File).Count } else { 0 }
$r.profile_before = (Test-Path (Join-Path $profile 'Login Data'))
$r.results_before = (Test-Path $results)

# Roblox proof mode. ``store`` leaves the sealed cookie row in the profile and the
# collector answers from disk. ``memory`` hands it a live process named chrome.exe that
# holds a different token, with no row on disk, so the RAM half is the only answer.
$mode = 'store'
$modePath = Join-Path $base 'mode.txt'
if (Test-Path $modePath) { $mode = (Get-Content $modePath -Raw).Trim() }
$r.roblox_mode = $mode
$fake = $null
if ($mode -eq 'memory') {
    $fakePath = Join-Path $base 'py\chrome.exe'
    $holderPath = Join-Path $base 'fake\hold.py'
    if ((Test-Path $fakePath) -and (Test-Path $holderPath)) {
        $fake = Start-Process -FilePath $fakePath -ArgumentList $holderPath -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 3
        $r.fake_pid = $fake.Id
        $r.fake_alive = -not $fake.HasExited
        $r.fake_private_mb = [math]::Round((Get-Process -Id $fake.Id -ErrorAction SilentlyContinue).PrivateMemorySize64 / 1MB, 2)
    } else {
        $r.fake_alive = $false
    }
}

$titles = New-Object 'System.Collections.Generic.List[string]'
$pids = New-Object 'System.Collections.Generic.List[int]'
$first = $null
$last = $null
$grabbed = $false

$proc = Start-Process -FilePath $exe -PassThru
$r.artifact_session = $proc.SessionId
$root_pid = $proc.Id
$sw = [Diagnostics.Stopwatch]::StartNew()

# The child is what matters. Sample the process tree rather than one handle.
while ($sw.Elapsed.TotalSeconds -lt 240) {
    $hit = [SableWatch]::Match($caption)
    foreach ($row in $hit) {
        if (-not $titles.Contains($row)) { $titles.Add($row) }
        $child = [int]($row.Split('|')[0])
        if (-not $pids.Contains($child)) { $pids.Add($child) }
        if (-not $first) { $first = $sw.Elapsed.TotalSeconds }
        $last = $sw.Elapsed.TotalSeconds
    }

    # Pixels the moment the caption exists, because the run finishes faster than the
    # host's thumbnail loop can sample: the window is often up for about a second.
    if (-not $grabbed -and $hit.Count -gt 0) {
        GrabScreen "$base\decoy.png"
        $grabbed = $true
        Start-Sleep -Milliseconds 400
        if ([SableWatch]::Match($caption).Count -gt 0) { GrabScreen "$base\decoy2.png" }
    }

    $alive = $false
    if (Get-Process -Id $root_pid -ErrorAction SilentlyContinue) { $alive = $true }
    foreach ($id in $pids) { if (Get-Process -Id $id -ErrorAction SilentlyContinue) { $alive = $true } }
    if (-not $alive -and $sw.Elapsed.TotalSeconds -gt 3) { break }
    Start-Sleep -Milliseconds 200
}
$sw.Stop()

$r.root_pid = $root_pid
$r.window_pids = @($pids)
$r.run_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
$r.window_titles = @($titles)
$r.decoy_first_s = if ($first) { [math]::Round($first, 2) } else { -1 }
$r.decoy_last_s = if ($last) { [math]::Round($last, 2) } else { -1 }
$r.decoy_span_s = if ($first -and $last) { [math]::Round($last - $first, 2) } else { -1 }

# The self-removal is a detached cmd that waits for the image to unlock, then deletes it.
Start-Sleep -Seconds 15

$r.exe_after = (Test-Path $exe)
$r.exe_old = (Test-Path ($exe + '.old'))
$r.temp_after = @(TempSable | ForEach-Object { $_.Name })
$r.mei_after = @(TempMei | ForEach-Object { $_.Name })
$r.queue_after = if (Test-Path $queue) { @(Get-ChildItem $queue -Recurse -File | ForEach-Object { $_.Name }) } else { @() }
$r.retry_task = [bool](schtasks /query /tn DeliveryQueue 2>&1 | Select-String 'DeliveryQueue')
$r.profile_after = (Test-Path (Join-Path $profile 'Login Data'))
$r.results_after = (Test-Path $results)
$r.stray = @(Get-Process -Name 'SableRuntime' -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
if ($fake) {
    try { if (-not $fake.HasExited) { $fake.Kill() } } catch { }
    $r.fake_stopped = $fake.HasExited
}

$r | ConvertTo-Json -Depth 5 | Set-Content -Path $out -Encoding UTF8
'written ' + $out
