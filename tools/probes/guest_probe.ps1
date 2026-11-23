$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# Runs in the guest's interactive session. Three questions, in order:
#
#   1. Is MessageBoxTimeoutW actually exported by this user32, and does a call through
#      it return a real value or fail silently?
#   2. Does this process own a visible window station and desktop at all?
#   3. When the artifact itself runs, does any window with the configured caption appear
#      for any process, not just the one we expect?
#
# Question 3 is the one that matters, because the earlier watcher only ever looked at
# windows owned by the process it had started, and only ever through EnumWindows in a
# second PowerShell process.

$out = 'C:\guest\probe.json'
$exe = 'C:\guest\SableRuntime.exe'
Remove-Item $out -Force -ErrorAction SilentlyContinue

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class SableProbe
{
    public delegate bool EnumProc(IntPtr h, IntPtr p);

    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr p);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int MessageBoxW(IntPtr h, string text, string caption, uint type);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int MessageBoxTimeoutW(IntPtr h, string text, string caption, uint type, ushort lang, uint ms);
    [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool GetUserObjectInformationW(IntPtr h, int index, StringBuilder buf, int len, out int needed);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr LoadLibraryW(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module, string name);

    const uint FLAGS = 0x00050040;   // MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST
    const int UOI_NAME = 2;

    static string ObjName(IntPtr handle)
    {
        var buf = new StringBuilder(256);
        int needed;
        if (!GetUserObjectInformationW(handle, UOI_NAME, buf, 512, out needed)) return "<err>";
        return buf.ToString();
    }

    static string DumpOwn(uint pid)
    {
        var found = new List<string>();
        EnumWindows((h, p) =>
        {
            uint owner;
            GetWindowThreadProcessId(h, out owner);
            if (owner == pid)
            {
                var cls = new StringBuilder(256);
                var txt = new StringBuilder(512);
                GetClassNameW(h, cls, 256);
                GetWindowTextW(h, txt, 512);
                found.Add((IsWindowVisible(h) ? "vis" : "hid") + " " + cls + " [" + txt + "]");
            }
            return true;
        }, IntPtr.Zero);
        return string.Join(" ;; ", found.ToArray());
    }

    static string WatchOwn(uint pid, int ms)
    {
        var seen = new List<string>();
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < ms)
        {
            string d = DumpOwn(pid);
            if (d.Length > 0 && seen.Count < 12 && !seen.Contains(d)) seen.Add(d);
            Thread.Sleep(200);
        }
        return string.Join(" ## ", seen.ToArray());
    }

    public static string Run()
    {
        var sb = new StringBuilder();
        var me = Process.GetCurrentProcess();
        uint pid = (uint)me.Id;
        sb.AppendLine("pid=" + pid);
        sb.AppendLine("session=" + me.SessionId);
        sb.AppendLine("interactive=" + Environment.UserInteractive);
        sb.AppendLine("winsta=" + ObjName(GetProcessWindowStation()));

        IntPtr mod = LoadLibraryW("user32.dll");
        sb.AppendLine("user32=" + mod.ToInt64());
        bool exported = GetProcAddress(mod, "MessageBoxTimeoutW") != IntPtr.Zero;
        sb.AppendLine("export_timeout=" + exported);

        // --- 1. the timeout export, on a worker, with the main thread watching ---
        int code = -999;
        var t = new Thread(() => { code = MessageBoxTimeoutW(IntPtr.Zero, "probe one", "Sable Probe Timeout", FLAGS, 0, 6000); });
        t.IsBackground = true;
        t.Start();
        Thread.Sleep(500);
        sb.AppendLine("timeout_windows=" + WatchOwn(pid, 4500));
        sb.AppendLine("timeout_alive_mid=" + t.IsAlive);
        t.Join(6000);
        sb.AppendLine("timeout_return=" + code);
        sb.AppendLine("timeout_alive_end=" + t.IsAlive);

        // --- 2. the plain call, which is what the fallback path uses ---
        int code2 = -999;
        var t2 = new Thread(() => { code2 = MessageBoxW(IntPtr.Zero, "probe two", "Sable Probe Plain", FLAGS); });
        t2.IsBackground = true;
        t2.Start();
        Thread.Sleep(500);
        sb.AppendLine("plain_windows=" + WatchOwn(pid, 4000));
        sb.AppendLine("plain_alive_mid=" + t2.IsAlive);
        t2.Join(1500);
        sb.AppendLine("plain_alive_end=" + t2.IsAlive);
        return sb.ToString();
    }

    // --- 3. the artifact, watched globally instead of by pid ---
    public static string WatchArtifact(string exe, int ms, out string timeline)
    {
        var sb = new StringBuilder();
        var lines = new List<string>();
        var sw = Stopwatch.StartNew();

        ProcessStartInfo psi = new ProcessStartInfo(exe);
        psi.UseShellExecute = false;
        Process proc;
        try { proc = Process.Start(psi); }
        catch (Exception exc) { timeline = "start failed: " + exc.Message; return "start failed"; }

        uint target = (uint)proc.Id;
        sb.AppendLine("artifact_pid=" + target);

        var seen = new List<string>();
        while (sw.ElapsedMilliseconds < ms)
        {
            bool alive;
            try { alive = !proc.HasExited; } catch { alive = false; }

            EnumWindows((h, p) =>
            {
                if (IsWindowVisible(h))
                {
                    var txt = new StringBuilder(512);
                    GetWindowTextW(h, txt, 512);
                    if (txt.Length > 0)
                    {
                        uint owner;
                        GetWindowThreadProcessId(h, out owner);
                        var cls = new StringBuilder(256);
                        GetClassNameW(h, cls, 256);
                        string row = owner + "|" + cls + "|" + txt;
                        if (owner == target || txt.ToString().IndexOf("Northline", StringComparison.OrdinalIgnoreCase) >= 0)
                            if (seen.Count < 20 && !seen.Contains(row)) { seen.Add(row); lines.Add(sw.ElapsedMilliseconds + "ms " + row); }
                    }
                }
                return true;
            }, IntPtr.Zero);

            if (!alive) break;
            Thread.Sleep(200);
        }
        sb.AppendLine("artifact_seconds=" + Math.Round(sw.Elapsed.TotalSeconds, 1));
        sb.AppendLine("artifact_windows=" + string.Join(" ## ", seen.ToArray()));
        timeline = string.Join("\n", lines.ToArray());
        return sb.ToString();
    }
}
'@

$report = [ordered]@{}
$report.session = (Get-Process -Id $PID).SessionId
$report.explorer_session = (Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1).SessionId
$report.exe_before = (Test-Path $exe)

$report.api = [SableProbe]::Run()

$timeline = ''
if (Test-Path $exe) {
    $report.artifact = [SableProbe]::WatchArtifact($exe, 90000, [ref]$timeline)
    Start-Sleep -Seconds 15
    $report.exe_after = (Test-Path $exe)
} else {
    $report.artifact = 'artifact missing'
    $report.exe_after = $false
}
$report.timeline = $timeline

($report | ConvertTo-Json -Depth 5) | Set-Content -Path $out -Encoding UTF8
'written ' + $out
