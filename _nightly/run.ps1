#Requires -Version 5.1
<#
    SABLE nightly loop.

    Runs the gate, and while it is red asks the `nightly` agent to fix exactly one
    queue item. Everything happens on a throwaway branch. It never pushes, never
    merges, and never touches `main`.

    Preflight refuses to start unless the tree is clean, so a dirty tree is never
    mixed into an unattended commit.

        powershell -NoProfile -ExecutionPolicy Bypass -File _nightly\run.ps1
        powershell ... -File _nightly\run.ps1 -GateOnly
        powershell ... -File _nightly\run.ps1 -MaxRounds 6 -Model opencode/some-model

    Drop `_nightly\STOP` to halt at the next round boundary. `_nightly\REPORT.md`
    is the morning read.
#>
[CmdletBinding()]
param(
    [int]$MaxRounds = 4,
    [string]$Model = '',
    [switch]$GateOnly
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$Nightly = $PSScriptRoot
$Root = Split-Path -Parent $Nightly
Set-Location -LiteralPath $Root

$StopFile    = Join-Path $Nightly 'STOP'
$ReportFile  = Join-Path $Nightly 'REPORT.md'
$LastFailure = Join-Path $Nightly 'last-failure.txt'
$QueueFile   = Join-Path $Nightly 'QUEUE.md'
$Stamp       = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogFile     = Join-Path $Nightly "nightly-$Stamp.log"

# The interpreter the gate has always used. Override with SABLE_PY on another machine.
$Python = $env:SABLE_PY
if (-not $Python) {
    $Python = Join-Path $env:LOCALAPPDATA 'Temp\opencode\py312\python.exe'
}
if (-not (Test-Path -LiteralPath $Python)) {
    $Python = 'python'
}

$Opencode = $env:SABLE_OPENCODE
if (-not $Opencode) {
    $cmd = Get-Command opencode -CommandType Application,ExternalScript -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($cmd) { $Opencode = $cmd.Source }
}

# Frozen for every child process this script starts, so the task does not depend on
# the user's environment being set.
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:QT_QPA_PLATFORM = 'offscreen'

function Write-Log {
    param([string]$Text)
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text
    Write-Host $line
    Add-Content -LiteralPath $LogFile -Value $line -Encoding utf8
}

function Invoke-Git {
    param([string[]]$Arguments)
    $text = & git @Arguments 2>&1 | Out-String
    [pscustomobject]@{ Code = $LASTEXITCODE; Text = $text.Trim() }
}

function Invoke-Gate {
    $stages = @(
        @{ Name = 'pytest';     Args = @('-m', 'pytest', '-q', '--no-header', '-p', 'no:cacheprovider') },
        @{ Name = 'ruff';       Args = @('-m', 'ruff', 'check', '.') },
        @{ Name = 'compileall'; Args = @('-m', 'compileall', '-q', 'agent', 'core', 'app', 'tests', 'tools') }
    )
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($stage in $stages) {
        $argv = $stage.Args
        $out = & $Python @argv 2>&1 | Out-String
        $code = $LASTEXITCODE
        $lines.Add("--- $($stage.Name) exit $code ---")
        if ($out.Trim()) { $lines.Add($out.Trim()) }
        if ($code -ne 0) {
            return [pscustomobject]@{ Ok = $false; Stage = $stage.Name; Exits = $lines; Text = ($lines -join "`n") }
        }
    }
    [pscustomobject]@{ Ok = $true; Stage = 'none'; Exits = $lines; Text = ($lines -join "`n") }
}

function Get-QueueItem {
    if (-not (Test-Path -LiteralPath $QueueFile)) { return $null }
    $all = @(Get-Content -LiteralPath $QueueFile)
    for ($i = 0; $i -lt $all.Count; $i++) {
        if ($all[$i] -match '^\s*-\s*\[\s\]\s*(.+)$') {
            $parts = @($Matches[1].Trim())
            $j = $i + 1
            # Wrapped items continue on indented lines.
            while ($j -lt $all.Count -and $all[$j] -match '^\s{4,}\S') {
                $parts += $all[$j].Trim()
                $j++
            }
            $text = ($parts -join ' ')
            if ($text -notmatch '@human') { return $text }
        }
    }
    return $null
}

Write-Log "nightly start; root=$Root; python=$Python"

if (Test-Path -LiteralPath $StopFile) {
    Write-Log 'STOP file present; exiting without touching the tree'
    exit 0
}

$inside = Invoke-Git @('rev-parse', '--is-inside-work-tree')
if ($inside.Code -ne 0 -or $inside.Text -ne 'true') {
    Write-Log 'not a git work tree; exiting'
    exit 3
}

$gate = Invoke-Gate
Write-Log ("preflight gate: {0} (failed stage: {1})" -f ($(if ($gate.Ok) { 'green' } else { 'red' })), $gate.Stage)

if ($GateOnly) {
    Write-Host $gate.Text
    if ($gate.Ok) { exit 0 } else { exit 1 }
}

if ($gate.Ok) {
    Write-Log 'gate already green; nothing to fix'
    exit 0
}

$item = Get-QueueItem
if (-not $item) {
    Write-Log 'queue is empty or every item is @human; not starting a branch'
    exit 0
}
Write-Log "item: $item"

$dirty = Invoke-Git @('status', '--porcelain')
if ($dirty.Text) {
    Write-Log 'tree is not clean; refusing to mix unattended work with it'
    Write-Host $dirty.Text
    exit 3
}

$headRef = Invoke-Git @('rev-parse', '--abbrev-ref', 'HEAD')
$headSha = (Invoke-Git @('rev-parse', '--short', 'HEAD')).Text
$original = $headRef.Text
$branch = 'auto/nightly-' + (Get-Date -Format 'yyyyMMdd')
$n = 0
while ((Invoke-Git @('rev-parse', '--verify', '--quiet', "refs/heads/$branch")).Code -eq 0) {
    $n++
    $branch = 'auto/nightly-' + (Get-Date -Format 'yyyyMMdd') + "-$n"
}

$made = Invoke-Git @('switch', '-c', $branch)
if ($made.Code -ne 0) {
    Write-Log "could not create $branch; exiting"
    Write-Host $made.Text
    exit 3
}
Write-Log "branch $branch from $original @ $headSha"

if (-not $Opencode) {
    Write-Log 'opencode not found; gate-only run'
}

$previous = ''
$stalled = $false
$round = 0

while (-not $gate.Ok) {
    if (Test-Path -LiteralPath $StopFile) {
        Write-Log 'STOP file appeared; halting at round boundary'
        break
    }
    if ($round -ge $MaxRounds) {
        Write-Log "round cap $MaxRounds reached"
        break
    }

    $signature = ($gate.Text -split "`n" | Select-Object -Last 40) -join "`n"
    if ($signature -eq $previous) {
        $stalled = $true
        Write-Log 'same failure twice with no progress; halting'
        break
    }
    $previous = $signature

    $round++
    Set-Content -LiteralPath $LastFailure -Value $gate.Text -Encoding utf8
    Write-Log "round $round; asking the nightly agent"

    if (-not $Opencode) { break }

    $prompt = @"
Round $round of $MaxRounds. The gate failed at stage '$($gate.Stage)'.

Your objective is the first unchecked non-@human item in _nightly\QUEUE.md:

$item

The captured gate output is below. Fix the cause, not the test.

$($gate.Text)
"@

    $ocArgs = @('run', '--agent', 'nightly', '--auto', '--standalone', '--archived')
    if ($Model) { $ocArgs += @('--model', $Model) }
    $ocArgs += $prompt

    & $Opencode @ocArgs 2>&1 | Tee-Object -FilePath $LogFile -Append | ForEach-Object { Write-Host $_ }
    Write-Log "round $round finished; re-running the gate"

    $gate = Invoke-Gate
    Write-Log ("gate after round {0}: {1}" -f $round, $(if ($gate.Ok) { 'green' } else { "red at $($gate.Stage)" }))
}

$verdict = if ($gate.Ok) { 'green' } elseif ($stalled) { 'stalled' } else { 'red' }
$diff = Invoke-Git @('diff', '--stat')
$status = Invoke-Git @('status', '--porcelain')

$failureExcerpt = 'none'
if (-not $gate.Ok) {
    $tail = ($gate.Text -split "`n" | Select-Object -Last 40) -join "`n"
    $failureExcerpt = $tail
}

$report = @"
# Nightly report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')

| | |
|---|---|
| verdict | **$verdict** |
| branch | ``$branch`` |
| started from | ``$original`` @ ``$headSha`` |
| rounds | $round / $MaxRounds |
| item | $item |
| log | ``$LogFile`` |

## Gate

``````
$($gate.Exits -join "`n")
``````

## Changes

``````
$(if ($diff.Text) { $diff.Text } else { '(no tracked changes)' })
``````

## Failure tail

``````
$failureExcerpt
``````

$(if ($verdict -eq 'green') { 'Green. Merge it or bin it.' } else { 'Not green. The branch holds the attempt; the failure tail is above.' })
"@

Set-Content -LiteralPath $ReportFile -Value $report -Encoding utf8

$committed = $false
if ($status.Text) {
    Invoke-Git @('add', '-A') | Out-Null
    $msgFile = Join-Path ([System.IO.Path]::GetTempPath()) "sable-nightly-$Stamp.txt"
    Set-Content -LiteralPath $msgFile -Value "nightly: $verdict - $item" -Encoding utf8
    $commit = Invoke-Git @('commit', '-F', $msgFile)
    Remove-Item -LiteralPath $msgFile -Force -ErrorAction SilentlyContinue
    if ($commit.Code -eq 0) {
        $committed = $true
        Write-Log 'committed on the branch'
    }
    else {
        Write-Log 'commit refused; leaving the work uncommitted on the branch'
        Write-Host $commit.Text
    }
}

if ($original -and $original -ne $branch) {
    $back = Invoke-Git @('switch', $original)
    if ($back.Code -ne 0) {
        Write-Log "could not return to $original; staying on $branch"
        Write-Host $back.Text
    }
    else {
        Write-Log "back on $original"
    }
}

Get-ChildItem -LiteralPath $Root -Recurse -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Log ("nightly done: {0}; committed={1}" -f $verdict, $committed)

if ($verdict -eq 'green') { exit 0 } else { exit 1 }
