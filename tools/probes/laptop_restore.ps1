$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$name = 'SABLE-CLEAN'
$vm = Get-VM -Name $name
if ($vm.State -ne 'Off') { Stop-VM -Name $name -TurnOff -Force; Start-Sleep -Seconds 4 }

Restore-VMSnapshot -VMName $name -Name 'clean-baseline' -Confirm:$false
"restored"
Start-VM -Name $name

$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

$ok = $false
for ($i = 1; $i -le 60; $i++) {
    Start-Sleep -Seconds 5
    try {
        $h = Invoke-Command -VMName $name -Credential $cred -ErrorAction Stop -ScriptBlock { $ENV:COMPUTERNAME }
        if ($h) { "guest back after ~" + ($i * 5) + "s : $h"; $ok = $true; break }
    } catch { }
}
if (-not $ok) { "guest did not come back"; exit 1 }

Invoke-Command -VMName $name -Credential $cred -ScriptBlock {
    $s = Get-MpComputerStatus
    "realtime : " + $s.RealTimeProtectionEnabled
    "sig      : " + $s.AntivirusSignatureVersion + "  " + $s.AntivirusSignatureLastUpdated
    "threats  : " + @(Get-MpThreatDetection).Count
    "artifact : " + (Test-Path (Join-Path $env:TEMP 'NorthlineSetup.exe'))
}
