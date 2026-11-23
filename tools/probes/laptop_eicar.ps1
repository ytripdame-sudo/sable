$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$name = 'SABLE-CLEAN'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

$vm = Get-VM -Name $name
if ($vm.State -ne 'Off') { Stop-VM -Name $name -TurnOff -Force; Start-Sleep -Seconds 4 }
Restore-VMSnapshot -VMName $name -Name 'clean-baseline' -Confirm:$false
Start-VM -Name $name
"restored"

for ($i = 1; $i -le 60; $i++) {
    Start-Sleep -Seconds 5
    try {
        $h = Invoke-Command -VMName $name -Credential $cred -ErrorAction Stop -ScriptBlock { $ENV:COMPUTERNAME }
        if ($h) { "guest up after ~" + ($i * 5) + "s"; break }
    } catch { }
}

Invoke-Command -VMName $name -Credential $cred -ErrorAction Stop -ScriptBlock {
    $ProgressPreference = "SilentlyContinue"

    # EICAR, assembled from char codes so no layer mangles it
    $codes = @(88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42)
    $eicar = -join ($codes | ForEach-Object { [char]$_ })

    $path = Join-Path $env:TEMP 'eicar-control.com'
    "writing control file : $path"
    try {
        [IO.File]::WriteAllText($path, $eicar)
        "write returned ok (no synchronous block)"
    } catch {
        "write threw: " + $_.Exception.GetType().Name
    }

    Start-Sleep -Seconds 8
    "file still there : " + (Test-Path $path)
    "threats now      : " + @(Get-MpThreatDetection).Count
    @(Get-MpThreatDetection) | ForEach-Object {
        "  {0} | {1} | {2}" -f $_.ThreatID, $_.InitialDetectionTime, ($_.Resources -join ',')
    }
    $ev = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'} -MaxEvents 10 -ErrorAction SilentlyContinue
    "recent defender events:"
    $ev | Select-Object -First 6 | ForEach-Object { "  {0} id={1}" -f $_.TimeCreated.ToString('HH:mm:ss'), $_.Id }
}
