$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Stop-VM -Name SABLE-CLEAN -TurnOff -Force
Start-Sleep -Seconds 3

$dvd = Get-VMDvdDrive -VMName SABLE-CLEAN
"dvd path   : " + $dvd.Path
Set-VMFirmware -VMName SABLE-CLEAN -FirstBootDevice $dvd

$fw = Get-VMFirmware -VMName SABLE-CLEAN
Write-Output "--- boot order now ---"
$fw.BootOrder | ForEach-Object { "  " + $_.BootType + "  " + $_.Device.Name }

$first = $fw.BootOrder[0]
if ($first.BootType -ne 'Drive' -or $first.Device.Path -ne $dvd.Path) {
    throw "boot order did not take: first is " + $first.BootType
}
"first boot : DVD " + (Split-Path $first.Device.Path -Leaf)

Start-VM -Name SABLE-CLEAN
Start-Sleep -Seconds 20
"state      : " + (Get-VM -Name SABLE-CLEAN).State
"vhdx MB    : " + [math]::Round((Get-Item 'C:\sablevm\SABLE-CLEAN.vhdx').Length / 1MB, 1)
