$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ConfirmPreference = "None"

$name   = 'SABLE-CLEAN'
$root   = 'C:\sablevm'
$osIso  = Join-Path $root 'win10.iso'
$ansIso = Join-Path $root 'answer.iso'
$vhdx   = Join-Path $root 'SABLE-CLEAN.vhdx'

$vm = Get-VM -Name $name -ErrorAction SilentlyContinue
if ($vm) {
    if ($vm.State -ne 'Off') { Stop-VM -Name $name -TurnOff -Force; Start-Sleep -Seconds 4 }
    Remove-VM -Name $name -Force
    "old vm removed"
}
Remove-Item -Force $vhdx -ErrorAction SilentlyContinue

New-VM -Name $name -Generation 2 -MemoryStartupBytes 3GB `
       -NewVHDPath $vhdx -NewVHDSizeBytes 60GB `
       -SwitchName 'Default Switch' | Out-Null
Set-VMProcessor -VMName $name -Count 2
Set-VMMemory -VMName $name -DynamicMemoryEnabled $false -StartupBytes 3GB
Set-VM -Name $name -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing

Add-VMDvdDrive -VMName $name -Path $osIso  | Out-Null
Add-VMDvdDrive -VMName $name -Path $ansIso | Out-Null

Set-VMFirmware -VMName $name -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
$dvd = Get-VMDvdDrive -VMName $name | Where-Object { $_.Path -eq $osIso }
if (-not $dvd) { throw "install dvd not attached" }
Set-VMFirmware -VMName $name -FirstBootDevice $dvd

Write-Output "--- layout ---"
Get-VMHardDiskDrive -VMName $name | ForEach-Object { "  hdd loc={0} {1}" -f $_.ControllerLocation, (Split-Path $_.Path -Leaf) }
Get-VMDvdDrive     -VMName $name | ForEach-Object { "  dvd loc={0} {1}" -f $_.ControllerLocation, (Split-Path $_.Path -Leaf) }
(Get-VMFirmware -VMName $name).BootOrder | ForEach-Object { "  boot {0,-8} {1}" -f $_.BootType, $_.Device.Name }

Write-Output "--- starting ---"
$ns = 'root\virtualization\v2'
Start-VM -Name $name
Start-Sleep -Seconds 2
$vc = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$name'"
$kb = Get-CimInstance -Namespace $ns -ClassName Msvm_Keyboard -Filter "SystemName='$($vc.Name)'"
for ($i = 0; $i -lt 30; $i++) {
    try { Invoke-CimMethod -InputObject $kb -MethodName 'TypeKey' -Arguments @{ keyCode = [byte]32 } | Out-Null } catch { }
    Start-Sleep -Milliseconds 500
}
"keys sent, watching disk"
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 10
    $mb = [math]::Round((Get-Item $vhdx).Length / 1MB, 0)
    if ($i % 3 -eq 0) { "  t+{0,3}s  vhd {1} MB" -f (($i + 1) * 10), $mb }
    if ($mb -gt 4000) { "  setup is writing"; break }
}
"vhd final  : " + [math]::Round((Get-Item $vhdx).Length / 1MB, 0) + " MB"
"state      : " + (Get-VM -Name $name).State
