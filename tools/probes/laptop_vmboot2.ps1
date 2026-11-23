$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$name = 'SABLE-CLEAN'
$vm = Get-VM -Name $name
if ($vm.State -ne 'Off') { Stop-VM -Name $name -TurnOff -Force; Start-Sleep -Seconds 4 }

Set-VMFirmware -VMName $name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
$fw = Get-VMFirmware -VMName $name
"secureboot : " + $fw.SecureBoot
"template   : " + $fw.SecureBootTemplate
$dvd = Get-VMDvdDrive -VMName $name
Set-VMFirmware -VMName $name -FirstBootDevice $dvd
"first      : " + (Get-VMFirmware -VMName $name).BootOrder[0].Device.Name

# send a key right after start so the "press any key" window is caught
$ns = 'root\virtualization\v2'
Start-VM -Name $name
$vc = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$name'"
Start-Sleep -Seconds 2
$kb = Get-CimInstance -Namespace $ns -ClassName Msvm_Keyboard -Filter "SystemName='$($vc.Name)'"
for ($i = 0; $i -lt 40; $i++) {
    try { Invoke-CimMethod -InputObject $kb -MethodName 'TypeKey' -Arguments @{ keyCode = [byte]32 } | Out-Null } catch { }
    Start-Sleep -Milliseconds 500
}
"keys sent"
Start-Sleep -Seconds 30
"state      : " + (Get-VM -Name $name).State
"vhd MB     : " + [math]::Round((Get-Item 'C:\sablevm\SABLE-CLEAN.vhdx').Length / 1MB, 1)
