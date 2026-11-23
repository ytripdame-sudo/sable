$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ConfirmPreference = "None"

$name = 'SABLE-CLEAN'
$ansIso = 'C:\sablevm\answer.iso'

# prove the ISO is readable before it is attached to anything
$img = Mount-DiskImage -ImagePath $ansIso -PassThru
Start-Sleep -Seconds 2
$drive = ($img | Get-Volume).DriveLetter
"answer iso mounted : $drive`:"
"contents           : " + ((Get-ChildItem "${drive}:\").Name -join ', ')
$xml = Get-Content "${drive}:\autounattend.xml" -Raw
"xml bytes          : " + $xml.Length
"xml head           : " + $xml.Substring(0, 62)
Dismount-DiskImage -ImagePath $ansIso | Out-Null
"dismounted"

$vm = Get-VM -Name $name
if ($vm.State -ne 'Off') { Stop-VM -Name $name -TurnOff -Force; Start-Sleep -Seconds 4 }

Get-VMHardDiskDrive -VMName $name | Where-Object { (Split-Path $_.Path -Leaf) -eq 'answer.vhdx' } |
    ForEach-Object { Remove-VMHardDiskDrive -VMName $name -ControllerType $_.ControllerType -ControllerNumber $_.ControllerNumber -ControllerLocation $_.ControllerLocation; "removed answer.vhdx disk" }

Remove-Item -Force 'C:\sablevm\SABLE-CLEAN.vhdx' -ErrorAction SilentlyContinue

New-VHD -Path 'C:\sablevm\SABLE-CLEAN.vhdx' -SizeBytes 60GB -Dynamic | Out-Null
Add-VMHardDiskDrive -VMName $name -Path 'C:\sablevm\SABLE-CLEAN.vhdx'
"os disk recreated"

Get-VMDvdDrive -VMName $name | ForEach-Object { "  dvd before: " + (Split-Path $_.Path -Leaf) }
Add-VMDvdDrive -VMName $name -Path $ansIso
Get-VMDvdDrive -VMName $name | ForEach-Object { "  dvd now   : " + (Split-Path $_.Path -Leaf) }

$installDvd = Get-VMDvdDrive -VMName $name | Where-Object { $_.Path -eq 'C:\sablevm\win10.iso' }
Set-VMFirmware -VMName $name -FirstBootDevice $installDvd
$fw = Get-VMFirmware -VMName $name
"secureboot : " + $fw.SecureBoot
$fw.BootOrder | ForEach-Object { "  boot: " + $_.BootType + "  " + $_.Device.Name }
