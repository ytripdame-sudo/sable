$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ConfirmPreference = "None"

$root = 'C:\sablevm'
New-Item -ItemType Directory -Force -Path $root | Out-Null

$vhd = Join-Path $root 'answer.vhdx'
$src = Join-Path $root 'autounattend.xml'
if (-not (Test-Path $src)) { throw "autounattend.xml not staged at $src" }
"answer xml : " + (Get-Item $src).Length + " bytes"

if (Test-Path $vhd) {
    try { Dismount-VHD -Path $vhd -ErrorAction Stop } catch { }
    Remove-Item -Force $vhd
}

New-VHD -Path $vhd -SizeBytes 64MB -Fixed | Out-Null
"vhd        : " + (Get-Item $vhd).Length + " bytes"

Mount-VHD -Path $vhd | Out-Null
Start-Sleep -Seconds 3

$disk = Get-Disk | Where-Object { $_.Location -like '*answer.vhdx*' }
if (-not $disk) { throw "mounted disk not found" }
"disk       : " + $disk.Number + "  size " + $disk.Size

Initialize-Disk -Number $disk.Number -PartitionStyle MBR | Out-Null
$part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
Start-Sleep -Seconds 2
$part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
$letter = [string]$part.DriveLetter
if (-not $letter) { throw "no drive letter assigned" }
"partition  : $letter`:"

Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel 'ANSWER' -Confirm:$false | Out-Null
Start-Sleep -Seconds 1

Copy-Item -Path $src -Destination "${letter}:\autounattend.xml" -Force
$check = Get-Item "${letter}:\autounattend.xml"
"copied     : " + $check.Length + " bytes at " + $check.FullName
"files      : " + ((Get-ChildItem "${letter}:\").Name -join ', ')

Dismount-VHD -Path $vhd
"vhd final  : " + (Get-Item $vhd).Length + " bytes"
