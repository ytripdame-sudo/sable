$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ConfirmPreference = "None"

$name = 'SABLE-CLEAN'
$root = 'C:\sablevm'
$iso  = Join-Path $root 'win10.iso'
$vhdx = Join-Path $root 'SABLE-CLEAN.vhdx'
$ans  = Join-Path $root 'answer.vhdx'

foreach ($p in @($iso, $ans)) {
    if (-not (Test-Path $p)) { throw "missing $p" }
}

if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) { throw "Hyper-V module not loaded" }

$old = Get-VM -Name $name -ErrorAction SilentlyContinue
if ($old) {
    "removing old vm"
    if ($old.State -ne 'Off') { Stop-VM -Name $name -TurnOff -Force }
    Remove-VM -Name $name -Force
}
if (Test-Path $vhdx) { Remove-Item -Force $vhdx }

"iso        : " + [math]::Round((Get-Item $iso).Length/1MB,1) + " MB"
"answer vhd : " + [math]::Round((Get-Item $ans).Length/1MB,1) + " MB"

New-VM -Name $name -Generation 2 -MemoryStartupBytes 3GB `
       -NewVHDPath $vhdx -NewVHDSizeBytes 60GB `
       -SwitchName 'Default Switch' | Out-Null

Set-VMProcessor -VMName $name -Count 2 -ExposeVirtualizationExtensions $false
Set-VMMemory -VMName $name -DynamicMemoryEnabled $false -StartupBytes 3GB
Set-VM -Name $name -AutomaticCheckpointsEnabled $false -CheckpointType Standard
Set-VM -Name $name -AutomaticStartAction Nothing -AutomaticStopAction ShutDown

$dvd = Add-VMDvdDrive -VMName $name -Path $iso
Add-VMHardDiskDrive -VMName $name -Path $ans
Set-VMFirmware -VMName $name -EnableSecureBoot Off
Set-VMFirmware -VMName $name -FirstBootDevice $dvd

"--- layout ---"
Get-VMHardDiskDrive -VMName $name | ForEach-Object { "  hdd  ctrl={0} lun={1}  {2}" -f $_.ControllerType, $_.ControllerNumber, (Split-Path $_.Path -Leaf) }
Get-VMDvdDrive -VMName $name | ForEach-Object { "  dvd  ctrl={0} lun={1}  {2}" -f $_.ControllerType, $_.ControllerNumber, (Split-Path $_.Path -Leaf) }

Start-VM -Name $name
Start-Sleep -Seconds 5
"state      : " + (Get-VM -Name $name).State
"uptime     : " + (Get-VM -Name $name).Uptime
