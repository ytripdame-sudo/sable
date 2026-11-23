$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ConfirmPreference = "None"

$name = 'SABLE-CLEAN'

Get-VMSnapshot -VMName $name -ErrorAction SilentlyContinue | ForEach-Object {
    "removing old snapshot : " + $_.Name
    Remove-VMSnapshot -VMName $name -Name $_.Name
}

Checkpoint-VM -Name $name -SnapshotName 'clean-baseline'
Start-Sleep -Seconds 3

Write-Output "=== snapshots ==="
Get-VMSnapshot -VMName $name | ForEach-Object { "  {0}  parent={1}" -f $_.Name, $_.ParentSnapshotName }
"vm state  : " + (Get-VM -Name $name).State
"vhd MB    : " + [math]::Round((Get-Item 'C:\sablevm\SABLE-CLEAN.vhdx').Length / 1MB, 0)
