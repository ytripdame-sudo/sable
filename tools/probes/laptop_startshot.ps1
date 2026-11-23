$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$name = 'SABLE-CLEAN'
$ns = 'root\virtualization\v2'

$vm = Get-VM -Name $name
if ($vm.State -eq 'Off') {
    Start-VM -Name $name
    "started"
    Start-Sleep -Seconds 12
}

function Get-Kb {
    $vc = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$name'"
    Get-CimInstance -Namespace $ns -ClassName Msvm_Keyboard -Filter "SystemName='$($vc.Name)'"
}
$kb = Get-Kb
for ($i = 0; $i -lt 12; $i++) {
    try { Invoke-CimMethod -InputObject $kb -MethodName 'TypeKey' -Arguments @{ keyCode = [byte]32 } | Out-Null } catch { }
    Start-Sleep -Milliseconds 400
}
"keys sent"

Start-Sleep -Seconds 25
"state      : " + (Get-VM -Name $name).State
"vhd MB     : " + [math]::Round((Get-Item 'C:\sablevm\SABLE-CLEAN.vhdx').Length / 1MB, 1)
