$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ConfirmPreference = "None"

$name = 'SABLE-CLEAN'
$ns = 'root\virtualization\v2'

function Get-Kb {
    $vc = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$name'"
    $kb = Get-CimInstance -Namespace $ns -ClassName Msvm_Keyboard -Filter "SystemName='$($vc.Name)'"
    return $kb
}

$vm = Get-VM -Name $name
if ($vm.State -ne 'Off') { Stop-VM -Name $name -TurnOff -Force; Start-Sleep -Seconds 3 }

$vhd = 'C:\sablevm\SABLE-CLEAN.vhdx'
$before = (Get-Item $vhd).Length
"vhd before : $before"

foreach ($attempt in 1..3) {
    "--- attempt $attempt ---"
    Start-VM -Name $name
    $kb = $null
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Seconds 1
        try {
            if (-not $kb -or $kb.SystemName -eq $null) { $kb = Get-Kb }
            $r = Invoke-CimMethod -InputObject $kb -MethodName 'TypeKey' -Arguments @{ keyCode = [byte]32 }
            if ($i -lt 3 -or $i % 10 -eq 0) { "  t+{0,2}s  key rc={1}" -f $i, $r.ReturnValue }
        } catch {
            if ($i % 10 -eq 0) { "  t+{0,2}s  key err {1}" -f $i, $_.Exception.Message }
        }
        $now = (Get-Item $vhd).Length
        if ($now -gt ($before + 100MB)) {
            "  disk growing: " + [math]::Round($now / 1MB, 0) + " MB"
            break
        }
    }
    $after = (Get-Item $vhd).Length
    "vhd now    : " + [math]::Round($after / 1MB, 1) + " MB"
    if ($after -gt ($before + 100MB)) { "INSTALL RUNNING"; break }
    "no growth, retrying"
    Stop-VM -Name $name -TurnOff -Force
    Start-Sleep -Seconds 5
}

"state      : " + (Get-VM -Name $name).State
