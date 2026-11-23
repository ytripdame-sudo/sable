try { Stop-VM -Name SABLE-CLEAN -TurnOff -Force -ErrorAction Stop } catch { "stop err: " + $_.Exception.Message }
Start-Sleep -Seconds 6
$vm = Get-VM -Name SABLE-CLEAN
"state     : " + $vm.State
"snapshot  : " + ((Get-VMSnapshot -VMName SABLE-CLEAN).Name -join ", ")
"mem free  : " + [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1MB,1) + " GB"
