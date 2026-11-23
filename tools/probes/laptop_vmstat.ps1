$vm = Get-VM -Name SABLE-CLEAN
"state     : " + $vm.State
"uptime    : " + $vm.Uptime
"heartbeat : " + $vm.Heartbeat
"vcpus     : " + ((Get-VMProcessor -VMName SABLE-CLEAN).Count)
"mem MB    : " + [math]::Round((Get-VMMemory -VMName SABLE-CLEAN).Startup / 1MB, 0)
$d = Get-Item 'C:\sablevm\SABLE-CLEAN.vhdx' -ErrorAction SilentlyContinue
if ($d) { "vhdx      : " + [math]::Round($d.Length / 1GB, 2) + " GB" }
"host free : " + [math]::Round((Get-PSDrive C).Free / 1GB, 1) + " GB"
"(c) 8GB host, install takes its time"
