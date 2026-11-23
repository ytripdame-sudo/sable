$p = 'C:\sablevm\SABLE-CLEAN.vhdx'
$f = Get-Item $p
"vhdx bytes : " + $f.Length
"vhdx MB    : " + [math]::Round($f.Length / 1MB, 1)
$vm = Get-VM -Name SABLE-CLEAN
"state      : " + $vm.State
"uptime     : " + $vm.Uptime
Write-Output "--- boot order ---"
$fw = Get-VMFirmware -VMName SABLE-CLEAN
$fw.BootOrder | ForEach-Object { "  " + $_.BootType + "  " + $_.Device.Name + "  " + $_.Device.Path }
"secureboot : " + $fw.SecureBoot
Write-Output "--- integration ---"
Get-VMIntegrationService -VMName SABLE-CLEAN | ForEach-Object { "  {0,-22} {1}" -f $_.Name, $_.Enabled }
Write-Output "--- counters ---"
$c = (Get-VM -Name SABLE-CLEAN | Get-VMNetworkAdapter).Statistics
"bytes in   : " + $c.ReceivedBytes
"bytes out  : " + $c.SentBytes
$d = (Get-VM -Name SABLE-CLEAN).UpTime
"now        : " + (Get-Date).ToString('HH:mm:ss')
