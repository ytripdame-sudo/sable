$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

"=== disk ==="
foreach ($d in Get-PSDrive -PSProvider FileSystem) {
    if ($d.Used -ne $null) { "  {0}: free {1,7:N1} GB / total {2,7:N1} GB" -f $d.Name, ($d.Free/1GB), (($d.Used + $d.Free)/1GB) }
}

"=== C:\sablevm ==="
$sv = Get-ChildItem 'C:\sablevm' -File
$tot = ($sv | Measure-Object Length -Sum).Sum
"  total    : " + [math]::Round($tot/1GB,2) + " GB across " + $sv.Count + " files"
$sv | Sort-Object Length -Descending | Select-Object -First 6 | ForEach-Object { "    {0,10:N1} MB  {1}" -f ($_.Length/1MB), $_.Name }

"=== vm ==="
$vm = Get-VM -Name SABLE-CLEAN
"  state    : " + $vm.State
"  snapshot : " + ((Get-VMSnapshot -VMName SABLE-CLEAN).Name -join ', ')
$snapdir = 'C:\sablevm'
Get-ChildItem $snapdir -Filter '*.avhdx' | ForEach-Object { "    avhdx {0,10:N1} MB  {1}" -f ($_.Length/1MB), $_.Name }

"=== hyper-v ==="
"  feature  : " + ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State)
"  hypervpr : " + (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
"  sshd     : " + (Get-Service sshd).Status + " / " + (Get-Service sshd).StartType

"=== leftovers ==="
foreach ($p in @("$env:TEMP\NorthlineSetup.exe", 'C:\abe_test', 'C:\sablevm\autounattend.xml')) {
    if (Test-Path $p) {
        $i = Get-Item $p
        if ($i.PSIsContainer) { "  {0,-46} DIR with {1} files" -f $p, (Get-ChildItem $p -File).Count }
        else { "  {0,-46} {1:N0} bytes" -f $p, $i.Length }
    } else { "  {0,-46} gone" -f $p }
}

"=== scheduled tasks ==="
schtasks /query /fo csv /nh 2>$null | Select-String -Pattern 'SABLE|WinSvcHost|abe' | ForEach-Object { "  " + $_.Line }

"=== hostname ==="
"  " + $env:COMPUTERNAME + "  user " + $env:USERNAME
