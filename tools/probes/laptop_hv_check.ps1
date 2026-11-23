$ErrorActionPreference = "SilentlyContinue"
$cs = Get-CimInstance Win32_ComputerSystem
"hypervisor    : " + $cs.HypervisorPresent
"vmms          : " + (Get-Service vmms).Status
"vmcompute     : " + (Get-Service vmcompute).Status
"new-vm cmdlet : " + (Get-Command New-VM).Name
"hyperv module : " + ((Get-Module -ListAvailable Hyper-V).Version -join ', ')

Write-Output "=== switches ==="
Get-VMSwitch | ForEach-Object { "  {0}  type={1}" -f $_.Name, $_.SwitchType }

Write-Output "=== host ram ==="
"total GB      : " + [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
$os = Get-CimInstance Win32_OperatingSystem
"free GB       : " + [math]::Round($os.FreePhysicalMemory / 1MB, 1)
"disk C free   : " + [math]::Round((Get-PSDrive C).Free / 1GB, 1) + " GB"
"cores/logical : {0}/{1}" -f (Get-CimInstance Win32_Processor).NumberOfCores, (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors
