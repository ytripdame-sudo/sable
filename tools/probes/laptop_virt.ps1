$ErrorActionPreference = 'SilentlyContinue'
$cpu = Get-CimInstance Win32_Processor
"cpu          : " + $cpu.Name.Trim()
"cores/logical: {0}/{1}" -f $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors
"vt firmware  : " + $cpu.VirtualizationFirmwareEnabled
"vt monitor   : " + $cpu.VMMonitorModeExtensions
"slat         : " + $cpu.SecondLevelAddressTranslationExtensions

$cs = Get-CimInstance Win32_ComputerSystem
"ram GB       : " + [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
"hypervisor   : " + $cs.HypervisorPresent

"edition      : " + (Get-CimInstance Win32_OperatingSystem).Caption
"build        : " + (Get-CimInstance Win32_OperatingSystem).BuildNumber

foreach ($f in 'Microsoft-Hyper-V-All', 'Microsoft-Hyper-V-Hypervisor', 'Containers-DisposableClientVM', 'VirtualMachinePlatform') {
    $s = Get-WindowsOptionalFeature -Online -FeatureName $f
    "{0,-34} {1}" -f $f, $s.State
}

"disk C free  : " + [math]::Round((Get-PSDrive C).Free / 1GB, 1) + " GB"
"vbox present : " + (Test-Path 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe')
"vmware       : " + (Test-Path 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe')
