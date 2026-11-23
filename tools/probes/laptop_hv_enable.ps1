$ErrorActionPreference = "Stop"
$f = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
"payload state : " + $f.State
$f2 = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell
"mgmt state    : " + $f2.State
if ($f.State -like "Disabled*WithPayloadRemoved*") { "PAYLOAD MISSING - hyper-v cannot be enabled offline"; exit 2 }
"enabling..."
$r = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
"restart needed: " + $r.RestartNeeded
$after = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
"state now     : " + $after.State
