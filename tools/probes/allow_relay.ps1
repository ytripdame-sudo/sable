# Adds one inbound rule so the laptop can reach the local relay on this PC.
# Scoped to the LAN subnet and to port 8099, so it opens nothing else. The rule is
# profile-agnostic because this adapter is classified Public and a Private-only rule
# would never match. Named so it can be removed in one line.
$ErrorActionPreference = 'Stop'
$name = 'Sable local relay 8099'
if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -DisplayName $name -Profile Any -Enabled True
    Write-Output "rule updated to Any profile"
} else {
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 8099 -RemoteAddress 192.168.1.0/24 `
        -Profile Any -Description 'Local relay for a Sable test run' | Out-Null
    Write-Output "rule created"
}
Get-NetFirewallRule -DisplayName $name | Select-Object DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize
