$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

$name = 'SABLE-CLEAN'
if ((Get-VM -Name $name).State -ne 'Running') { Start-VM -Name $name | Out-Null }
$deadline = (Get-Date).AddMinutes(6)
while ((Get-Date) -lt $deadline) {
    if ((Get-VMIntegrationService -VMName $name -Name 'Heartbeat').PrimaryStatusDescription -like 'Ok*') { break }
    Start-Sleep -Seconds 5
}

'--- prep ---'
Invoke-Command -VMName $name -Credential $cred -FilePath C:\sablevm\guest_prep.ps1 |
    ForEach-Object { '  ' + $_ }

'--- probe ---'
Invoke-Command -VMName $name -Credential $cred -FilePath C:\sablevm\guest_probe_run.ps1 |
    ForEach-Object { '  ' + $_ }
