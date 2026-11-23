$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$name = 'SABLE-CLEAN'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

$vm = Get-VM -Name $name
if ($vm.State -ne 'Running') { Start-VM -Name $name | Out-Null }
$deadline = (Get-Date).AddMinutes(6)
while ((Get-Date) -lt $deadline) {
    if ((Get-VMIntegrationService -VMName $name -Name 'Heartbeat').PrimaryStatusDescription -like 'Ok*') { break }
    Start-Sleep -Seconds 5
}
'heartbeat  ' + (Get-VMIntegrationService -VMName $name -Name 'Heartbeat').PrimaryStatusDescription

'--- wipe guest staging ---'
Invoke-Command -VMName $name -Credential $cred -ScriptBlock {
    foreach ($p in 'C:\guest', 'C:\Users\bench\AppData\Local\Google') {
        if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
    foreach ($q in @(Get-ChildItem $env:TEMP -Directory -Filter 'sable-*' -ErrorAction SilentlyContinue)) {
        Remove-Item $q.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    'guest staging cleared'
}

'--- prep ---'
Invoke-Command -VMName $name -Credential $cred -FilePath C:\sablevm\guest_prep.ps1 |
    ForEach-Object { '  ' + $_ }

'--- run ---'
$job = Start-Job -ScriptBlock {
    param($name, $plain)
    $sec = ConvertTo-SecureString $plain -AsPlainText -Force
    $c = New-Object System.Management.Automation.PSCredential('bench', $sec)
    Invoke-Command -VMName $name -Credential $c -FilePath C:\sablevm\guest_run.ps1
} -ArgumentList $name, 'Sable!Clean2026'

# Console frames while the dialog is up. The guest reports the window title and its
# span as well, so the pixels are a second opinion rather than the only evidence.
$shots = @()
foreach ($i in 1..8) {
    Start-Sleep -Seconds 3
    try {
        & C:\sablevm\shot.ps1 -Out ("C:\sablevm\rt-{0}.png" -f $i) | Out-Null
        $shots += "rt-$i.png"
    } catch {
        $shots += "rt-$i failed: " + $_.Exception.Message
    }
}
'shots      ' + ($shots -join ' ')

'--- results ---'
Receive-Job -Job $job -Wait -AutoRemoveJob | ForEach-Object { '  ' + $_ }
