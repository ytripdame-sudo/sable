$ErrorActionPreference = 'Continue'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)
Invoke-Command -VMName SABLE-CLEAN -Credential $cred -FilePath C:\sablevm\guest_diag.ps1 |
    ForEach-Object { '  ' + $_ }
