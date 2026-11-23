$ErrorActionPreference = 'Continue'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

foreach ($name in 'decoy.png', 'decoy2.png') {
    $b64 = Invoke-Command -VMName SABLE-CLEAN -Credential $cred -ArgumentList $name -ScriptBlock {
        param($n)
        $p = "C:\guest\$n"
        if (-not (Test-Path $p)) { return 'MISSING' }
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($p))
    }
    if ($b64 -eq 'MISSING' -or -not $b64) {
        'missing ' + $name
        continue
    }
    $bytes = [Convert]::FromBase64String($b64)
    [IO.File]::WriteAllBytes("C:\sablevm\$name", $bytes)
    'pulled  ' + $name + '  ' + $bytes.Length + ' B'
}
