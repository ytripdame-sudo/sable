$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$hex = (Get-Content 'C:\abe_test\out.hex' -Raw).Trim()
$plain = [byte[]]::new($hex.Length / 2)
for ($i = 0; $i -lt $plain.Length; $i++) { $plain[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
if ($plain.Length -gt 5 -and [Text.Encoding]::ASCII.GetString($plain[0..4]) -eq 'DPAPI') { $blob = $plain[5..($plain.Length - 1)] } else { $blob = $plain }
"blob  : $($blob.Length) bytes"
try {
    $key = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    "LEN   : " + $key.Length
    "KEY   : " + (($key | ForEach-Object { $_.ToString('x2') }) -join '')
} catch {
    "FAIL  : " + $_.Exception.Message
}
