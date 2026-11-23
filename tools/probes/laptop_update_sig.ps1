$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$name = 'SABLE-CLEAN'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

Invoke-Command -VMName $name -Credential $cred -ErrorAction Stop -ScriptBlock {
    $ProgressPreference = "SilentlyContinue"

    Write-Output "=== internet reachability ==="
    $out = & curl.exe -s -m 20 -o NUL -w "%{http_code}" http://www.msftconnecttest.com/connecttest.txt
    "  connecttest http : $out"
    $out2 = & curl.exe -s -m 20 http://www.msftconnecttest.com/connecttest.txt
    "  body             : $out2"

    Write-Output "=== before ==="
    $s = Get-MpComputerStatus
    "  sig  : " + $s.AntivirusSignatureVersion + "  " + $s.AntivirusSignatureLastUpdated
    "  plat : " + $s.AMProductVersion

    Write-Output "=== updating signatures ==="
    try {
        $u = Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop
        "  returned: $u"
    } catch {
        "  FAILED  : " + $_.Exception.Message
        try {
            $u2 = Update-MpSignature -ErrorAction Stop
            "  retry ok: $u2"
        } catch {
            "  retry   : " + $_.Exception.Message
        }
    }

    Write-Output "=== after ==="
    Start-Sleep -Seconds 3
    $s2 = Get-MpComputerStatus
    "  sig     : " + $s2.AntivirusSignatureVersion
    "  updated : " + $s2.AntivirusSignatureLastUpdated
    "  plat    : " + $s2.AMProductVersion
    "  engine  : " + $s2.AMEngineVersion
    "  realtime: " + $s2.RealTimeProtectionEnabled
}
