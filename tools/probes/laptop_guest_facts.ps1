$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$name = 'SABLE-CLEAN'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

Invoke-Command -VMName $name -Credential $cred -ErrorAction Stop -ScriptBlock {
    Write-Output "=== defender ==="
    $s = Get-MpComputerStatus
    "realtime        : " + $s.RealTimeProtectionEnabled
    "antivirus on    : " + $s.AntivirusEnabled
    "sig version     : " + $s.AntivirusSignatureVersion
    "sig updated     : " + $s.AntivirusSignatureLastUpdated
    "engine          : " + $s.AMEngineVersion
    "platform        : " + $s.AMProductVersion
    "tamper protect  : " + $s.IsTamperProtected
    "exclusions      : " + (((Get-MpPreference).ExclusionPath) -join ';')

    Write-Output "=== network ==="
    Get-NetIPConfiguration | ForEach-Object {
        "  {0}  mac={1}" -f $_.InterfaceAlias, $_.NetAdapter.MacAddress
        if ($_.IPv4Address) { "    ip  " + ($_.IPv4Address.IPAddress -join ', ') + "  gw " + ($_.IPv4DefaultGateway.NextHop -join ', ') }
    }
    "  route to 192.168.1.151: " + ((Find-NetRoute -RemoteIPAddress '192.168.1.151' -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress -join ', ')

    Write-Output "=== reach desktop ==="
    $t = Test-NetConnection -ComputerName '192.168.1.151' -Port 8099 -WarningAction SilentlyContinue
    "  tcp 8099 : " + $t.TcpTestSucceeded
    try {
        $r = Invoke-WebRequest -Uri 'http://192.168.1.151:8099/' -UseBasicParsing -TimeoutSec 15
        "  http     : " + $r.StatusCode + "  " + $r.Content
    } catch {
        "  http     : FAIL " + $_.Exception.Message
    }

    Write-Output "=== internet ==="
    try { $o = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 15; "  connect  : " + $o.Content.Trim() } catch { "  connect  : FAIL " + $_.Exception.Message }

    Write-Output "=== bench dir ==="
    "  ready.txt: " + (Test-Path 'C:\bench\ready.txt')
    "  temp     : " + $env:TEMP
    "  free C:  : " + [math]::Round((Get-PSDrive C).Free / 1GB, 1) + " GB"
}
