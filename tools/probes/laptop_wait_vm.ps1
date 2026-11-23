$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$name = 'SABLE-CLEAN'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

"waiting for powershell direct on $name ..."
$ok = $false
for ($i = 1; $i -le 200; $i++) {
    $vm = Get-VM -Name $name
    $state = $vm.State
    $beat  = $vm.Heartbeat
    if ($beat -eq 'Ok') {
        try {
            $r = Invoke-Command -VMName $name -Credential $cred -ScriptBlock {
                [pscustomobject]@{
                    host    = $ENV:COMPUTERNAME
                    user    = "$ENV:USERDOMAIN\$ENV:USERNAME"
                    build   = (Get-CimInstance Win32_OperatingSystem).BuildNumber
                    caption = (Get-CimInstance Win32_OperatingSystem).Caption
                    ready   = Test-Path 'C:\bench\ready.txt'
                    ip      = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' } | Select-Object -First 1).IPAddress
                }
            } -ErrorAction Stop
            $ok = $true
            "reachable after ~" + ($i * 10) + "s"
            $r | ForEach-Object { "  {0,-8} {1}" -f $_.PSObject.Properties.Name, $_.PSObject.Properties.Value }
            break
        } catch {
            $lastErr = $_.Exception.Message
        }
    }
    if ($i % 6 -eq 0) { "  t+{0,3}s  state={1}  heartbeat={2}" -f ($i * 10), $state, $beat }
    Start-Sleep -Seconds 10
}

if (-not $ok) {
    "NOT REACHABLE"
    "state     : " + (Get-VM -Name $name).State
    "heartbeat : " + (Get-VM -Name $name).Heartbeat
    "lasterr   : " + $lastErr
    exit 1
}

Write-Output "=== guest ==="
Invoke-Command -VMName $name -Credential $cred -ScriptBlock {
    $os = Get-CimInstance Win32_OperatingSystem
    "caption   : " + $os.Caption
    "build     : " + $os.BuildNumber + " / " + $os.Version
    "installed : " + $os.InstallDate
    "defender  : " + (Get-MpComputerStatus).RealTimeProtectionEnabled
    "sig ver   : " + (Get-MpComputerStatus).AntivirusSignatureVersion
    "sig date  : " + (Get-MpComputerStatus).AntivirusSignatureLastUpdated
    "net       : " + ((Get-NetAdapter | Where-Object Status -eq 'Up').Name -join ', ')
    "ip        : " + ((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' }).IPAddress -join ', ')
    "gateway   : " + ((Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop -join ', ')
}
