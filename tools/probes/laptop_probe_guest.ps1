$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$name = 'SABLE-CLEAN'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

"heartbeat : " + (Get-VM -Name $name).Heartbeat
"probing powershell direct ..."
try {
    $r = Invoke-Command -VMName $name -Credential $cred -ErrorAction Stop -ScriptBlock {
        $os = Get-CimInstance Win32_OperatingSystem
        [pscustomobject]@{
            host      = $ENV:COMPUTERNAME
            user      = "$ENV:USERDOMAIN\$ENV:USERNAME"
            caption   = $os.Caption
            build     = $os.BuildNumber
            version   = $os.Version
            installed = $os.InstallDate
            uptime    = ((Get-Date) - $os.LastBootUpTime).ToString()
            ready     = Test-Path 'C:\bench\ready.txt'
            ip        = ((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' }).IPAddress -join ', ')
            gateway   = ((Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop -join ', ')
        }
    }
    $r | Format-List
} catch {
    "PROBE FAILED: " + $_.Exception.Message
    exit 1
}
