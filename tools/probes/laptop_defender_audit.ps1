$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$name = 'SABLE-CLEAN'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

Invoke-Command -VMName $name -Credential $cred -ErrorAction Stop -ScriptBlock {
    $ProgressPreference = "SilentlyContinue"
    $log = 'Microsoft-Windows-Windows Defender/Operational'
    $all = Get-WinEvent -LogName $log -MaxEvents 400 -ErrorAction SilentlyContinue
    "events total      : " + @($all).Count

    $ids = @{}
    foreach ($e in $all) { $ids[$e.Id] = 1 + ($ids[$e.Id] -as [int]) }
    "distinct ids      : " + (($ids.Keys | Sort-Object) -join ', ')

    Write-Output "=== last 12 ==="
    $all | Select-Object -First 12 | ForEach-Object {
        "  {0}  id={1,-5} {2}" -f $_.TimeCreated.ToString('HH:mm:ss'), $_.Id, $_.ProviderName
    }

    Write-Output "=== scan activity today ==="
    $since = (Get-Date).Date
    $today = $all | Where-Object { $_.TimeCreated -ge $since }
    "  events today    : " + @($today).Count
    "  ids today       : " + ((@($today) | ForEach-Object { $_.Id }) -join ', ')

    Write-Output "=== detection verdicts ==="
    "  MpThreatDetection : " + @(Get-MpThreatDetection).Count
    "  MpThreat          : " + @(Get-MpThreat).Count
    "  MpStatus          : " + (Get-MpComputerStatus).RealTimeProtectionEnabled
    "  last quick scan   : " + (Get-MpComputerStatus).QuickScanStartTime
    "  last full scan    : " + (Get-MpComputerStatus).FullScanStartTime

    Write-Output "=== asr / tamper ==="
    $p = Get-MpPreference
    "  asr rules         : " + (@($p.AttackSurfaceReductionRules_Ids).Count)
    "  cloud block level : " + $p.CloudBlockLevel
    "  submit samples    : " + $p.SubmitSamplesConsent
    "  map reports       : " + (Get-MpComputerStatus).MAPSReporting
}
