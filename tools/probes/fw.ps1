$ErrorActionPreference = 'Stop'
$log = 'C:\Users\Kuzenee\Desktop\55555\_harness\out\fw.txt'
try {
    $existing = Get-NetFirewallRule -DisplayName 'SABLE relay 8099' -ErrorAction SilentlyContinue
    if ($existing) {
        "already present: $($existing.Name)" | Out-File $log -Encoding utf8
    } else {
        $rule = New-NetFirewallRule -DisplayName 'SABLE relay 8099' `
            -Direction Inbound -Action Allow -Protocol TCP `
            -LocalPort 8099 -Profile Private
        "created: $($rule.Name)" | Out-File $log -Encoding utf8
    }
} catch {
    "FAILED: $($_.Exception.Message)" | Out-File $log -Encoding utf8
}
