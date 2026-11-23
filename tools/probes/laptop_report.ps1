$ErrorActionPreference = 'Continue'
$pass = ConvertTo-SecureString 'Sable!Clean2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('bench', $pass)

$text = $null
for ($i = 1; $i -le 20; $i++) {
    try {
        $text = Invoke-Command -VMName SABLE-CLEAN -Credential $cred -ScriptBlock {
            $p = 'C:\guest\run.json'
            if (-not (Test-Path $p)) { return $null }
            $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
            $sr = New-Object IO.StreamReader($fs)
            $body = $sr.ReadToEnd()
            $sr.Close(); $fs.Close()
            $body
        } -ErrorAction Stop
        if ($text) { break }
    } catch {
        $text = 'retry ' + $i + ': ' + $_.Exception.Message
    }
    Start-Sleep -Seconds 2
}
$text
