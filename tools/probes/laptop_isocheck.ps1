$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$iso = 'C:\sablevm\win10.iso'

$img = Mount-DiskImage -ImagePath $iso -PassThru
Start-Sleep -Seconds 2
$vol = $img | Get-Volume
$drive = $vol.DriveLetter
"mounted at : $drive`:"
"label      : " + $vol.FileSystemLabel + "  " + $vol.FileSystem

$root = "${drive}:\"
"root items : " + ((Get-ChildItem $root).Name -join ', ')

foreach ($p in @('sources\boot.wim', 'sources\install.wim', 'bootmgr.efi', 'efi\boot\bootx64.efi', 'efi\microsoft\boot\bootmgfw.efi')) {
    $f = Join-Path $root $p
    if (Test-Path $f) {
        $i = Get-Item $f
        "  {0,-34} {1,12:N0} bytes" -f $p, $i.Length
    } else {
        "  {0,-34} MISSING" -f $p
    }
}

# boot.wim header: 'MSWIM' magic at offset 0
$bw = Join-Path $root 'sources\boot.wim'
if (Test-Path $bw) {
    $fs = [IO.File]::OpenRead($bw)
    $h = New-Object byte[] 8
    [void]$fs.Read($h, 0, 8)
    $fs.Close()
    "boot.wim magic : " + [Text.Encoding]::ASCII.GetString($h, 0, 5) + "  ver " + [BitConverter]::ToUInt32($h, 4)
}

Dismount-DiskImage -ImagePath $iso | Out-Null
"dismounted"
