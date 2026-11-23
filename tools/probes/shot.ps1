param([string]$Out = 'C:\sablevm\screen.png')

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Drawing

$name = 'SABLE-CLEAN'
$ns = 'root\virtualization\v2'

$vc = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$name'"
$svc = Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
$vsd = Get-CimAssociatedInstance -InputObject $vc -ResultClassName Msvm_VirtualSystemSettingData |
       Where-Object { $_.VirtualSystemIdentifier -eq $vc.Name } | Select-Object -First 1
if (-not $vsd) {
    $vsd = Get-CimAssociatedInstance -InputObject $vc -ResultClassName Msvm_VirtualSystemSettingData |
           Select-Object -First 1
}

$w = 1024
$h = 768
$res = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage -Arguments @{
    TargetSystem = [CimInstance]$vsd
    WidthPixels  = [uint16]$w
    HeightPixels = [uint16]$h
}
if ($res.ReturnValue -ne 0) { throw "thumbnail failed $($res.ReturnValue)" }

$data = $res.ImageData
$bpp = 2
if ($data.Length -ge ($w * $h * 4)) { $bpp = 4 }

$bmp = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$rect = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
$bd = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$stride = $bd.Stride
$buf = New-Object byte[] ($stride * $h)

for ($y = 0; $y -lt $h; $y++) {
    $row = $y * $stride
    $src = $y * $w * $bpp
    for ($x = 0; $x -lt $w; $x++) {
        if ($bpp -eq 2) {
            $v = $data[$src + $x * 2] -bor ($data[$src + $x * 2 + 1] -shl 8)
            $r = [int]((($v -shr 11) -band 0x1F) * 255 / 31)
            $g = [int]((($v -shr 5) -band 0x3F) * 255 / 63)
            $b = [int](($v -band 0x1F) * 255 / 31)
        } else {
            $b = $data[$src + $x * 4 + 0]
            $g = $data[$src + $x * 4 + 1]
            $r = $data[$src + $x * 4 + 2]
        }
        $o = $row + $x * 3
        $buf[$o] = [byte]$b
        $buf[$o + 1] = [byte]$g
        $buf[$o + 2] = [byte]$r
    }
}

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $bd.Scan0, $buf.Length)
$bmp.UnlockBits($bd)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
'saved ' + $Out + ' ' + (Get-Item $Out).Length
