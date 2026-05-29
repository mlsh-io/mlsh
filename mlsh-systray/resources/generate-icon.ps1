# Generates resources/app.ico (multi-resolution) with the MLSH hexagonal-cube
# logo, used as the embedded executable icon and the installer icon.
#
# The runtime tray/window icons are painted by IconFactory (QPainter); this
# static .ico is only for Explorer, shortcuts and the taskbar. Re-run after
# changing the logo:  pwsh -File resources/generate-icon.ps1
#
# 3-tone gray faces + dark outline read on both light and dark backgrounds.

Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = 'Stop'
$outIco = Join-Path $PSScriptRoot 'app.ico'
$sizes = 16, 24, 32, 48, 64, 128, 256

function New-LogoPng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    # Map the 256-unit design space into the bitmap with small padding.
    $pad = $size * 0.06
    $scale = ($size - 2 * $pad) / 256.0
    $g.TranslateTransform($pad, $pad)
    $g.ScaleTransform($scale, $scale)

    function P($x, $y) { New-Object System.Drawing.PointF($x, $y) }
    function Poly($pts) { $arr = [System.Drawing.PointF[]]$pts; return $arr }

    $top = Poly @((P 128 39), (P 52 83), (P 128 127), (P 204 83))
    $left = Poly @((P 52 83), (P 52 171), (P 128 215), (P 128 127))
    $right = Poly @((P 204 83), (P 128 127), (P 128 215), (P 204 171))
    $hex = Poly @((P 128 7), (P 24 67), (P 24 187), (P 128 247), (P 232 187), (P 232 67))
    $diamond = Poly @((P 128 39), (P 52 83), (P 128 127), (P 204 83))

    $bTop = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 200, 200, 204))
    $bLeft = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 142, 142, 147))
    $bRight = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 99, 99, 102))
    $g.FillPolygon($bTop, $top)
    $g.FillPolygon($bLeft, $left)
    $g.FillPolygon($bRight, $right)

    $ink = [System.Drawing.Color]::FromArgb(255, 29, 29, 31)
    $penOuter = New-Object System.Drawing.Pen ($ink, 12)
    $penOuter.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $penOuter.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $penOuter.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $g.DrawPolygon($penOuter, $hex)

    $penInner = New-Object System.Drawing.Pen ($ink, 8)
    $penInner.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $penInner.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $penInner.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $g.DrawPolygon($penInner, $diamond)
    $g.DrawLine($penInner, (P 128 127), (P 128 215))
    $g.DrawLine($penInner, (P 52 83), (P 52 171))
    $g.DrawLine($penInner, (P 204 83), (P 204 171))

    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return , $ms.ToArray()
}

# Assemble an ICO with PNG-compressed frames (Vista+).
$frames = foreach ($s in $sizes) { , (New-LogoPng $s) }

$fs = [System.IO.File]::Create($outIco)
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([uint16]0)            # reserved
$bw.Write([uint16]1)            # type = icon
$bw.Write([uint16]$sizes.Count) # image count

$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $png = $frames[$i]
    $bw.Write([byte]($(if ($s -ge 256) { 0 } else { $s }))) # width  (0 => 256)
    $bw.Write([byte]($(if ($s -ge 256) { 0 } else { $s }))) # height (0 => 256)
    $bw.Write([byte]0)   # palette
    $bw.Write([byte]0)   # reserved
    $bw.Write([uint16]1) # planes
    $bw.Write([uint16]32) # bit depth
    $bw.Write([uint32]$png.Length)
    $bw.Write([uint32]$offset)
    $offset += $png.Length
}
foreach ($png in $frames) { $bw.Write($png) }
$bw.Flush(); $bw.Close(); $fs.Close()

Write-Host "Wrote $outIco ($([System.IO.FileInfo]::new($outIco).Length) bytes, $($sizes.Count) sizes)"
