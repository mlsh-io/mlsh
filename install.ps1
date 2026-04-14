#Requires -Version 5.1
<#
.SYNOPSIS
    mlsh installer for Windows — downloads and runs the Inno Setup installer.
    Usage: irm https://get.mlsh.io/install.ps1 | iex
#>

$ErrorActionPreference = 'Stop'
$repo = 'mlsh-io/mlsh'

Write-Host "`n  mlsh installer for Windows`n" -ForegroundColor Cyan

# Fetch latest release
Write-Host "  Fetching latest release ..." -ForegroundColor Gray
$release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" `
    -Headers @{ 'User-Agent' = 'mlsh-installer' }
$tag = $release.tag_name
Write-Host "  Latest version: $tag" -ForegroundColor Green

# Find the setup exe
$asset = $release.assets | Where-Object { $_.name -match 'windows.*setup\.exe$' }
if (-not $asset) {
    Write-Host "  ERROR: Windows installer not found in release $tag" -ForegroundColor Red
    Write-Host "  You can download the zip manually from: https://github.com/$repo/releases/tag/$tag" -ForegroundColor Yellow
    exit 1
}

# Download
$tmpDir = Join-Path $env:TEMP "mlsh-install-$(Get-Random)"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$exePath = Join-Path $tmpDir $asset.name

Write-Host "  Downloading $($asset.name) ..." -ForegroundColor Gray
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $exePath -UseBasicParsing

# Run installer
Write-Host "  Launching installer ...`n" -ForegroundColor Gray
Start-Process -FilePath $exePath -Wait

# Cleanup
Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue

Write-Host "  Done! Restart your terminal, then run: mlsh --help`n" -ForegroundColor Green
