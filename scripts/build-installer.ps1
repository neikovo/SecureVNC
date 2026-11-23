# Builds dist\SecureVNC-Setup-<version>.exe (needs Inno Setup 6: https://jrsoftware.org/isinfo.php).
param(
    [string]$Version = '1.0.0',
    [switch]$NoPublish
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')

$iscc = @(
    $env:ISCC,
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "$root\tools\InnoSetup\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 (ISCC.exe) not found. Install it, or set $env:ISCC to ISCC.exe.' }

if (-not $NoPublish) { & "$PSScriptRoot\publish.ps1" }
& $iscc /Q "/DAppVersion=$Version" "$root\installer\SecureVNC.iss"
if ($LASTEXITCODE) { throw "ISCC failed ($LASTEXITCODE)" }
Write-Host "Setup: $root\dist\SecureVNC-Setup-$Version.exe"
