#Requires -RunAsAdministrator
# Removes a manual install (install-server.ps1). Setup program installs are removed from Settings > Apps.
# -RemoveData also deletes users, keys and certificates in %ProgramData%\SecureVNC.
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'SecureVNC\Server'),
    [switch]$RemoveData
)
$ErrorActionPreference = 'Stop'
$configure = Join-Path $InstallDir 'configure-server.ps1'
if (-not (Test-Path $configure)) { $configure = Join-Path $PSScriptRoot 'configure-server.ps1' }
& $configure -Remove

Start-Sleep -Milliseconds 500
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
if ($RemoveData) { Remove-Item (Join-Path $env:ProgramData 'SecureVNC') -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'SecureVNC Server removed.'
