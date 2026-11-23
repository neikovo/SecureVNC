#Requires -RunAsAdministrator
# Manual install without the setup program (the setup program, SecureVNC-Setup.exe, is the easy way).
# Run from the published Server folder, as administrator.
param(
    [int]$Port = 0,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'SecureVNC\Server')
)
$ErrorActionPreference = 'Stop'

if (Get-Service SecureVNC -ErrorAction SilentlyContinue) { Stop-Service SecureVNC -Force -ErrorAction SilentlyContinue }
Get-Process SecureVNC.Server -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

New-Item -ItemType Directory -Force $InstallDir | Out-Null
Copy-Item (Join-Path $PSScriptRoot '*') $InstallDir -Recurse -Force -Exclude 'install-server.ps1', 'uninstall-server.ps1'

& (Join-Path $InstallDir 'configure-server.ps1') -Port $Port
Write-Host "`nInstalled in $InstallDir."
& (Join-Path $InstallDir 'SecureVNC.Manager.exe') --first-run
