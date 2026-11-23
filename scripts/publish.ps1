# Builds self-contained packages (no .NET needed on the target PCs):
#   dist\Server  -> files for the PC that will be controlled (packed by build-installer.ps1, or install-server.ps1)
#   dist\Client  -> SecureVNC.Client.exe, runs from anywhere
param([string]$Out = (Join-Path $PSScriptRoot '..\dist'))
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$Out = [IO.Path]::GetFullPath($Out)
if (Test-Path $Out) { Remove-Item $Out -Recurse -Force }

$common = @('-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '-p:DebugType=none', '--nologo', '-v', 'quiet')
foreach ($project in 'Server', 'Admin', 'Service', 'Manager') {
    dotnet publish "$root\src\SecureVNC.$project" @common -o "$Out\Server"
    if ($LASTEXITCODE) { throw "$project publish failed" }
}
dotnet publish "$root\src\SecureVNC.Client" @common -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o "$Out\Client"
if ($LASTEXITCODE) { throw 'Client publish failed' }

Copy-Item "$PSScriptRoot\configure-server.ps1", "$PSScriptRoot\install-server.ps1", "$PSScriptRoot\uninstall-server.ps1" "$Out\Server"
Write-Host "Done: $Out\Server and $Out\Client"
