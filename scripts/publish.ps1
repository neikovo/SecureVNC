# Builds self-contained packages (no .NET needed on the target PCs):
#   dist\Server  -> files for the PC that will be controlled (packed by build-installer.ps1, or install-server.ps1)
#   dist\Auth    -> SecureVNC Auth Server + Auth Console (central administrators, Windows Server)
#   dist\Client  -> SecureVNC.Client.exe, runs from anywhere
#   dist\SecureVNC-Client-Portable.zip -> client for a USB stick, keeps its data next to the exe
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
foreach ($project in 'AuthServer', 'Manager') {
    dotnet publish "$root\src\SecureVNC.$project" @common -o "$Out\Auth"
    if ($LASTEXITCODE) { throw "$project (auth) publish failed" }
}
Copy-Item "$PSScriptRoot\configure-auth.ps1" "$Out\Auth"
dotnet publish "$root\src\SecureVNC.Client" @common -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o "$Out\Client"
if ($LASTEXITCODE) { throw 'Client publish failed' }

# Portable client: the exe plus a SecureVNC-data folder -> trusted servers and settings stay next to it.
$portable = "$Out\SecureVNC-Client-Portable"
New-Item -ItemType Directory -Force "$portable\SecureVNC-data" | Out-Null
Copy-Item "$Out\Client\SecureVNC.Client.exe" $portable
Set-Content "$portable\SecureVNC-data\README.txt" 'SecureVNC Client portable mode: trusted servers and settings are kept in this folder. Keep it next to SecureVNC.Client.exe.' -Encoding utf8
Compress-Archive "$portable\*" "$Out\SecureVNC-Client-Portable.zip" -CompressionLevel Optimal
Remove-Item $portable -Recurse -Force

Copy-Item "$PSScriptRoot\configure-server.ps1", "$PSScriptRoot\install-server.ps1", "$PSScriptRoot\uninstall-server.ps1" "$Out\Server"
Write-Host "Done: $Out\Server and $Out\Client"
