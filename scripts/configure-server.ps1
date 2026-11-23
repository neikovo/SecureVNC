#Requires -RunAsAdministrator
# Sets up (or with -Remove: tears down) SecureVNC Server for the files in THIS folder.
# Used by the setup program and by install-server.ps1; no questions asked, safe to run again.
#  - local CA + server certificate (users are added with SecureVNC Manager)
#  - firewall: the port only from the local subnet
#  - Windows service "SecureVNC" (automatic, restarts on failure)
#  - policy SoftwareSASGeneration so the service may send Ctrl+Alt+Del (original value kept and restored)
param(
    [int]$Port = 0,          # 0 = keep the configured port (5901 on a new install)
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$serviceName = 'SecureVNC'
$ruleName = 'SecureVNC Server'
$data = Join-Path $env:ProgramData 'SecureVNC'
$backup = Join-Path $data 'sas-policy-original.txt'
$policyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

function Stop-SecureVnc {
    if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
    }
    Unregister-ScheduledTask -TaskName 'SecureVNC Server' -Confirm:$false -ErrorAction SilentlyContinue   # phase 1 leftover
    Get-Process SecureVNC.Server -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 500
}

if ($Remove) {
    Stop-SecureVnc
    if (Get-Service $serviceName -ErrorAction SilentlyContinue) { sc.exe delete $serviceName | Out-Null }
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if (Test-Path $backup) {
        $original = (Get-Content $backup -Raw).Trim()
        if ($original -eq 'none') { Remove-ItemProperty $policyKey -Name SoftwareSASGeneration -ErrorAction SilentlyContinue }
        else { Set-ItemProperty $policyKey -Name SoftwareSASGeneration -Value ([int]$original) -Type DWord }
        Remove-Item $backup
    }
    Write-Host 'SecureVNC service, firewall rule and policy removed. Users and certificates are kept in' $data
    exit 0
}

$admin = Join-Path $PSScriptRoot 'SecureVNC.Admin.exe'
$server = Join-Path $PSScriptRoot 'SecureVNC.Server.exe'
$serviceExe = Join-Path $PSScriptRoot 'SecureVNC.Service.exe'

Stop-SecureVnc

# Local CA + certificate (no-op when they already exist).
& $admin init --no-user | Out-Host
if ($LASTEXITCODE) { throw "SecureVNC.Admin init failed ($LASTEXITCODE)" }

$configFile = Join-Path $data 'config.json'
$config = Get-Content $configFile -Raw | ConvertFrom-Json
if ($Port -gt 0 -and $config.port -ne $Port) {
    $config.port = $Port
    $config | ConvertTo-Json -Depth 5 | Set-Content $configFile -Encoding utf8
}
$Port = $config.port

# Firewall: the agent (SecureVNC.Server.exe) listens; only the local subnet may connect.
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port `
    -RemoteAddress LocalSubnet -Program $server -Profile Private, Domain | Out-Null

# Ctrl+Alt+Del from software: 1 = services may generate it, 3 = services + Ease of Access apps.
$current = (Get-ItemProperty $policyKey -Name SoftwareSASGeneration -ErrorAction SilentlyContinue).SoftwareSASGeneration
if (-not (Test-Path $backup)) { Set-Content $backup ($(if ($null -eq $current) { 'none' } else { $current })) }
if ($current -notin 1, 3) {
    $value = if ($current -eq 2) { 3 } else { 1 }
    Set-ItemProperty $policyKey -Name SoftwareSASGeneration -Value $value -Type DWord
    Write-Host "Policy SoftwareSASGeneration set to $value."
}

# Service (re-created so the path always points at this folder).
if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
}
New-Service -Name $serviceName -BinaryPathName "`"$serviceExe`"" -DisplayName 'SecureVNC Server' `
    -Description 'Secure remote desktop for the local network (TLS + Google Authenticator).' -StartupType Automatic | Out-Null
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
Start-Service $serviceName

$public = Get-NetConnectionProfile | Where-Object NetworkCategory -eq 'Public'
if ($public) {
    Write-Warning "Network '$($public.Name -join ', ')' is set to Public: SecureVNC is blocked there. Set it to Private in Windows Settings if this is your home/office LAN."
    exit 10   # the setup program shows this hint
}
Write-Host "SecureVNC service running, port $Port."
exit 0
