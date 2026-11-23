#Requires -RunAsAdministrator
# Sets up (or with -Remove: tears down) the SecureVNC Auth Server for the files in THIS folder.
#  - organization CA, TLS certificate and join key (first time only)
#  - firewall: port 5902 from private networks
#  - Windows service "SecureVNCAuth" (automatic, restarts on failure)
param([switch]$Remove)
$ErrorActionPreference = 'Stop'
$serviceName = 'SecureVNCAuth'
$ruleName = 'SecureVNC Auth Server'
$exe = Join-Path $PSScriptRoot 'SecureVNC.AuthServer.exe'

if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
}
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) {
    Write-Host "SecureVNC Auth Server service and firewall rule removed. Data is kept in $env:ProgramData\SecureVNC-Auth"
    exit 0
}

& $exe --init | Out-Host
if ($LASTEXITCODE) { throw "SecureVNC.AuthServer --init failed ($LASTEXITCODE)" }

$config = Get-Content (Join-Path $env:ProgramData 'SecureVNC-Auth\auth-config.json') -Raw | ConvertFrom-Json
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $config.port `
    -RemoteAddress 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 -Program $exe | Out-Null

New-Service -Name $serviceName -BinaryPathName "`"$exe`"" -DisplayName 'SecureVNC Auth Server' `
    -Description 'Central SecureVNC administrator accounts: computers ask it to check every login.' -StartupType Automatic | Out-Null
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
Start-Service $serviceName
Write-Host "SecureVNC Auth Server running, port $($config.port)."
exit 0
