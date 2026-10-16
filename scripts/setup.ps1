$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (!(Test-Path '.env')) {
    function New-Secret { $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); return ([BitConverter]::ToString($b)).Replace('-','').ToLower() }
    $config = @("DB_PASSWORD=$(New-Secret)", "JWT_SECRET=$(New-Secret)", "ADMIN_PASSWORD=StudyAdmin2026")
    [IO.File]::WriteAllLines((Join-Path (Get-Location) '.env'), $config)
}
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { throw 'Docker startup failed' }
Write-Host 'Open https://localhost:8443 ; admin / StudyAdmin2026 (first setup only)'
