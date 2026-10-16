$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$file = 'messenger-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.dump'
docker compose exec -T db pg_dump -U messenger -d messenger -Fc -f /backups/$file
if ($LASTEXITCODE -ne 0) { throw 'Backup failed' }
Write-Host "Backup saved: backups/$file"
