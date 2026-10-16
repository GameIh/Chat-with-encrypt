param([Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]+\.dump$')][string]$BackupFile)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (!(Test-Path -LiteralPath (Join-Path 'backups' $BackupFile))) { throw 'Backup not found' }
docker compose exec -T db pg_restore -l /backups/$BackupFile
if ($LASTEXITCODE -ne 0) { throw 'Invalid backup' }
docker compose stop app
try {
    docker compose exec -T db pg_restore -U messenger -d messenger --clean --if-exists --single-transaction /backups/$BackupFile
    if ($LASTEXITCODE -ne 0) { throw 'Restore failed' }
} finally { docker compose start app }
