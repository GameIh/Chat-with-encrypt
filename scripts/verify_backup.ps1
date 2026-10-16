$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
docker compose exec -T db pg_dump -U messenger -d messenger -Fc -f /backups/demo.dump
if ($LASTEXITCODE -ne 0) { throw 'Backup failed' }
docker compose exec -T db dropdb -U messenger --if-exists --force messenger_restore_check
docker compose exec -T db createdb -U messenger messenger_restore_check
docker compose exec -T db pg_restore -U messenger -d messenger_restore_check --exit-on-error /backups/demo.dump
if ($LASTEXITCODE -ne 0) { throw 'Restore verification failed' }
docker compose exec -T app python -m scripts.compare_backup
if ($LASTEXITCODE -ne 0) { throw 'Backup content differs' }
