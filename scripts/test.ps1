$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
docker compose exec -T db psql -U messenger -d postgres -c 'DROP DATABASE IF EXISTS messenger_test WITH (FORCE);'
docker compose exec -T db psql -U messenger -d postgres -c 'CREATE DATABASE messenger_test;'
docker compose exec -T app sh -c 'DATABASE_URL="${DATABASE_URL%/*}/messenger_test" python -m pytest tests/test_api.py -q -p no:cacheprovider'
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
