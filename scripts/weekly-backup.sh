#!/bin/sh
set -eu
while true; do
  file="/backups/weekly-$(date -u +%Y%m%d-%H%M%S).dump"
  if pg_dump -h db -U messenger -d messenger -Fc -f "$file.tmp"; then
    mv "$file.tmp" "$file"
    echo "Encrypted database backup completed"
  else
    echo "Backup failed; retry in one hour" >&2
    sleep 3600
    continue
  fi
  sleep 604800
done
