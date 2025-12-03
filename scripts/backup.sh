#!/bin/bash
# backup.sh - Backup models and data

BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"

echo "Creating backup in $BACKUP_DIR..."

mkdir -p "$BACKUP_DIR"

# Backup models
if [ -d "models" ]; then
    cp -r models "$BACKUP_DIR/"
    echo "✓ Models backed up"
fi

# Backup configuration
if [ -f "config.yaml" ]; then
    cp config.yaml "$BACKUP_DIR/"
    echo "✓ Configuration backed up"
fi

# Backup databases
if command -v docker-compose &> /dev/null; then
    docker-compose exec -T mongodb mongodump --archive > "$BACKUP_DIR/mongodb_dump.archive"
    echo "✓ MongoDB backed up"
fi

# Create archive
tar -czf "$BACKUP_DIR.tar.gz" -C backups "$(basename $BACKUP_DIR)"
rm -rf "$BACKUP_DIR"

echo "✓ Backup complete: $BACKUP_DIR.tar.gz"
