#!/bin/bash
set -e
echo "Deploying NetWatch to /opt/netwatch..."
sudo rsync -av \
  --exclude='.git' \
  --exclude='data/connections.db' \
  --exclude='data/connections.db-wal' \
  --exclude='data/connections.db-shm' \
  --exclude='data/GeoLite2-Country.mmdb' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  /home/cm/netwatch/ /opt/netwatch/
sudo chown -R root:root /opt/netwatch
sudo chown -R cm:cm /opt/netwatch/data
echo "Done. Run with: netwatch"
