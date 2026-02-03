#!/bin/bash
# Uninstall CyberPWN systemd service
# Run from project root: sudo bash scripts/uninstall_service.sh

set -e
SERVICE_NAME="cyberpwn.service"
UNIT_PATH="/etc/systemd/system/$SERVICE_NAME"

sudo systemctl stop "$SERVICE_NAME" || true
sudo systemctl disable "$SERVICE_NAME" || true
if [ -f "$UNIT_PATH" ]; then
  sudo rm "$UNIT_PATH"
fi
sudo systemctl daemon-reload
sudo systemctl reset-failed "$SERVICE_NAME" || true

echo "Service $SERVICE_NAME uninstalled."
