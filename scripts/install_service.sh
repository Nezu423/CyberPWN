#!/bin/bash
# Install CyberPWN as a systemd service (always on, restart on crash, start on boot).
# Run from project root: sudo bash scripts/install_service.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVICE_NAME="cyberpwn.service"
UNIT_PATH="/etc/systemd/system/$SERVICE_NAME"

if [ ! -f "$PROJECT_DIR/server.py" ]; then
  echo "Error: server.py not found in $PROJECT_DIR"
  exit 1
fi

PYTHON="$PROJECT_DIR/bruce_env/bin/python"
if [ ! -x "$PYTHON" ]; then
  PYTHON="$(command -v python3 || command -v python)"
  echo "Note: Using $PYTHON (bruce_env not found)"
fi

# Substitute project path; if not using venv, fix ExecStart to use $PYTHON
sed "s|PROJECT_DIR|$PROJECT_DIR|g" "$PROJECT_DIR/cyberpwn.service" | \
  sed "s|$PROJECT_DIR/bruce_env/bin/python|$PYTHON|g" > "/tmp/$SERVICE_NAME"
sudo cp "/tmp/$SERVICE_NAME" "$UNIT_PATH"
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl start "$SERVICE_NAME"
echo "Installed. Status: sudo systemctl status $SERVICE_NAME"
echo "Logs: sudo journalctl -u $SERVICE_NAME -f"
