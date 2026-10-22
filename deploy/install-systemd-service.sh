#!/usr/bin/env bash
# Install siem-maintenance.service (systemd, survives reboot).
# Usage:
#   sudo bash deploy/install-systemd-service.sh [/absolute/path/to/Siem-Maintenance] [/path/to/python]
#
# Second argument defaults to REPO_ROOT/.venv/bin/python. When you run without a venv,
# pass the interpreter you used for pip (e.g. /usr/bin/python3).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${1:-"$SCRIPT_DIR/.."}" && pwd)"
PYTHON_BIN="${2:-$REPO_ROOT/.venv/bin/python}"
AGENT_DIR="$REPO_ROOT/Agent-SIEM-maintenance"
UNIT_NAME="siem-maintenance.service"
UNIT_DST="/etc/systemd/system/$UNIT_NAME"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This helper is for Linux systemd only." >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found." >&2
  exit 1
fi
if [[ ! -f "$AGENT_DIR/maintenance_service.py" ]]; then
  echo "Not found: $AGENT_DIR/maintenance_service.py (wrong REPO_ROOT?)" >&2
  exit 1
fi
# Optional second argument: Python interpreter (default: .venv/bin/python)
if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Not found or not executable: $PYTHON_BIN — set up Python deps first." >&2
  exit 1
fi
if [[ "${EUID:-0}" -ne 0 ]]; then
  echo "Run as root: sudo bash $0 $REPO_ROOT" >&2
  exit 1
fi

# Run as the invoking admin user when installed via sudo (not as root).
RUN_USER="${SUDO_USER:-}"
RUN_GROUP=""
if [[ -n "$RUN_USER" && "$RUN_USER" != "root" ]]; then
  RUN_GROUP="$(id -gn "$RUN_USER")"
else
  echo "Warning: no SUDO_USER; service will run as root. Edit $UNIT_DST to set User= and Group=." >&2
fi

TMP_UNIT="$(mktemp)"
trap 'rm -f "$TMP_UNIT"' EXIT

{
  cat <<EOF
[Unit]
Description=SIEM Maintenance scheduler (daily Chat report + Elasticsearch health polls)
Documentation=https://github.com/cylab-africa/Siem-Maintenance-Agent-Monitoring
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$AGENT_DIR
EOF
  if [[ -n "$RUN_USER" && "$RUN_USER" != "root" ]]; then
    echo "User=$RUN_USER"
    echo "Group=$RUN_GROUP"
  fi
  cat <<EOF
ExecStart=$PYTHON_BIN $AGENT_DIR/maintenance_service.py
Restart=on-failure
RestartSec=30
# Loads repo .env then Agent-SIEM-maintenance/.env via maintenance_service.load_env
StandardOutput=journal
StandardError=journal
SyslogIdentifier=siem-maintenance

[Install]
WantedBy=multi-user.target
EOF
} >"$TMP_UNIT"

cp "$TMP_UNIT" "$UNIT_DST"
chmod 0644 "$UNIT_DST"
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
systemctl restart "$UNIT_NAME"
echo "Installed $UNIT_DST and enabled $UNIT_NAME."
systemctl --no-pager --full status "$UNIT_NAME" || true
echo ""
echo "Logs: journalctl -u $UNIT_NAME -f"
echo "Stop:  sudo systemctl stop $UNIT_NAME"
echo "Disable boot: sudo systemctl disable $UNIT_NAME"
