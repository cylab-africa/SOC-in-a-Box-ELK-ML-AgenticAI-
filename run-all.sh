#!/usr/bin/env bash
# One entry point: optional install → verify → check APScheduler onsite → start all services.
#   cd /path/to/Siem-Maintenance && bash run-all.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$REPO_ROOT/.venv/bin/python"
AGENT="$REPO_ROOT/Agent-SIEM-maintenance"
PIDS=()

read_yes() {
  local _d="${2:-Y}"
  read -r -p "$1 [Y/n]: " _a
  _a="${_a:-$_d}"
  [[ ! "$_a" =~ ^[Nn] ]]
}

resolve_python() {
  if [[ -x "$VENV_PY" ]]; then
    echo "$VENV_PY"
  elif command -v python3 >/dev/null; then
    echo "python3"
  else
    echo "Install Python 3.10+ or run install.sh (creates .venv)." >&2
    exit 1
  fi
}

cleanup() {
  echo ""
  echo "Shutting down background services..."
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  echo "All services stopped."
}
trap cleanup EXIT INT TERM

echo ""
echo "=== SIEM-Maintenance — setup + scheduler ==="
echo "Repository: $REPO_ROOT"
echo ""

if read_yes "Run interactive install (env, pip, model presets, verify offer)" "Y"; then
  bash "$REPO_ROOT/install.sh"
fi

PY="$(resolve_python)"
echo ""
echo "--- Environment check ---"
set +e
( cd "$REPO_ROOT" && "$PY" "$REPO_ROOT/verify_setup.py" )
VERIFY_EC=$?
set -e
if [[ "$VERIFY_EC" -ne 0 ]]; then
  echo "verify_setup.py reported issues. Fix .env or network." >&2
  read_yes "Continue anyway to scheduler check" "N" || exit "$VERIFY_EC"
fi

# --- Feedback loop env check ---
echo ""
echo "--- Feedback loop config ---"
_load_env_val() { grep -m1 "^$1=" "$AGENT/.env" 2>/dev/null | cut -d= -f2- | tr -d '"' || true; }

_SA_KEY="$(_load_env_val GOOGLE_CHAT_SA_KEY)"
_SPACE_ID="$(_load_env_val GOOGLE_CHAT_SPACE_ID)"
_SHEET_ID="$(_load_env_val FEEDBACK_SHEET_ID)"
_WEBHOOK="$(_load_env_val GC_ALERT_WEBHOOK)"

FEEDBACK_OK=true

# Auto-detect GOOGLE_CHAT_SPACE_ID from webhook URL if missing
if [[ -z "$_SPACE_ID" && -n "$_WEBHOOK" ]]; then
  _detected="$(echo "$_WEBHOOK" | grep -oP 'spaces/[^/]+' || true)"
  if [[ -n "$_detected" ]]; then
    echo "GOOGLE_CHAT_SPACE_ID not set but webhook URL found."
    echo "  Detected space: $_detected"
    if read_yes "Add GOOGLE_CHAT_SPACE_ID=$_detected to .env" "Y"; then
      # Append to both .env files
      for _ef in "$REPO_ROOT/.env" "$AGENT/.env"; do
        if [[ -f "$_ef" ]] && ! grep -q "^GOOGLE_CHAT_SPACE_ID=" "$_ef"; then
          echo "GOOGLE_CHAT_SPACE_ID=$_detected" >> "$_ef"
        fi
      done
      _SPACE_ID="$_detected"
      echo "  Added GOOGLE_CHAT_SPACE_ID=$_detected"
    fi
  fi
fi

if [[ -z "$_SPACE_ID" ]]; then
  echo "WARNING: GOOGLE_CHAT_SPACE_ID not set — interactive feedback buttons will not work."
  echo "  Fix: add GOOGLE_CHAT_SPACE_ID=spaces/<YOUR_SPACE> to $AGENT/.env"
  FEEDBACK_OK=false
fi
if [[ -z "$_SA_KEY" || ! -f "${_SA_KEY:-/nonexistent}" ]]; then
  echo "WARNING: GOOGLE_CHAT_SA_KEY missing or file not found — Chat App mode unavailable."
  FEEDBACK_OK=false
fi
if [[ -z "$_SHEET_ID" ]]; then
  echo "WARNING: FEEDBACK_SHEET_ID not set — feedback poller will not work."
  FEEDBACK_OK=false
fi
if [[ "$FEEDBACK_OK" == "true" ]]; then
  echo "OK: Feedback loop config looks good (space=$_SPACE_ID, sheet=$_SHEET_ID)"
fi

echo ""
echo "--- Onsite scheduler (APScheduler + maintenance_service) ---"
"$PY" -c "
import sys
sys.path.insert(0, r'$AGENT')
import maintenance_service
from apscheduler.schedulers.background import BackgroundScheduler
print('OK: maintenance_service.py loads; APScheduler (BackgroundScheduler) is installed.')
"

echo ""
if read_yes "Start all services now (scheduler + feedback poller + feedback server)" "Y"; then
  # Start feedback poller in background
  if [[ -n "$_SHEET_ID" ]]; then
    echo "Starting feedback_poller.py (background, polling every 60s)"
    (cd "$AGENT" && "$PY" "$AGENT/feedback_poller.py" --loop 60) &
    PIDS+=($!)
  else
    echo "Skipping feedback poller (FEEDBACK_SHEET_ID not set)"
  fi

  # Start maintenance scheduler (foreground) with feedback server
  echo "Starting maintenance_service.py --start-feedback-server (Ctrl+C to stop all)"
  (cd "$AGENT" && exec "$PY" "$AGENT/maintenance_service.py" --start-feedback-server)
else
  echo "Later run:"
  echo "  cd $AGENT && $PY maintenance_service.py --start-feedback-server"
  echo "  cd $AGENT && $PY feedback_poller.py --loop 60"
fi
