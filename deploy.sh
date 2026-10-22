#!/usr/bin/env bash
# Automated deployment for the Linux anomaly detection pipeline, with optional
# add-ons: the SIEM Maintenance Agent (addons/siem-maintenance) and the Alert
# Triage Agent (addons/alert-triage).
#
# Usage:
#   ./deploy.sh                          interactive; asks about each add-on
#   ./deploy.sh --with-maintenance       detection pipeline + maintenance agent
#   ./deploy.sh --with-triage            detection pipeline + alert triage agent
#   ./deploy.sh --mode docker            run under Docker Compose instead of venv + systemd
#   ES_HOST=... ES_USERNAME=... ES_PASSWORD=... ./deploy.sh --non-interactive --with-maintenance
#   ./deploy.sh --dry-run                print what would happen, change nothing
#
# Run ./deploy.sh --help for every option. See DEPLOYMENT.md for details.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADDON_DIR="$REPO_ROOT/addons/siem-maintenance"
ADDON_AGENT_DIR="$ADDON_DIR/Agent-SIEM-maintenance"
ENV_FILE="$REPO_ROOT/.env"
ADDON_ENV_FILE="$ADDON_DIR/.env"
VENV_DIR="$REPO_ROOT/.venv"
ADDON_VENV_DIR="$ADDON_DIR/.venv"
DETECTION_UNIT="realtime_service.service"
MAINTENANCE_UNIT="siem-maintenance.service"
TRIAGE_DIR="$REPO_ROOT/addons/alert-triage"
TRIAGE_ENV_FILE="$TRIAGE_DIR/.env"
TRIAGE_VENV_DIR="$TRIAGE_DIR/.venv"
TRIAGE_CERT_DIR="$TRIAGE_DIR/certs"
TRIAGE_UNIT="alert-triage.service"
# Version pins for the vendored agent, kept outside the subtree.
TRIAGE_CONSTRAINTS="$REPO_ROOT/addons/alert-triage.constraints.txt"
# System trust stores, in the order distributions ship them.
SYSTEM_CA_BUNDLES=(/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem)
COMPOSE_FILE="$REPO_ROOT/docker/docker-compose.yml"
COMPOSE_EXTERNAL_ES="$REPO_ROOT/docker/docker-compose.external-es.yml"
MIN_PY_MINOR=10

# ── Options ──────────────────────────────────────────────────────────────────
MODE="venv"                 # venv | docker
WITH_MAINTENANCE=""         # "", yes, no  ("" = ask)
WITH_TRIAGE=""              # "", yes, no  ("" = ask)
# The triage agent has no authentication of its own, so it listens on loopback
# unless the operator explicitly chooses otherwise.
TRIAGE_LISTEN="${TRIAGE_LISTEN:-127.0.0.1}"
TRIAGE_PORT="${TRIAGE_PORT:-8000}"
NON_INTERACTIVE=0
DRY_RUN=0
INSTALL_SYSTEMD=1
RECONFIGURE=0
MAINTENANCE_WIZARD=0
LOCAL_ES=0
REPLACE_UNITS=0
EXTRAS=""
INSECURE_TLS="${ES_INSECURE_TLS:-0}"
SERVICE_USER="${SUDO_USER:-$(id -un)}"

usage() {
  cat <<'EOF'
Usage: ./deploy.sh [options]

Components:
  --with-maintenance       Also deploy the SIEM Maintenance Agent add-on
  --no-maintenance         Deploy the detection pipeline only (skip the question)
  --maintenance-wizard     Configure the add-on with its own full installer
                           (addons/siem-maintenance/install.sh: feedback loop,
                           Google Chat app, LLM presets) instead of the short setup here
  --with-triage            Also deploy the Alert Triage Agent add-on (AI-assisted
                           investigation of Elastic Security alerts: web UI, API, MCP)
  --no-triage              Skip the Alert Triage Agent (skip the question)
  --triage-listen ADDR     Address the triage agent listens on (default 127.0.0.1).
                           It has no authentication: anyone who can reach it can read
                           alerts and run investigations. Only widen this behind an
                           authenticating reverse proxy or on a trusted network.
  --triage-port PORT       Triage agent port (default 8000)

Install mode:
  --mode venv|docker       venv = Python venv + systemd units (default)
                           docker = Docker Compose (add-ons run as the "maintenance"
                           and "triage" profiles)
  --local-es               docker mode only: also start the bundled Elasticsearch + Kibana
  --extras LIST            Extra pip groups for detection, e.g. "dl,ops" (torch, mlflow)
  --no-systemd             venv mode: install packages and config but no systemd units
  --service-user USER      User the systemd units run as (default: invoking user)
  --replace-units          Overwrite existing systemd units that point at another checkout

Configuration:
  --insecure-tls           Allow sending ES credentials without TLS certificate
                           verification (lab clusters with self-signed certs only;
                           prefer ES_CA_CERT=/path/to/ca.pem)
  --non-interactive        Never prompt; read values from the environment
                           (ES_HOST, ES_USERNAME, ES_PASSWORD, GC_ALERT_WEBHOOK, ...)
  --reconfigure            Re-ask settings even if .env files already exist

Other:
  --dry-run                Print every action without changing anything
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-maintenance)   WITH_MAINTENANCE="yes" ;;
    --no-maintenance)     WITH_MAINTENANCE="no" ;;
    --maintenance-wizard) MAINTENANCE_WIZARD=1; WITH_MAINTENANCE="yes" ;;
    --with-triage)        WITH_TRIAGE="yes" ;;
    --no-triage)          WITH_TRIAGE="no" ;;
    --triage-listen)      TRIAGE_LISTEN="${2:?--triage-listen needs an address}"; shift ;;
    --triage-listen=*)    TRIAGE_LISTEN="${1#*=}" ;;
    --triage-port)        TRIAGE_PORT="${2:?--triage-port needs a number}"; shift ;;
    --triage-port=*)      TRIAGE_PORT="${1#*=}" ;;
    --mode)               MODE="${2:?--mode needs venv or docker}"; shift ;;
    --mode=*)             MODE="${1#*=}" ;;
    --local-es)           LOCAL_ES=1 ;;
    --extras)             EXTRAS="${2:?--extras needs a list}"; shift ;;
    --extras=*)           EXTRAS="${1#*=}" ;;
    --no-systemd)         INSTALL_SYSTEMD=0 ;;
    --service-user)       SERVICE_USER="${2:?--service-user needs a name}"; shift ;;
    --replace-units)      REPLACE_UNITS=1 ;;
    --non-interactive)    NON_INTERACTIVE=1 ;;
    --reconfigure)        RECONFIGURE=1 ;;
    --insecure-tls)       INSECURE_TLS=1 ;;
    --dry-run)            DRY_RUN=1 ;;
    -h|--help)            usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ "$MODE" != "venv" && "$MODE" != "docker" ]]; then
  echo "--mode must be venv or docker (got: $MODE)" >&2
  exit 2
fi
if ! [[ "$TRIAGE_PORT" =~ ^[0-9]+$ ]] || (( TRIAGE_PORT < 1 || TRIAGE_PORT > 65535 )); then
  echo "--triage-port must be 1-65535 (got: $TRIAGE_PORT)" >&2
  exit 2
fi

# ── Output helpers ───────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_OK=$'\e[32m'; C_FAIL=$'\e[31m'; C_WARN=$'\e[33m'; C_INFO=$'\e[36m'; C_OFF=$'\e[0m'
else
  C_OK=""; C_FAIL=""; C_WARN=""; C_INFO=""; C_OFF=""
fi
ok()   { printf '  [%s OK %s] %s\n' "$C_OK" "$C_OFF" "$*"; }
fail() { printf '  [%sFAIL%s] %s\n' "$C_FAIL" "$C_OFF" "$*" >&2; }
warn() { printf '  [%sWARN%s] %s\n' "$C_WARN" "$C_OFF" "$*"; }
info() { printf '  [%sINFO%s] %s\n' "$C_INFO" "$C_OFF" "$*"; }
step() { printf '\n== %s ==\n' "$*"; }
die()  { fail "$*"; exit 1; }

# Run a command, or only print it under --dry-run.
run() {
  if (( DRY_RUN )); then
    printf '  [DRY ] %s\n' "$*"
  else
    "$@"
  fi
}

# prompt VAR "question" "default"  — uses $VAR from the environment if set.
prompt() {
  local var="$1" msg="$2" def="${3:-}" cur="${!1:-}" reply
  [[ -n "$cur" ]] && def="$cur"
  if (( NON_INTERACTIVE )); then
    printf -v "$var" '%s' "$def"
    return
  fi
  if [[ -n "$def" ]]; then
    read -r -p "  $msg [$def]: " reply
  else
    read -r -p "  $msg: " reply
  fi
  printf -v "$var" '%s' "${reply:-$def}"
}

# prompt_secret VAR "question"  — keeps an existing value when Enter is pressed.
prompt_secret() {
  local var="$1" msg="$2" cur="${!1:-}" reply hint=""
  if (( NON_INTERACTIVE )); then
    return
  fi
  [[ -n "$cur" ]] && hint=" (Enter keeps current)"
  read -r -s -p "  $msg$hint: " reply
  echo
  [[ -n "$reply" ]] && printf -v "$var" '%s' "$reply"
  return 0
}

# confirm "question" default(Y|N)
confirm() {
  local msg="$1" def="${2:-N}" reply
  if (( NON_INTERACTIVE )); then
    [[ "$def" == "Y" ]]
    return
  fi
  if [[ "$def" == "Y" ]]; then
    read -r -p "  $msg (Y/n): " reply; reply="${reply:-Y}"
  else
    read -r -p "  $msg (y/N): " reply; reply="${reply:-N}"
  fi
  [[ "$reply" =~ ^[Yy] ]]
}

require_value() {
  local var="$1"
  [[ -n "${!var:-}" ]] || die "$var is required (set it in the environment for --non-interactive)"
}

# Quote a value for a dotenv file when it contains characters dotenv would split on.
escape_env() {
  local v="$1" special='[[:space:]#"'"'"'$&\\]'
  if [[ "$v" =~ $special ]]; then
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    printf '"%s"' "$v"
  else
    printf '%s' "$v"
  fi
}

# Read KEY's value from a dotenv file (unquoted; first match).
env_get() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || return 0
  awk -v k="$key" '
    index($0, k "=") == 1 {
      v = substr($0, length(k) + 2)
      if (v ~ /^".*"$/) { v = substr(v, 2, length(v) - 2); gsub(/\\"/, "\"", v); gsub(/\\\\/, "\\", v) }
      print v; exit
    }' "$file"
}

# Set KEY=VALUE in a dotenv file, replacing an existing (possibly commented) line.
env_set() {
  local file="$1" key="$2" value
  value="$(escape_env "$3")"
  if (( DRY_RUN )); then
    printf '  [DRY ] set %s in %s\n' "$key" "${file#"$REPO_ROOT"/}"
    return
  fi
  local tmp
  tmp="$(mktemp "$file.XXXXXX")"
  # Value goes through ENVIRON: awk -v would interpret its backslash escapes.
  ENV_SET_VALUE="$value" awk -v k="$key" '
    BEGIN { done = 0; v = ENVIRON["ENV_SET_VALUE"] }
    !done && (index($0, k "=") == 1 || index($0, "#" k "=") == 1) { print k "=" v; done = 1; next }
    { print }
    END { if (!done) print k "=" v }' "$file" >"$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$file"
}

# Load ES_* settings from an existing .env into the shell, without overriding
# anything the caller exported.
load_existing_env() {
  local file="$1" key
  shift
  for key in "$@"; do
    if [[ -z "${!key:-}" ]]; then
      printf -v "$key" '%s' "$(env_get "$file" "$key")"
    fi
  done
}

# Fail fast when a value is still the placeholder from .env.example.
is_placeholder() {
  [[ -z "$1" || "$1" == your-* || "$1" == *your-elasticsearch-host* ]]
}

# ── Preflight ────────────────────────────────────────────────────────────────
preflight() {
  step "Preflight"
  [[ "$(uname -s)" == "Linux" ]] || warn "Not Linux; systemd steps will be skipped"
  if [[ "$(id -u)" -eq 0 && -z "${SUDO_USER:-}" ]]; then
    warn "Running as root. Services will run as root unless you pass --service-user."
  fi

  if [[ "$MODE" == "venv" ]]; then
    command -v python3 >/dev/null || die "python3 not found (need Python 3.$MIN_PY_MINOR+)"
    local minor
    minor="$(python3 -c 'import sys; print(sys.version_info.minor if sys.version_info.major == 3 else 0)')"
    (( minor >= MIN_PY_MINOR )) || die "Python 3.$MIN_PY_MINOR+ required (found 3.$minor)"
    ok "Python $(python3 -c 'import platform; print(platform.python_version())')"
    if ! python3 -c 'import ensurepip, venv' 2>/dev/null; then
      die "python3 venv support missing. On Debian/Ubuntu: sudo apt install -y python3-venv"
    fi
    ok "venv module available"
  else
    if docker compose version >/dev/null 2>&1; then
      ok "$(docker compose version | head -1)"
    elif (( DRY_RUN )); then
      warn "Docker Compose v2 not found (continuing because of --dry-run)"
    else
      die "Docker Compose v2 not found (need docker with the compose plugin)"
    fi
  fi
  command -v curl >/dev/null || die "curl not found"

  if [[ -z "$WITH_MAINTENANCE" ]]; then
    echo
    echo "  Optional add-on: SIEM Maintenance Agent"
    echo "  Watches cluster health and ingestion freshness, sends a daily Google Chat"
    echo "  report, and can run safe auto-remediation."
    if confirm "Deploy the SIEM Maintenance Agent too?" N; then
      WITH_MAINTENANCE="yes"
    else
      WITH_MAINTENANCE="no"
    fi
  fi
  if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
    [[ -f "$ADDON_AGENT_DIR/maintenance_service.py" ]] \
      || die "Add-on not found at $ADDON_DIR (clone the full repository)"
    ok "Maintenance add-on: enabled"
  else
    info "Maintenance add-on: skipped (re-run with --with-maintenance to add it later)"
  fi

  if [[ -z "$WITH_TRIAGE" ]]; then
    echo
    echo "  Optional add-on: Alert Triage Agent"
    echo "  AI-assisted investigation of Elastic Security alerts (web UI, REST API, and"
    echo "  an MCP server), with threat-intel and asset context. Runs on Ollama or Claude."
    if confirm "Deploy the Alert Triage Agent too?" N; then
      WITH_TRIAGE="yes"
    else
      WITH_TRIAGE="no"
    fi
  fi
  if [[ "$WITH_TRIAGE" == "yes" ]]; then
    [[ -f "$TRIAGE_DIR/server.py" ]] || die "Add-on not found at $TRIAGE_DIR (clone the full repository)"
    ok "Triage add-on: enabled (listening on $TRIAGE_LISTEN:$TRIAGE_PORT)"
  else
    info "Triage add-on: skipped (re-run with --with-triage to add it later)"
  fi
}

# ── Elasticsearch connectivity ───────────────────────────────────────────────
# Credentials go to curl on stdin so they never appear in the process list, and
# are only sent over a verified TLS connection unless --insecure-tls is given.
es_check() {
  local host="$1" user="$2" pass="$3" out flags=(-sS --max-time 10)
  if (( DRY_RUN )); then
    printf '  [DRY ] check Elasticsearch at %s\n' "$host"
    return 0
  fi
  if [[ -n "${ES_CA_CERT:-}" ]]; then
    local ca
    ca="$(ca_cert_path)"
    [[ -r "$ca" ]] || { fail "ES_CA_CERT not readable: $ca"; return 1; }
    flags+=(--cacert "$ca")
  fi
  local cfg=""
  [[ -n "$user" ]] && cfg="user = \"${user//\"/\\\"}:${pass//\"/\\\"}\""
  if out="$(printf '%s\n' "$cfg" | curl "${flags[@]}" -K - "$host" 2>&1)" && [[ "$out" == *cluster_name* ]]; then
    ok "Elasticsearch reachable at $host (TLS verified)"
    return 0
  fi
  if (( INSECURE_TLS )); then
    if out="$(printf '%s\n' "$cfg" | curl "${flags[@]}" -k -K - "$host" 2>&1)" && [[ "$out" == *cluster_name* ]]; then
      warn "Elasticsearch reachable at $host with TLS verification disabled (--insecure-tls)"
      return 0
    fi
  elif [[ "$host" == https://* ]]; then
    # Diagnose a certificate problem without sending credentials.
    local code
    code="$(curl -sS --max-time 10 -k -o /dev/null -w '%{http_code}' "$host" 2>/dev/null || true)"
    if [[ -n "$code" && "$code" != "000" ]]; then
      fail "Elasticsearch at $host answers, but its TLS certificate is not trusted"
      info "Set ES_CA_CERT=/path/to/ca.pem, or pass --insecure-tls for a lab cluster"
      return 1
    fi
  fi
  fail "Could not reach Elasticsearch at $host: ${out:0:200}"
  return 1
}

# ES_CA_CERT as an absolute path; relative paths are relative to the repo root,
# which is the working directory of the detection service and container.
ca_cert_path() {
  if [[ "$ES_CA_CERT" == /* ]]; then
    printf '%s' "$ES_CA_CERT"
  else
    printf '%s' "$REPO_ROOT/$ES_CA_CERT"
  fi
}

is_false() {
  [[ "${1,,}" =~ ^(0|false|no|off)$ ]]
}

# Reconcile TLS settings from flags, environment and .env, and persist them so
# the pipeline verifies exactly as this script's connectivity check did.
apply_tls_settings() {
  load_existing_env "$ENV_FILE" ES_CA_CERT ES_VERIFY_CERTS
  if (( LOCAL_ES )) && (( ! INSECURE_TLS )); then
    info "Bundled Elasticsearch uses an auto-generated self-signed certificate; disabling verification"
    INSECURE_TLS=1
  fi
  is_false "${ES_VERIFY_CERTS:-true}" && INSECURE_TLS=1
  if (( INSECURE_TLS )); then
    ES_VERIFY_CERTS="false"
    [[ "$(env_get "$ENV_FILE" ES_VERIFY_CERTS)" == "false" ]] || env_set "$ENV_FILE" ES_VERIFY_CERTS false
    warn "TLS verification disabled for the pipeline (ES_VERIFY_CERTS=false); lab use only"
  else
    ES_VERIFY_CERTS="true"
  fi
  if [[ -n "${ES_CA_CERT:-}" ]]; then
    [[ "$(env_get "$ENV_FILE" ES_CA_CERT)" == "$ES_CA_CERT" ]] || env_set "$ENV_FILE" ES_CA_CERT "$ES_CA_CERT"
    if [[ "$MODE" == "docker" && "$(ca_cert_path)" != "$REPO_ROOT/config/"* ]]; then
      warn "ES_CA_CERT is outside config/, so the container cannot see it. Use config/certs/ca.pem."
    fi
  fi
}

# ── Detection pipeline configuration ─────────────────────────────────────────
configure_detection() {
  step "Detection pipeline configuration (.env)"
  if [[ -f "$ENV_FILE" && $RECONFIGURE -eq 0 ]]; then
    load_existing_env "$ENV_FILE" ES_HOST ES_USERNAME ES_PASSWORD \
      ES_PROCESS_INDEX ES_NETWORK_INDEX ES_DISCOVERY_INDEX
    if ! is_placeholder "${ES_HOST:-}"; then
      ok "Using existing .env (pass --reconfigure to change it)"
      apply_tls_settings
      es_check "$ES_HOST" "${ES_USERNAME:-}" "${ES_PASSWORD:-}" \
        || warn "Continuing; fix ES settings in .env before starting the services"
      return
    fi
    info ".env still has placeholder values; asking for them now"
  fi

  if [[ ! -f "$ENV_FILE" ]]; then
    run cp "$REPO_ROOT/.env.example" "$ENV_FILE"
    run chmod 600 "$ENV_FILE"
  fi
  load_existing_env "$ENV_FILE" ES_HOST ES_USERNAME ES_PASSWORD \
    ES_PROCESS_INDEX ES_NETWORK_INDEX ES_DISCOVERY_INDEX
  is_placeholder "${ES_HOST:-}" && ES_HOST=""
  is_placeholder "${ES_USERNAME:-}" && ES_USERNAME=""
  is_placeholder "${ES_PASSWORD:-}" && ES_PASSWORD=""

  local default_host="https://localhost:9200"
  (( LOCAL_ES )) && default_host="https://elasticsearch:9200"
  prompt ES_HOST "Elasticsearch URL (ES_HOST)" "$default_host"
  prompt ES_USERNAME "Elasticsearch username" "elastic"
  prompt_secret ES_PASSWORD "Elasticsearch password"
  prompt ES_PROCESS_INDEX "Process events index pattern" ".ds-logs-endpoint.events.process-default-*"
  prompt ES_NETWORK_INDEX "Network events index pattern" ".ds-logs-endpoint.events.network-default-*"
  prompt ES_DISCOVERY_INDEX "Discovery events index pattern" "logs-endpoint.events.process-*"
  require_value ES_HOST
  require_value ES_PASSWORD

  local key
  for key in ES_HOST ES_USERNAME ES_PASSWORD ES_PROCESS_INDEX ES_NETWORK_INDEX ES_DISCOVERY_INDEX; do
    env_set "$ENV_FILE" "$key" "${!key}"
  done
  ok "Wrote .env"
  apply_tls_settings

  if (( LOCAL_ES )); then
    info "Bundled Elasticsearch is not running yet; skipping connectivity check"
  else
    es_check "$ES_HOST" "$ES_USERNAME" "$ES_PASSWORD" \
      || warn "Continuing; fix ES settings in .env before starting the services"
  fi
}

# ── Maintenance add-on configuration ─────────────────────────────────────────
configure_maintenance() {
  step "SIEM Maintenance Agent configuration (addons/siem-maintenance/.env)"
  if [[ -f "$ADDON_ENV_FILE" && $RECONFIGURE -eq 0 ]]; then
    ok "Using existing add-on .env (pass --reconfigure to change it)"
    sync_addon_env_copy
    return
  fi

  local sys_tz
  sys_tz="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
  KIBANA_HOST="${KIBANA_HOST:-${ES_HOST/:9200/:5601}}"
  (( LOCAL_ES )) && KIBANA_HOST="http://kibana:5601"

  echo "  Elasticsearch settings are reused from the detection pipeline."
  prompt KIBANA_HOST "Kibana URL (KIBANA_HOST)" "$KIBANA_HOST"
  prompt GC_ALERT_WEBHOOK "Google Chat incoming webhook URL (blank = no Chat alerts)" ""
  prompt GC_ALERT_SPACE_NAME "Chat space name shown on alert cards" "SIEM-MAINTENANCE"
  prompt MAINTENANCE_IANA_TIMEZONE "Timezone (IANA, e.g. Africa/Kigali)" "${sys_tz:-UTC}"
  prompt DAILY_REPORT_TIME_CAT "Daily report time (HH:MM)" "08:30"
  prompt ES_HEALTH_MONITOR_INTERVAL_SECONDS "Health check interval in seconds" "7200"

  # LLM narrative is optional; provider is chosen from the model-name prefix.
  LLM_PROVIDER="${LLM_PROVIDER:-none}"
  prompt LLM_PROVIDER "LLM for report narrative: none, ollama, openai, anthropic" "$LLM_PROVIDER"
  LLM_ENABLED="true"
  OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
  case "$LLM_PROVIDER" in
    ollama)
      prompt OLLAMA_URL "Ollama URL" "$OLLAMA_URL"
      prompt LLM_MODEL "Ollama model tag" "llama3.2" ;;
    openai)
      prompt_secret OPENAI_API_KEY "OpenAI API key"
      require_value OPENAI_API_KEY
      prompt LLM_MODEL "OpenAI model" "gpt-4o-mini" ;;
    anthropic)
      prompt_secret ANTHROPIC_API_KEY "Anthropic API key"
      require_value ANTHROPIC_API_KEY
      prompt LLM_MODEL "Anthropic model" "claude-sonnet-4-6" ;;
    none)
      LLM_ENABLED="false"; LLM_MODEL="${LLM_MODEL:-llama3.2}" ;;
    *) die "Unknown LLM provider: $LLM_PROVIDER" ;;
  esac
  if [[ "$MODE" == "docker" && "$OLLAMA_URL" == *localhost* && "$LLM_PROVIDER" == "ollama" ]]; then
    warn "Inside Docker, localhost is the container. Use http://host.docker.internal:11434 or the host IP."
  fi

  # Auto-remediation changes the cluster (cache clears, snapshot/empty-index
  # cleanup), so new deployments start in dry-run until someone opts in.
  AUTO_REMEDIATION_DRY_RUN="${AUTO_REMEDIATION_DRY_RUN:-true}"
  if confirm "Let auto-remediation make real changes to the cluster? (No = dry-run, log only)" N; then
    AUTO_REMEDIATION_DRY_RUN="false"
  fi

  if (( DRY_RUN )); then
    printf '  [DRY ] write %s\n' "${ADDON_ENV_FILE#"$REPO_ROOT"/}"
  else
    local tmp
    tmp="$(mktemp "$ADDON_ENV_FILE.XXXXXX")"
    {
      echo "# Generated by deploy.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "# Full option list: addons/siem-maintenance/README.md"
      echo
      echo "ES_HOST=$(escape_env "$ES_HOST")"
      echo "KIBANA_HOST=$(escape_env "$KIBANA_HOST")"
      echo "ES_AUTH_TYPE=userpass"
      echo "ES_API_KEY="
      echo "ES_USERNAME=$(escape_env "${ES_USERNAME:-}")"
      echo "ES_PASSWORD=$(escape_env "${ES_PASSWORD:-}")"
      echo "ES_PROCESS_INDEX=$(escape_env "$ES_PROCESS_INDEX")"
      echo "ES_NETWORK_INDEX=$(escape_env "$ES_NETWORK_INDEX")"
      echo "ES_DISCOVERY_INDEX=$(escape_env "$ES_DISCOVERY_INDEX")"
      echo "ES_VERIFY_CERTS=$ES_VERIFY_CERTS"
      [[ -n "${ES_CA_CERT:-}" ]] && echo "ES_CA_CERT=$(escape_env "$(ca_cert_path)")"
      echo "ES_QUERY_SLOW_SEC=2.0"
      echo "ES_QUERY_CRITICAL_SEC=10.0"
      echo
      echo "GC_ALERT_WEBHOOK=$(escape_env "${GC_ALERT_WEBHOOK:-}")"
      echo "GC_ALERT_SPACE_NAME=$(escape_env "$GC_ALERT_SPACE_NAME")"
      echo "GC_CARD_LOGO_URL="
      echo
      echo "LOG_LEVEL=INFO"
      echo "ES_ALERT_COOLDOWN_HOURS=2"
      echo "ES_HEALTH_MONITOR_INTERVAL_SECONDS=$(escape_env "$ES_HEALTH_MONITOR_INTERVAL_SECONDS")"
      echo
      echo "LLM_ENABLED=$LLM_ENABLED"
      echo "LLM_MODEL=$(escape_env "$LLM_MODEL")"
      echo "ES_HEALTH_LLM_MODEL=$(escape_env "$LLM_MODEL")"
      echo "OLLAMA_URL=$(escape_env "$OLLAMA_URL")"
      [[ -n "${OPENAI_API_KEY:-}" ]] && echo "OPENAI_API_KEY=$(escape_env "$OPENAI_API_KEY")"
      [[ -n "${ANTHROPIC_API_KEY:-}" ]] && echo "ANTHROPIC_API_KEY=$(escape_env "$ANTHROPIC_API_KEY")"
      echo
      echo "MAINTENANCE_IANA_TIMEZONE=$(escape_env "$MAINTENANCE_IANA_TIMEZONE")"
      echo "DAILY_REPORT_TIME_CAT=$(escape_env "$DAILY_REPORT_TIME_CAT")"
      echo "AUTO_REMEDIATION_TIME=08:35"
      echo "AUTO_REMEDIATION_DRY_RUN=$AUTO_REMEDIATION_DRY_RUN"
      echo "FEEDBACK_SERVER_PORT=8090"
      echo "ML_FILE_RETENTION_DAYS=7"
      echo "DAILY_REPORT_ATTACH_ES_LOGS=false"
      echo "DAILY_REPORT_ATTACH_ES_JSON=false"
    } >"$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$ADDON_ENV_FILE"
  fi
  sync_addon_env_copy
  ok "Wrote add-on .env (auto-remediation dry-run: $AUTO_REMEDIATION_DRY_RUN)"
  [[ -z "${GC_ALERT_WEBHOOK:-}" ]] && warn "No Chat webhook set; the agent will run but cannot send alerts"
  info "Feedback loop / Chat app buttons: run addons/siem-maintenance/install.sh later (or --maintenance-wizard)"
}

# The agent loads repo .env then Agent-SIEM-maintenance/.env; its installer keeps both in sync.
sync_addon_env_copy() {
  run cp "$ADDON_ENV_FILE" "$ADDON_AGENT_DIR/.env"
  run chmod 600 "$ADDON_AGENT_DIR/.env"
}

# ── Alert triage add-on configuration ────────────────────────────────────────
is_loopback() {
  [[ "$1" == "127.0.0.1" || "$1" == "localhost" || "$1" == "::1" ]]
}

# httpx (used by the triage agent) honours SSL_CERT_FILE, but that file replaces
# the default trust store, so for a private CA it must also hold the public CAs
# that threat-intel and LLM APIs are signed by. Build system CAs + ES_CA_CERT.
build_triage_ca_bundle() {
  local base="" candidate bundle="$TRIAGE_CERT_DIR/ca-bundle.pem" ca
  ca="$(ca_cert_path)"
  for candidate in "${SYSTEM_CA_BUNDLES[@]}"; do
    if [[ -r "$candidate" ]]; then base="$candidate"; break; fi
  done
  [[ -n "$base" ]] || base="$(python3 -c 'import certifi; print(certifi.where())' 2>/dev/null || true)"
  [[ -n "$base" && -r "$base" ]] || die "No system CA bundle found to combine with ES_CA_CERT"
  if (( DRY_RUN )); then
    printf '  [DRY ] build %s from %s + %s\n' "${bundle#"$REPO_ROOT"/}" "$base" "$ca"
    return
  fi
  [[ -r "$ca" ]] || die "ES_CA_CERT not readable: $ca"
  mkdir -p "$TRIAGE_CERT_DIR"
  cat "$base" "$ca" >"$bundle"
  chmod 644 "$bundle"
  ok "Built ${bundle#"$REPO_ROOT"/} (system CAs + ES_CA_CERT)"
}

configure_triage() {
  step "Alert Triage Agent configuration (addons/alert-triage/.env)"
  if ! is_loopback "$TRIAGE_LISTEN"; then
    warn "The triage agent will listen on $TRIAGE_LISTEN:$TRIAGE_PORT with NO authentication."
    warn "Anyone who can reach it can read open alerts and run investigations with its ES credentials."
    if (( ! NON_INTERACTIVE )) && ! confirm "Expose it on $TRIAGE_LISTEN anyway?" N; then
      TRIAGE_LISTEN="127.0.0.1"
      info "Keeping it on 127.0.0.1 (reach it with: ssh -L $TRIAGE_PORT:127.0.0.1:$TRIAGE_PORT <this host>)"
    fi
  fi

  # Inside a container the agent must listen on all interfaces; the host-side
  # port mapping carries TRIAGE_LISTEN instead.
  local listen_in_env="$TRIAGE_LISTEN" ssl_cert_file=""
  [[ "$MODE" == "docker" ]] && listen_in_env="0.0.0.0"
  if [[ "$ES_VERIFY_CERTS" == "true" && -n "${ES_CA_CERT:-}" ]]; then
    build_triage_ca_bundle
    ssl_cert_file="$TRIAGE_CERT_DIR/ca-bundle.pem"
    [[ "$MODE" == "docker" ]] && ssl_cert_file="/app/certs/ca-bundle.pem"
  fi

  if [[ -f "$TRIAGE_ENV_FILE" && $RECONFIGURE -eq 0 ]]; then
    ok "Using existing add-on .env (pass --reconfigure to change it)"
    [[ "$(env_get "$TRIAGE_ENV_FILE" HOST)" == "$listen_in_env" ]] || env_set "$TRIAGE_ENV_FILE" HOST "$listen_in_env"
    [[ "$(env_get "$TRIAGE_ENV_FILE" PORT)" == "$TRIAGE_PORT" ]] || env_set "$TRIAGE_ENV_FILE" PORT "$TRIAGE_PORT"
    return
  fi

  echo "  The agent only runs searches. A read-only Elasticsearch user for the alert and"
  echo "  event indices is recommended; press Enter to reuse the pipeline's account."
  TRIAGE_ES_USERNAME="${TRIAGE_ES_USERNAME:-${ES_USERNAME:-}}"
  TRIAGE_ES_PASSWORD="${TRIAGE_ES_PASSWORD:-${ES_PASSWORD:-}}"
  prompt TRIAGE_ES_USERNAME "Elasticsearch username for the triage agent" "$TRIAGE_ES_USERNAME"
  prompt_secret TRIAGE_ES_PASSWORD "Elasticsearch password for the triage agent"
  require_value TRIAGE_ES_PASSWORD
  prompt ELASTIC_INDEX "Security alerts index" ".alerts-security.alerts-default"

  AI_PROVIDER="${AI_PROVIDER:-none}"
  prompt AI_PROVIDER "AI verdicts: none, ollama, claude, openai_compat" "$AI_PROVIDER"
  OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
  case "$AI_PROVIDER" in
    ollama)
      prompt OLLAMA_URL "Ollama URL" "$OLLAMA_URL"
      prompt OLLAMA_MODEL "Ollama model tag" "llama3.2" ;;
    claude)
      prompt_secret ANTHROPIC_API_KEY "Anthropic API key"
      require_value ANTHROPIC_API_KEY
      prompt CLAUDE_MODEL "Claude model" "claude-haiku-4-5-20251001" ;;
    openai_compat)
      prompt OPENAI_COMPAT_URL "OpenAI-compatible base URL" "http://localhost:1234/v1"
      prompt_secret OPENAI_COMPAT_KEY "API key (blank if none)"
      prompt OPENAI_COMPAT_MODEL "Model" "mistral" ;;
    none) ;;
    *) die "Unknown AI provider: $AI_PROVIDER" ;;
  esac
  if [[ "$MODE" == "docker" && "$AI_PROVIDER" == "ollama" && "$OLLAMA_URL" == *localhost* ]]; then
    warn "Inside Docker, localhost is the container. Use http://host.docker.internal:11434 or the host IP."
  fi
  prompt_secret ABUSEIPDB_API_KEY "AbuseIPDB API key (blank to skip)"
  prompt_secret VIRUSTOTAL_API_KEY "VirusTotal API key (blank to skip)"

  if (( DRY_RUN )); then
    printf '  [DRY ] write %s\n' "${TRIAGE_ENV_FILE#"$REPO_ROOT"/}"
  else
    local tmp
    tmp="$(mktemp "$TRIAGE_ENV_FILE.XXXXXX")"
    {
      echo "# Generated by deploy.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "# Full option list: addons/alert-triage/.env.example"
      echo
      echo "ELASTIC_URL=$(escape_env "$ES_HOST")"
      echo "ELASTIC_USERNAME=$(escape_env "$TRIAGE_ES_USERNAME")"
      echo "ELASTIC_PASSWORD=$(escape_env "$TRIAGE_ES_PASSWORD")"
      echo "ELASTIC_VERIFY_SSL=$ES_VERIFY_CERTS"
      [[ -n "$ssl_cert_file" ]] && echo "SSL_CERT_FILE=$(escape_env "$ssl_cert_file")"
      echo "ELASTIC_INDEX=$(escape_env "$ELASTIC_INDEX")"
      echo "ELASTIC_TIMEOUT=30"
      echo
      echo "ABUSEIPDB_API_KEY=$(escape_env "${ABUSEIPDB_API_KEY:-}")"
      echo "VIRUSTOTAL_API_KEY=$(escape_env "${VIRUSTOTAL_API_KEY:-}")"
      echo "THREAT_INTEL_TIMEOUT=10"
      echo
      echo "AI_PROVIDER=$AI_PROVIDER"
      [[ -n "${ANTHROPIC_API_KEY:-}" && "$AI_PROVIDER" == "claude" ]] && echo "ANTHROPIC_API_KEY=$(escape_env "$ANTHROPIC_API_KEY")"
      echo "CLAUDE_MODEL=$(escape_env "${CLAUDE_MODEL:-claude-haiku-4-5-20251001}")"
      echo "OLLAMA_URL=$(escape_env "$OLLAMA_URL")"
      echo "OLLAMA_MODEL=$(escape_env "${OLLAMA_MODEL:-llama3.2}")"
      echo "OPENAI_COMPAT_URL=$(escape_env "${OPENAI_COMPAT_URL:-}")"
      echo "OPENAI_COMPAT_KEY=$(escape_env "${OPENAI_COMPAT_KEY:-}")"
      echo "OPENAI_COMPAT_MODEL=$(escape_env "${OPENAI_COMPAT_MODEL:-mistral}")"
      echo
      echo "HOST=$listen_in_env"
      echo "PORT=$TRIAGE_PORT"
      echo "LOG_LEVEL=INFO"
      echo "ASSET_INVENTORY_PATH=assets.yml"
      echo "RELATED_EVENTS_WINDOW_MIN=15"
      echo "RELATED_EVENTS_MAX=50"
    } >"$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$TRIAGE_ENV_FILE"
  fi
  ok "Wrote add-on .env (AI: $AI_PROVIDER, TLS verification: $ES_VERIFY_CERTS)"
  if [[ ! -f "$TRIAGE_DIR/assets.yml" ]]; then
    info "No asset inventory yet. Copy addons/alert-triage/assets.example.yml to assets.yml and"
    info "describe your hosts; verdicts are much better with host criticality and roles."
  fi
}

# ── venv installs ────────────────────────────────────────────────────────────
make_venv() {
  local dir="$1"
  if [[ -x "$dir/bin/python" ]]; then
    ok "Using existing venv ${dir#"$REPO_ROOT"/}"
  else
    run python3 -m venv "$dir"
    ok "Created venv ${dir#"$REPO_ROOT"/}"
  fi
  run "$dir/bin/python" -m pip install --quiet --upgrade pip
}

install_detection_venv() {
  step "Installing detection pipeline (venv)"
  make_venv "$VENV_DIR"
  local spec="."
  [[ -n "$EXTRAS" ]] && spec=".[${EXTRAS}]"
  (cd "$REPO_ROOT" && run "$VENV_DIR/bin/python" -m pip install --quiet -e "$spec")
  run mkdir -p "$REPO_ROOT/results/models" "$REPO_ROOT/results/reports" \
    "$REPO_ROOT/results/visualizations" "$REPO_ROOT/logs"
  ok "Installed detection dependencies${EXTRAS:+ (extras: $EXTRAS)}"
}

install_maintenance_venv() {
  step "Installing SIEM Maintenance Agent (venv)"
  make_venv "$ADDON_VENV_DIR"
  run "$ADDON_VENV_DIR/bin/python" -m pip install --quiet -r "$ADDON_DIR/requirements.txt"
  run mkdir -p "$ADDON_AGENT_DIR/results" "$ADDON_DIR/logs"
  ok "Installed add-on dependencies"
  if (( DRY_RUN )); then
    run "$ADDON_VENV_DIR/bin/python" "$ADDON_DIR/verify_setup.py"
    return
  fi
  # verify_setup.py logs full tracebacks on connection errors; show only its check lines.
  local out rc=0
  out="$(cd "$ADDON_DIR" && "$ADDON_VENV_DIR/bin/python" verify_setup.py 2>&1)" || rc=$?
  grep -E '^\s*\[(OK|FAIL|WARN|SKIP) *\]' <<<"$out" | sed 's/^ */    /' || true
  if (( rc == 0 )); then
    ok "Add-on verify_setup.py passed"
  else
    warn "Add-on verify_setup.py reported problems; fix addons/siem-maintenance/.env and re-run it"
  fi
}

install_triage_venv() {
  step "Installing Alert Triage Agent (venv)"
  make_venv "$TRIAGE_VENV_DIR"
  run "$TRIAGE_VENV_DIR/bin/python" -m pip install --quiet -r "$TRIAGE_DIR/requirements.txt" \
    -c "$TRIAGE_CONSTRAINTS"
  ok "Installed triage dependencies"
  (( DRY_RUN )) && return
  # Importing server builds the app, MCP tools, and AI provider from .env without serving.
  local out
  if out="$(cd "$TRIAGE_DIR" && "$TRIAGE_VENV_DIR/bin/python" -c 'import server' 2>&1)"; then
    ok "Triage agent loads with this configuration"
  else
    warn "Triage agent failed to load: $(tail -1 <<<"$out")"
  fi
}

# ── systemd ──────────────────────────────────────────────────────────────────
have_systemd() {
  [[ "$(uname -s)" == "Linux" ]] && command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]
}

# Returns 0 when it is fine to (re)write the unit: absent, already ours, or --replace-units.
unit_owned_or_absent() {
  local unit="$1" marker="$2" current
  current="$(systemctl cat "$unit" 2>/dev/null | grep -E '^(ExecStart|WorkingDirectory)=' || true)"
  [[ -z "$current" ]] && return 0
  [[ "$current" == *"$marker"* ]] && return 0
  warn "$unit already exists and points somewhere else:"
  sed 's/^/         /' <<<"$current"
  if (( REPLACE_UNITS )) || confirm "Replace it with this checkout's version?" N; then
    return 0
  fi
  return 1
}

install_detection_unit() {
  step "systemd: $DETECTION_UNIT"
  if ! unit_owned_or_absent "$DETECTION_UNIT" "$REPO_ROOT/"; then
    warn "Left $DETECTION_UNIT unchanged"
    return
  fi
  local unit
  unit="$(cat <<EOF
[Unit]
Description=Realtime Anomaly Detection Service
Documentation=https://github.com/cylab-africa/SOC-in-a-Box-ELK-ML-AgenticAI-
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$REPO_ROOT
Environment=PYTHONUNBUFFERED=1
ExecStart=$VENV_DIR/bin/python -u $REPO_ROOT/realtime_service.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=realtime_service

[Install]
WantedBy=multi-user.target
EOF
)"
  if (( DRY_RUN )); then
    printf '  [DRY ] write /etc/systemd/system/%s:\n' "$DETECTION_UNIT"
    sed 's/^/           /' <<<"$unit"
  else
    printf '%s\n' "$unit" | sudo tee "/etc/systemd/system/$DETECTION_UNIT" >/dev/null
  fi
  run sudo systemctl daemon-reload
  run sudo systemctl enable "$DETECTION_UNIT"
  run sudo systemctl restart "$DETECTION_UNIT"
  ok "$DETECTION_UNIT enabled and started (logs: journalctl -u $DETECTION_UNIT -f)"
}

install_maintenance_unit() {
  step "systemd: $MAINTENANCE_UNIT"
  if ! unit_owned_or_absent "$MAINTENANCE_UNIT" "$ADDON_AGENT_DIR"; then
    warn "Left $MAINTENANCE_UNIT unchanged"
    return
  fi
  # The add-on ships its own unit installer; it runs the service as SUDO_USER.
  run sudo env SUDO_USER="$SERVICE_USER" bash "$ADDON_DIR/deploy/install-systemd-service.sh" \
    "$ADDON_DIR" "$ADDON_VENV_DIR/bin/python"
  ok "$MAINTENANCE_UNIT enabled and started (logs: journalctl -u $MAINTENANCE_UNIT -f)"
}

# Host to probe /health on: the bind address, or loopback when bound to all interfaces.
triage_probe_host() {
  if [[ "$TRIAGE_LISTEN" == "0.0.0.0" || "$TRIAGE_LISTEN" == "::" ]] || is_loopback "$TRIAGE_LISTEN"; then
    printf '127.0.0.1'
  else
    printf '%s' "$TRIAGE_LISTEN"
  fi
}

wait_for_triage() {
  (( DRY_RUN )) && return
  local url i
  url="http://$(triage_probe_host):$TRIAGE_PORT/health"
  for i in $(seq 1 15); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      ok "Triage agent answering at $url"
      return
    fi
    sleep 1
  done
  warn "No answer from $url yet; check the service logs"
}

install_triage_unit() {
  step "systemd: $TRIAGE_UNIT"
  if ! unit_owned_or_absent "$TRIAGE_UNIT" "$TRIAGE_DIR"; then
    warn "Left $TRIAGE_UNIT unchanged"
    return
  fi
  local unit
  unit="$(cat <<EOF
[Unit]
Description=Alert Triage Agent (SOC-in-a-Box add-on)
Documentation=https://github.com/cylab-africa/SOC-in-a-Box-ELK-ML-AgenticAI-
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$TRIAGE_DIR
# server.py loads $TRIAGE_DIR/.env itself (python-dotenv)
ExecStart=$TRIAGE_VENV_DIR/bin/python $TRIAGE_DIR/server.py
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=alert-triage

[Install]
WantedBy=multi-user.target
EOF
)"
  if (( DRY_RUN )); then
    printf '  [DRY ] write /etc/systemd/system/%s:\n' "$TRIAGE_UNIT"
    sed 's/^/           /' <<<"$unit"
  else
    printf '%s\n' "$unit" | sudo tee "/etc/systemd/system/$TRIAGE_UNIT" >/dev/null
  fi
  run sudo systemctl daemon-reload
  run sudo systemctl enable "$TRIAGE_UNIT"
  run sudo systemctl restart "$TRIAGE_UNIT"
  ok "$TRIAGE_UNIT enabled and started (logs: journalctl -u $TRIAGE_UNIT -f)"
  wait_for_triage
}

# ── Docker ───────────────────────────────────────────────────────────────────
deploy_docker() {
  step "Docker Compose"
  local args=(--env-file "$ENV_FILE" -f "$COMPOSE_FILE")
  local services=()
  if (( LOCAL_ES )); then
    info "Starting bundled Elasticsearch + Kibana"
  else
    args+=(-f "$COMPOSE_EXTERNAL_ES")
    services=(detection)
  fi
  if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
    args+=(--profile maintenance)
    (( LOCAL_ES )) || services+=(siem-maintenance)
  fi
  if [[ "$WITH_TRIAGE" == "yes" ]]; then
    args+=(--profile triage)
    (( LOCAL_ES )) || services+=(alert-triage)
    run mkdir -p "$TRIAGE_CERT_DIR"
  fi
  # The triage port mapping is interpolated from these; compose defaults to 127.0.0.1:8000.
  local compose_env=(env TRIAGE_BIND="$TRIAGE_LISTEN" TRIAGE_PORT="$TRIAGE_PORT")
  if (( LOCAL_ES )); then
    run "${compose_env[@]}" docker compose "${args[@]}" up -d --build
  else
    run "${compose_env[@]}" docker compose "${args[@]}" up -d --build --no-deps "${services[@]}"
  fi
  ok "Containers started"
  if [[ "$WITH_TRIAGE" == "yes" ]]; then
    wait_for_triage
  fi
  info "Status: docker compose ${args[*]} ps"
  info "Logs:   docker compose ${args[*]} logs -f"
}

# ── Summary ──────────────────────────────────────────────────────────────────
summary() {
  step "Done"
  (( DRY_RUN )) && echo "  Dry run: nothing was changed."
  echo "  Detection pipeline:   $MODE"
  echo "  Maintenance add-on:   $WITH_MAINTENANCE"
  echo "  Triage add-on:        $WITH_TRIAGE"
  if [[ "$WITH_TRIAGE" == "yes" ]]; then
    echo "    Web UI / API:       http://$(triage_probe_host):$TRIAGE_PORT/"
    echo "    MCP endpoint:       http://$(triage_probe_host):$TRIAGE_PORT/mcp/mcp"
    if is_loopback "$TRIAGE_LISTEN"; then
      echo "    From another machine: ssh -L $TRIAGE_PORT:127.0.0.1:$TRIAGE_PORT <this host>"
    fi
  fi
  if [[ "$MODE" == "venv" ]]; then
    echo
    echo "  Sanity checks (see DEPLOYMENT.md section 6):"
    echo "    .venv/bin/python main.py --list-jobs"
    echo "    .venv/bin/python push_all_anomalies.py --dry-run"
    if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
      echo "    addons/siem-maintenance/.venv/bin/python addons/siem-maintenance/Agent-SIEM-maintenance/maintenance_service.py --once-poll"
    fi
    if (( ! INSTALL_SYSTEMD )) || ! have_systemd; then
      echo
      echo "  No systemd units installed. Start manually:"
      echo "    .venv/bin/python realtime_service.py"
      if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
        echo "    addons/siem-maintenance/.venv/bin/python addons/siem-maintenance/Agent-SIEM-maintenance/maintenance_service.py"
      fi
      if [[ "$WITH_TRIAGE" == "yes" ]]; then
        echo "    (cd addons/alert-triage && .venv/bin/python server.py)"
      fi
    fi
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  echo "SOC-in-a-Box deployment ($REPO_ROOT)"
  (( DRY_RUN )) && echo "DRY RUN: no changes will be made"
  preflight
  configure_detection

  if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
    if (( MAINTENANCE_WIZARD )); then
      (( NON_INTERACTIVE )) && die "--maintenance-wizard is interactive; drop --non-interactive"
      [[ "$MODE" == "venv" ]] || die "--maintenance-wizard only supports --mode venv"
      step "Handing off to the add-on's full installer"
      (cd "$ADDON_DIR" && run bash ./install.sh)
    else
      configure_maintenance
    fi
  fi
  [[ "$WITH_TRIAGE" == "yes" ]] && configure_triage

  if [[ "$MODE" == "docker" ]]; then
    deploy_docker
  else
    install_detection_venv
    if [[ "$WITH_MAINTENANCE" == "yes" && $MAINTENANCE_WIZARD -eq 0 ]]; then
      install_maintenance_venv
    fi
    [[ "$WITH_TRIAGE" == "yes" ]] && install_triage_venv
    if (( INSTALL_SYSTEMD )) && have_systemd; then
      install_detection_unit
      if [[ "$WITH_MAINTENANCE" == "yes" && $MAINTENANCE_WIZARD -eq 0 ]]; then
        install_maintenance_unit
      fi
      if [[ "$WITH_TRIAGE" == "yes" ]]; then
        install_triage_unit
      fi
    elif (( INSTALL_SYSTEMD )); then
      warn "systemd not available; skipping service units"
    fi
  fi
  summary
}

main
