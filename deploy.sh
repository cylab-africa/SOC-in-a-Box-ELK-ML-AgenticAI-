#!/usr/bin/env bash
# SOC-in-a-Box installer. Installs the detection engine on this machine, connects
# it to your Elasticsearch, and runs it as a background service, with optional
# add-ons: the SIEM Maintenance Agent (addons/siem-maintenance), the Alert Triage
# Agent (addons/alert-triage) and the Greenbone results push (addons/greenbone).
#
# Usage:
#   ./deploy.sh                          interactive; asks about each add-on
#   ./deploy.sh --with-maintenance       detection pipeline + maintenance agent
#   ./deploy.sh --with-triage            detection pipeline + alert triage agent
#   ./deploy.sh --with-greenbone         detection pipeline + Greenbone results push
#   ./deploy.sh --mode docker            run under Docker Compose instead of venv + systemd
#   ES_HOST=... ES_USERNAME=... ES_PASSWORD=... ./deploy.sh --non-interactive --with-maintenance
#   ./deploy.sh --dry-run                print what would happen, change nothing
#
# Run ./deploy.sh --help for every option. See docs/installation.md for details.
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
GREENBONE_DIR="$REPO_ROOT/addons/greenbone"
GREENBONE_ENV_FILE="$GREENBONE_DIR/.env"
GREENBONE_VENV_DIR="$GREENBONE_DIR/.venv"
GREENBONE_SERVICE="gvm-siem-push.service"
GREENBONE_TIMER="gvm-siem-push.timer"
# systemd OnCalendar expression for the push; daily at 06:00 unless overridden.
GREENBONE_SCHEDULE="${GREENBONE_SCHEDULE:-*-*-* 06:00:00}"
# gvmd's socket in the Greenbone Community Edition Docker Compose install.
GVM_DEFAULT_SOCKET="/var/lib/docker/volumes/greenbone-community-edition_gvmd_socket_vol/_data/gvmd.sock"
# Where the bundled TLS trust step saves a cluster's CA (relative to the repo root).
TRUSTED_CA_PATH="config/certs/ca.pem"
# Index patterns written to .env, with Elastic Agent's standard names as defaults.
INDEX_KEYS=(ES_PROCESS_INDEX ES_NETWORK_INDEX ES_DISCOVERY_INDEX ES_METADATA_INDEX ES_ALERTS_INDEX)
# System trust stores, in the order distributions ship them.
SYSTEM_CA_BUNDLES=(/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem)
COMPOSE_FILE="$REPO_ROOT/docker/docker-compose.yml"
COMPOSE_EXTERNAL_ES="$REPO_ROOT/docker/docker-compose.external-es.yml"
MIN_PY_MINOR=10

# ── Options ──────────────────────────────────────────────────────────────────
MODE="venv"                 # venv | docker
WITH_MAINTENANCE=""         # "", yes, no  ("" = ask)
WITH_TRIAGE=""              # "", yes, no  ("" = ask)
WITH_GREENBONE=""           # "", yes, no  ("" = ask)
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

Installs SOC-in-a-Box on this machine: checks the prerequisites, asks for your
Elasticsearch address and login (saved in .env), installs the detection engine
and any add-ons you choose, and starts them as background services. Safe to
re-run. Try --dry-run first to see every step without changing anything.

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
  --with-greenbone         Also install the Greenbone results push (needs Greenbone
                           on this server). Sends finished vulnerability scans to
                           Elasticsearch daily.
  --no-greenbone           Skip the Greenbone results push (skip the question)

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
  --insecure-tls           Don't verify Elasticsearch's TLS certificate (lab or
                           classroom clusters only). Without this flag, an untrusted
                           certificate is shown with its fingerprint and you choose
                           whether to trust it.
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
    --with-greenbone)     WITH_GREENBONE="yes" ;;
    --no-greenbone)       WITH_GREENBONE="no" ;;
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

# Remove KEY from a dotenv file if present.
env_del() {
  local file="$1" key="$2"
  [[ -f "$file" ]] && grep -q "^$key=" "$file" || return 0
  if (( DRY_RUN )); then
    printf '  [DRY ] remove %s from %s\n' "$key" "${file#"$REPO_ROOT"/}"
    return
  fi
  local tmp
  tmp="$(mktemp "$file.XXXXXX")"
  awk -v k="$key" 'index($0, k "=") != 1' "$file" >"$tmp"
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

  if [[ -z "$WITH_GREENBONE" ]]; then
    echo
    echo "  Optional add-on: Greenbone vulnerability results"
    echo "  Sends finished Greenbone / OpenVAS scan results to Elasticsearch once a day,"
    echo "  labelled new, fixed or unchanged since the previous scan. Needs Greenbone"
    echo "  installed on this server."
    if confirm "Install the Greenbone results push too?" N; then
      WITH_GREENBONE="yes"
    else
      WITH_GREENBONE="no"
    fi
  fi
  if [[ "$WITH_GREENBONE" == "yes" ]]; then
    [[ -f "$GREENBONE_DIR/gvm_siem_push.py" ]] || die "Add-on not found at $GREENBONE_DIR (clone the full repository)"
    # It reads gvmd's socket on this host, so it always runs from a host venv,
    # even when the detection engine runs in Docker.
    if [[ "$MODE" == "docker" ]]; then
      command -v python3 >/dev/null || die "The Greenbone add-on needs python3 on this host (with venv support)"
      python3 -c 'import ensurepip, venv' 2>/dev/null \
        || die "python3 venv support missing. On Debian/Ubuntu: sudo apt install -y python3-venv"
    fi
    ok "Greenbone add-on: enabled"
  else
    info "Greenbone add-on: skipped (re-run with --with-greenbone to add it later)"
  fi
}

# ── Elasticsearch connectivity ───────────────────────────────────────────────
# Credentials go to curl on stdin so they never appear in the process list, and
# are only sent over a verified TLS connection unless --insecure-tls is given.
# Returns 0 when connected, 2 when the cluster answers but its certificate is
# not trusted, and 1 for anything else.
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
  local cfg="" rc=0
  [[ -n "$user" ]] && cfg="user = \"${user//\"/\\\"}:${pass//\"/\\\"}\""
  out="$(printf '%s\n' "$cfg" | curl "${flags[@]}" -K - "$host" 2>&1)" || rc=$?
  if (( rc == 0 )); then
    es_response_ok "$host" "$out" "(TLS verified)"
    return
  fi
  if (( INSECURE_TLS )); then
    rc=0
    out="$(printf '%s\n' "$cfg" | curl "${flags[@]}" -k -K - "$host" 2>&1)" || rc=$?
    if (( rc == 0 )); then
      es_response_ok "$host" "$out" "with TLS verification off (lab use only)"
      return
    fi
  elif [[ "$host" == https://* ]]; then
    # Diagnose a certificate problem without sending credentials.
    local code
    code="$(curl -sS --max-time 10 -k -o /dev/null -w '%{http_code}' "$host" 2>/dev/null || true)"
    if [[ -n "$code" && "$code" != "000" ]]; then
      if [[ -n "${ES_CA_CERT:-}" && "$out" == *"subject name"* ]]; then
        warn "The certificate is trusted, but it was issued for a different name than the one in $host."
        info "Use the hostname or IP address the certificate was issued for, or continue without verification."
      else
        warn "Elasticsearch at $host answers, but its TLS certificate is not trusted"
      fi
      if (( NON_INTERACTIVE )); then
        info "Set ES_CA_CERT=/path/to/ca.pem, or pass --insecure-tls for a lab cluster"
      fi
      return 2
    fi
  fi
  fail "Could not reach Elasticsearch at $host: ${out:0:200}"
  return 1
}

# The TLS connection worked and Elasticsearch answered; check what it said.
es_response_ok() {
  local host="$1" out="$2" how="$3"
  if [[ "$out" == *cluster_name* ]]; then
    if [[ "$how" == "(TLS verified)" ]]; then
      ok "Elasticsearch reachable at $host $how"
    else
      warn "Elasticsearch reachable at $host $how"
    fi
    return 0
  fi
  if [[ "$out" == *security_exception* ]]; then
    fail "Elasticsearch at $host rejected the username or password"
  else
    fail "Unexpected answer from Elasticsearch at $host: ${out:0:200}"
  fi
  return 1
}

# host:port from an https:// URL, for openssl.
url_host_port() {
  local rest="${1#*://}"
  rest="${rest%%/*}"
  if [[ "$rest" == *:* ]]; then
    printf '%s' "$rest"
  else
    printf '%s:443' "$rest"
  fi
}

# Self-managed Elasticsearch signs its own certificates, so most first installs
# land here. Show the CA's fingerprint and let the user choose: trust it (saved
# to config/certs/ca.pem, verification stays on) or continue unverified (labs).
# Returns 0 when a choice was made, 1 to stop.
resolve_untrusted_cert() {
  local host="$1" chain="" ca="" fp="" choice
  (( NON_INTERACTIVE )) && return 1
  if command -v openssl >/dev/null; then
    chain="$(openssl s_client -connect "$(url_host_port "$host")" -showcerts </dev/null 2>/dev/null || true)"
    # The last certificate in the chain is the self-signed CA that issued the others.
    ca="$(awk '/-----BEGIN CERTIFICATE-----/ { c = ""; inside = 1 }
               inside { c = c $0 "\n" }
               /-----END CERTIFICATE-----/ { inside = 0; last = c }
               END { printf "%s", last }' <<<"$chain")"
    if [[ -n "$ca" ]]; then
      fp="$(openssl x509 -noout -fingerprint -sha256 <<<"$ca" 2>/dev/null | cut -d= -f2)"
    fi
  fi

  echo
  echo "  This is normal for a self-managed cluster: Elasticsearch signs its own certificates."
  if [[ -n "$fp" ]]; then
    echo "  The certificate authority's SHA-256 fingerprint is:"
    echo "    $fp"
    echo "  To be sure you are talking to your own cluster, compare it with the fingerprint"
    echo "  Elasticsearch printed when it was installed, or run this on the Elasticsearch server"
    echo "  (ignore colons and upper/lower case):"
    echo "    sudo openssl x509 -noout -fingerprint -sha256 -in /etc/elasticsearch/certs/http_ca.crt"
  fi
  echo
  if [[ -n "$fp" ]]; then
    echo "  1) Trust this certificate (recommended; the connection stays verified)"
  else
    echo "  1) Trust the certificate: unavailable, it could not be downloaded. Copy http_ca.crt"
    echo "     from the server to $TRUSTED_CA_PATH and set ES_CA_CERT=$TRUSTED_CA_PATH in .env."
  fi
  echo "  2) Continue without verifying the certificate (lab or classroom only)"
  echo "  3) Stop here"
  read -r -p "  Choose [1/2/3]: " choice
  case "$choice" in
    1)
      [[ -n "$fp" ]] || return 1
      run mkdir -p "$REPO_ROOT/$(dirname "$TRUSTED_CA_PATH")"
      if (( DRY_RUN )); then
        printf '  [DRY ] write %s\n' "$TRUSTED_CA_PATH"
      else
        printf '%s' "$ca" >"$REPO_ROOT/$TRUSTED_CA_PATH"
        chmod 644 "$REPO_ROOT/$TRUSTED_CA_PATH"
      fi
      ES_CA_CERT="$TRUSTED_CA_PATH"
      ES_VERIFY_CERTS="true"
      env_set "$ENV_FILE" ES_VERIFY_CERTS true
      ok "Saved the cluster's certificate to $TRUSTED_CA_PATH"
      ;;
    2)
      INSECURE_TLS=1
      ;;
    *)
      die "Stopped. Your settings so far are in .env; run ./deploy.sh again when ready."
      ;;
  esac
}

# Check the connection; while the certificate is the problem, offer the trust
# choice again (e.g. trusting worked but the hostname does not match).
connect_es() {
  local rc=0 attempts=0
  es_check "$ES_HOST" "${ES_USERNAME:-}" "${ES_PASSWORD:-}" || rc=$?
  while (( rc == 2 && attempts < 3 )) && resolve_untrusted_cert "$ES_HOST"; do
    attempts=$((attempts + 1))
    apply_tls_settings
    rc=0
    es_check "$ES_HOST" "${ES_USERNAME:-}" "${ES_PASSWORD:-}" || rc=$?
  done
  if (( rc != 0 )); then
    warn "Continuing; fix ES settings in .env before starting the services"
  fi
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
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "$value" =~ ^(0|false|no|off)$ ]]
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
    load_existing_env "$ENV_FILE" ES_HOST ES_USERNAME ES_PASSWORD "${INDEX_KEYS[@]}"
    if ! is_placeholder "${ES_HOST:-}"; then
      ok "Using existing .env (pass --reconfigure to change it)"
      apply_tls_settings
      connect_es
      return
    fi
    info ".env still has placeholder values; asking for them now"
  fi

  if [[ ! -f "$ENV_FILE" ]]; then
    run cp "$REPO_ROOT/.env.example" "$ENV_FILE"
    run chmod 600 "$ENV_FILE"
  fi
  load_existing_env "$ENV_FILE" ES_HOST ES_USERNAME ES_PASSWORD "${INDEX_KEYS[@]}"
  is_placeholder "${ES_HOST:-}" && ES_HOST=""
  is_placeholder "${ES_USERNAME:-}" && ES_USERNAME=""
  is_placeholder "${ES_PASSWORD:-}" && ES_PASSWORD=""

  local default_host="https://localhost:9200"
  (( LOCAL_ES )) && default_host="https://elasticsearch:9200"
  prompt ES_HOST "Elasticsearch URL (ES_HOST)" "$default_host"
  prompt ES_USERNAME "Elasticsearch username" "elastic"
  prompt_secret ES_PASSWORD "Elasticsearch password"
  require_value ES_HOST
  require_value ES_PASSWORD

  # Index patterns are not asked for: the defaults match a standard Elastic Agent
  # install. The summary lists them so they can be checked and edited in .env.
  : "${ES_PROCESS_INDEX:=.ds-logs-endpoint.events.process-default-*}"
  : "${ES_NETWORK_INDEX:=.ds-logs-endpoint.events.network-default-*}"
  : "${ES_DISCOVERY_INDEX:=logs-endpoint.events.process-*}"
  : "${ES_METADATA_INDEX:=logs-endpoint.events.process-*,logs-endpoint.events.network-*}"
  : "${ES_ALERTS_INDEX:=.internal.alerts-security.alerts-default-*}"

  local key
  for key in ES_HOST ES_USERNAME ES_PASSWORD "${INDEX_KEYS[@]}"; do
    env_set "$ENV_FILE" "$key" "${!key}"
  done
  ok "Wrote .env"
  apply_tls_settings

  if (( LOCAL_ES )); then
    info "Bundled Elasticsearch is not running yet; skipping connectivity check"
  else
    connect_es
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
    # Bind address, port, and TLS always follow this run, so the agent never
    # keeps an older, weaker TLS setting or another install mode's CA path.
    [[ "$(env_get "$TRIAGE_ENV_FILE" HOST)" == "$listen_in_env" ]] || env_set "$TRIAGE_ENV_FILE" HOST "$listen_in_env"
    [[ "$(env_get "$TRIAGE_ENV_FILE" PORT)" == "$TRIAGE_PORT" ]] || env_set "$TRIAGE_ENV_FILE" PORT "$TRIAGE_PORT"
    [[ "$(env_get "$TRIAGE_ENV_FILE" ELASTIC_VERIFY_SSL)" == "$ES_VERIFY_CERTS" ]] \
      || env_set "$TRIAGE_ENV_FILE" ELASTIC_VERIFY_SSL "$ES_VERIFY_CERTS"
    if [[ -n "$ssl_cert_file" ]]; then
      [[ "$(env_get "$TRIAGE_ENV_FILE" SSL_CERT_FILE)" == "$ssl_cert_file" ]] \
        || env_set "$TRIAGE_ENV_FILE" SSL_CERT_FILE "$ssl_cert_file"
    else
      env_del "$TRIAGE_ENV_FILE" SSL_CERT_FILE
    fi
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

# ── Greenbone add-on configuration ───────────────────────────────────────────
# The push script reads ES_CA_CERTS; it must be an absolute path because the
# timer runs it from the add-on directory.
greenbone_ca_value() {
  if [[ "$ES_VERIFY_CERTS" == "true" && -n "${ES_CA_CERT:-}" ]]; then
    ca_cert_path
  fi
}

# The push runs on the host. The bundled Elasticsearch's "elasticsearch" name only
# resolves inside Docker, but its port is published on the host.
greenbone_es_host() {
  if (( LOCAL_ES )); then
    printf 'https://localhost:9200'
  else
    printf '%s' "$ES_HOST"
  fi
}

configure_greenbone() {
  step "Greenbone add-on configuration (addons/greenbone/.env)"
  local ca
  ca="$(greenbone_ca_value)"
  if [[ -f "$GREENBONE_ENV_FILE" && $RECONFIGURE -eq 0 ]]; then
    ok "Using existing add-on .env (pass --reconfigure to change it)"
    # TLS always follows this run, like the other add-ons.
    [[ "$(env_get "$GREENBONE_ENV_FILE" ES_VERIFY_CERTS)" == "$ES_VERIFY_CERTS" ]] \
      || env_set "$GREENBONE_ENV_FILE" ES_VERIFY_CERTS "$ES_VERIFY_CERTS"
    if [[ -n "$ca" ]]; then
      [[ "$(env_get "$GREENBONE_ENV_FILE" ES_CA_CERTS)" == "$ca" ]] || env_set "$GREENBONE_ENV_FILE" ES_CA_CERTS "$ca"
    else
      env_del "$GREENBONE_ENV_FILE" ES_CA_CERTS
    fi
    return
  fi

  echo "  Elasticsearch settings are reused from the detection pipeline. Scan results go"
  echo "  to the gvm-vulnerabilities index, so that account needs write access to it."
  prompt GVM_SOCKET "Path to Greenbone's gvmd socket" "${GVM_SOCKET:-$GVM_DEFAULT_SOCKET}"
  if (( ! DRY_RUN )) && [[ ! -S "$GVM_SOCKET" ]] && ! sudo test -S "$GVM_SOCKET" 2>/dev/null; then
    warn "No socket at $GVM_SOCKET. Find it with: sudo find / -name gvmd.sock 2>/dev/null"
  fi
  prompt GVM_USERNAME "Greenbone username" "admin"
  prompt_secret GVM_PASSWORD "Greenbone password"
  require_value GVM_PASSWORD

  if (( DRY_RUN )); then
    printf '  [DRY ] write %s\n' "${GREENBONE_ENV_FILE#"$REPO_ROOT"/}"
  else
    local tmp
    tmp="$(mktemp "$GREENBONE_ENV_FILE.XXXXXX")"
    {
      echo "# Generated by deploy.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "# Full option list: addons/greenbone/README.md"
      echo
      echo "GVM_SOCKET=$(escape_env "$GVM_SOCKET")"
      echo "GVM_USERNAME=$(escape_env "$GVM_USERNAME")"
      echo "GVM_PASSWORD=$(escape_env "$GVM_PASSWORD")"
      echo
      echo "ES_HOST=$(escape_env "$(greenbone_es_host)")"
      echo "ES_USERNAME=$(escape_env "${ES_USERNAME:-}")"
      echo "ES_PASSWORD=$(escape_env "${ES_PASSWORD:-}")"
      echo "ES_INDEX=gvm-vulnerabilities"
      echo "ES_VERIFY_CERTS=$ES_VERIFY_CERTS"
      [[ -n "$ca" ]] && echo "ES_CA_CERTS=$(escape_env "$ca")"
      echo
      echo "STATE_FILE=$(escape_env "$GREENBONE_DIR/state/last_run")"
      echo "LOG_FILE=$(escape_env "$REPO_ROOT/logs/greenbone-push.log")"
    } >"$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$GREENBONE_ENV_FILE"
  fi
  ok "Wrote add-on .env (TLS verification: $ES_VERIFY_CERTS)"
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

# Run the Greenbone push as root: gvmd's socket is root-owned in the Docker Compose install.
greenbone_push_cmd() {
  printf '%s %s --env-file %s' "$GREENBONE_VENV_DIR/bin/python" "$GREENBONE_DIR/gvm_siem_push.py" "$GREENBONE_ENV_FILE"
}

install_greenbone_venv() {
  step "Installing Greenbone add-on (venv)"
  make_venv "$GREENBONE_VENV_DIR"
  run "$GREENBONE_VENV_DIR/bin/python" -m pip install --quiet -r "$GREENBONE_DIR/requirements.txt"
  run mkdir -p "$GREENBONE_DIR/state" "$REPO_ROOT/logs"
  ok "Installed Greenbone add-on dependencies"
  (( DRY_RUN )) && return
  # A dry run logs in to Greenbone and reads every task's latest report, sending nothing.
  info "Checking the Greenbone connection with a dry run (needs sudo; sends nothing)"
  local out
  if out="$(sudo "$GREENBONE_VENV_DIR/bin/python" "$GREENBONE_DIR/gvm_siem_push.py" \
      --env-file "$GREENBONE_ENV_FILE" --dry-run 2>&1)"; then
    ok "Greenbone dry run passed"
  else
    warn "Greenbone dry run failed: $(grep -m1 ERROR <<<"$out" || tail -1 <<<"$out")"
    warn "Fix addons/greenbone/.env, then check again with: sudo $(greenbone_push_cmd) --dry-run"
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
ExecStart=$VENV_DIR/bin/python -u $REPO_ROOT/engine/realtime_service.py
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

# A oneshot service plus a timer: the push runs once a day, not as a daemon.
install_greenbone_timer() {
  step "systemd: $GREENBONE_TIMER"
  if ! unit_owned_or_absent "$GREENBONE_SERVICE" "$GREENBONE_DIR"; then
    warn "Left $GREENBONE_SERVICE unchanged"
    return
  fi
  local service timer
  service="$(cat <<EOF
[Unit]
Description=Push Greenbone scan results to Elasticsearch (SOC-in-a-Box add-on)
Documentation=https://github.com/cylab-africa/SOC-in-a-Box-ELK-ML-AgenticAI-
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
# Runs as root: the gvmd socket is root-owned in the Greenbone Docker Compose install.
WorkingDirectory=$GREENBONE_DIR
ExecStart=$(greenbone_push_cmd)
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gvm-siem-push
EOF
)"
  timer="$(cat <<EOF
[Unit]
Description=Daily Greenbone results push (SOC-in-a-Box add-on)

[Timer]
OnCalendar=$GREENBONE_SCHEDULE
Persistent=true
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
EOF
)"
  if (( DRY_RUN )); then
    printf '  [DRY ] write /etc/systemd/system/%s:\n' "$GREENBONE_SERVICE"
    sed 's/^/           /' <<<"$service"
    printf '  [DRY ] write /etc/systemd/system/%s:\n' "$GREENBONE_TIMER"
    sed 's/^/           /' <<<"$timer"
  else
    printf '%s\n' "$service" | sudo tee "/etc/systemd/system/$GREENBONE_SERVICE" >/dev/null
    printf '%s\n' "$timer" | sudo tee "/etc/systemd/system/$GREENBONE_TIMER" >/dev/null
  fi
  run sudo systemctl daemon-reload
  run sudo systemctl enable --now "$GREENBONE_TIMER"
  ok "$GREENBONE_TIMER enabled ($GREENBONE_SCHEDULE; logs: journalctl -u $GREENBONE_SERVICE)"
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
# The index patterns are not asked for during install; list them here so the
# user can check them against the cluster and edit .env if they differ.
summary_data_sources() {
  local key value auth_flag=""
  echo
  echo "  Data sources the engine reads (index patterns in .env):"
  for key in "${INDEX_KEYS[@]}"; do
    value="$(env_get "$ENV_FILE" "$key")"
    printf '    %-20s %s\n' "$key" "${value:-${!key:-}}"
  done
  if [[ "$ES_VERIFY_CERTS" == "false" ]]; then
    auth_flag="-k "
  elif [[ -n "${ES_CA_CERT:-}" ]]; then
    auth_flag="--cacert $ES_CA_CERT "
  fi
  echo "  These are the standard Elastic Agent names. Check each one matches an index on"
  echo "  your cluster (list them with the command below). If one differs, edit .env and"
  echo "  restart the detection service."
  echo "    curl ${auth_flag}-u ${ES_USERNAME:-USER} \"$ES_HOST/_cat/indices/*endpoint*,*system*?h=index&expand_wildcards=all\""
}

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
  echo "  Greenbone add-on:     $WITH_GREENBONE"
  if [[ "$WITH_GREENBONE" == "yes" ]]; then
    echo "    Results index:      gvm-vulnerabilities (add it as a data view in Kibana)"
    if (( INSTALL_SYSTEMD )) && have_systemd; then
      echo "    Schedule:           daily ($GREENBONE_SCHEDULE); see: systemctl list-timers $GREENBONE_TIMER"
      echo "    Push now:           sudo systemctl start $GREENBONE_SERVICE"
    else
      echo "    No timer installed. Add to root's crontab (sudo crontab -e):"
      echo "      0 6 * * * $(greenbone_push_cmd)"
    fi
  fi
  summary_data_sources
  if [[ "$MODE" == "venv" ]]; then
    echo
    echo "  Sanity checks (see docs/installation.md, Step 3):"
    echo "    .venv/bin/python engine/main.py --list-jobs"
    echo "    .venv/bin/python engine/push_all_anomalies.py --dry-run"
    if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
      echo "    addons/siem-maintenance/.venv/bin/python addons/siem-maintenance/Agent-SIEM-maintenance/maintenance_service.py --once-poll"
    fi
    if (( ! INSTALL_SYSTEMD )) || ! have_systemd; then
      echo
      echo "  No systemd units installed. Start manually:"
      echo "    .venv/bin/python engine/realtime_service.py"
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
intro() {
  cat <<EOF
SOC-in-a-Box installer ($REPO_ROOT)

This script sets up SOC-in-a-Box on this machine. It will:
  1. Check that this machine has what it needs (Python 3.10+ or Docker, and curl).
  2. Ask which optional add-ons you want.
  3. Ask for your Elasticsearch address and login, save them in .env, and test the
     connection.
  4. Install the detection engine and the add-ons you chose.
  5. Start them as background services that keep running after you log out.
At the end it lists the data sources the engine will read, for you to check.

It only talks to your own Elasticsearch. It is safe to run again, and
./deploy.sh --dry-run shows every step without changing anything.
EOF
  (( DRY_RUN )) && echo "DRY RUN: no changes will be made"
  return 0
}

main() {
  intro
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
  [[ "$WITH_GREENBONE" == "yes" ]] && configure_greenbone

  if [[ "$MODE" == "docker" ]]; then
    deploy_docker
    # Greenbone's push reads gvmd's socket on this host, so it runs from a host venv and timer.
    if [[ "$WITH_GREENBONE" == "yes" ]]; then
      install_greenbone_venv
      if (( INSTALL_SYSTEMD )) && have_systemd; then
        install_greenbone_timer
      fi
    fi
  else
    install_detection_venv
    if [[ "$WITH_MAINTENANCE" == "yes" && $MAINTENANCE_WIZARD -eq 0 ]]; then
      install_maintenance_venv
    fi
    [[ "$WITH_TRIAGE" == "yes" ]] && install_triage_venv
    [[ "$WITH_GREENBONE" == "yes" ]] && install_greenbone_venv
    if (( INSTALL_SYSTEMD )) && have_systemd; then
      install_detection_unit
      if [[ "$WITH_MAINTENANCE" == "yes" && $MAINTENANCE_WIZARD -eq 0 ]]; then
        install_maintenance_unit
      fi
      if [[ "$WITH_TRIAGE" == "yes" ]]; then
        install_triage_unit
      fi
      if [[ "$WITH_GREENBONE" == "yes" ]]; then
        install_greenbone_timer
      fi
    elif (( INSTALL_SYSTEMD )); then
      warn "systemd not available; skipping service units"
    fi
  fi
  summary
}

main
