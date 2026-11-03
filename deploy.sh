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
#   ./deploy.sh --only greenbone         add one add-on to an existing install
#   ./deploy.sh --mode docker            run under Docker Compose instead of venv + systemd
#   ES_HOST=... ES_API_KEY=... ./deploy.sh --non-interactive --with-maintenance
#   (or ES_USERNAME=... ES_PASSWORD=... instead of ES_API_KEY)
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
# When the weekly push runs: Sunday 06:00 (local time) unless overridden, so
# scans that run on Saturday have finished.
GREENBONE_DAY="${GREENBONE_DAY:-Sun}"     # Mon..Sun
GREENBONE_TIME="${GREENBONE_TIME:-06:00}" # HH:MM
# The same as a systemd OnCalendar expression.
GREENBONE_SCHEDULE="${GREENBONE_SCHEDULE:-$GREENBONE_DAY *-*-* $GREENBONE_TIME:00}"
# gvmd's socket in the Greenbone Community Edition Docker Compose install.
GVM_DEFAULT_SOCKET="/var/lib/docker/volumes/greenbone-community-edition_gvmd_socket_vol/_data/gvmd.sock"
# Where a source / package install of Greenbone puts it.
GVM_OTHER_SOCKETS=(/run/gvmd/gvmd.sock /var/run/gvmd/gvmd.sock /run/gvm/gvmd.sock /var/run/gvm/gvmd.sock)
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
ONLY=""                     # maintenance | triage | greenbone: add just that add-on
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
  --only ADD-ON            Add (or redo) just one add-on on an existing install:
                           maintenance, triage or greenbone. Reuses the
                           Elasticsearch settings in .env; does not touch the
                           detection engine or the other add-ons.
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
                           Elasticsearch once a week (Sunday 06:00).
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
                           (ES_HOST, ES_API_KEY or ES_USERNAME + ES_PASSWORD,
                           GC_ALERT_WEBHOOK, ...). Add-ons can have their own
                           login: MAINTENANCE_ES_API_KEY, TRIAGE_ES_API_KEY,
                           GREENBONE_ES_API_KEY (or *_ES_USERNAME + *_ES_PASSWORD).
                           Or set ES_ADMIN_USERNAME + ES_ADMIN_PASSWORD to have
                           every part's API key created (the admin login is not saved)
  --reconfigure            Re-ask settings even if .env files already exist

Other:
  --dry-run                Print every action without changing anything
  -h, --help               Show this help
EOF
}

# Kept so the summary can print the command that repeats this install.
DEPLOY_ARGS=("$@")
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-maintenance)   WITH_MAINTENANCE="yes" ;;
    --no-maintenance)     WITH_MAINTENANCE="no" ;;
    --maintenance-wizard) MAINTENANCE_WIZARD=1; WITH_MAINTENANCE="yes" ;;
    --with-triage)        WITH_TRIAGE="yes" ;;
    --no-triage)          WITH_TRIAGE="no" ;;
    --with-greenbone)     WITH_GREENBONE="yes" ;;
    --no-greenbone)       WITH_GREENBONE="no" ;;
    --only)               ONLY="${2:?--only needs an add-on: maintenance, triage or greenbone}"; shift ;;
    --only=*)             ONLY="${1#*=}" ;;
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

if [[ -n "$ONLY" ]]; then
  case "$ONLY" in
    maintenance) WITH_MAINTENANCE="yes"; WITH_TRIAGE="no"; WITH_GREENBONE="no" ;;
    triage)      WITH_MAINTENANCE="no"; WITH_TRIAGE="yes"; WITH_GREENBONE="no" ;;
    greenbone)   WITH_MAINTENANCE="no"; WITH_TRIAGE="no"; WITH_GREENBONE="yes" ;;
    *) echo "--only must be maintenance, triage or greenbone (got: $ONLY)" >&2; exit 2 ;;
  esac
fi
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
  C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'; C_VALUE=$'\e[1;36m'; C_HEAD=$'\e[1;34m'
else
  C_OK=""; C_FAIL=""; C_WARN=""; C_INFO=""; C_OFF=""
  C_BOLD=""; C_DIM=""; C_VALUE=""; C_HEAD=""
fi
if [[ "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" =~ [Uu][Tt][Ff]-?8 ]]; then
  S_OK="✔"; S_FAIL="✘"; S_WARN="!"; S_SKIP="–"; S_RULE="═"; S_LINE="─"
else
  S_OK="+"; S_FAIL="x"; S_WARN="!"; S_SKIP="-"; S_RULE="="; S_LINE="-"
fi
RULE="$(printf "%72s" "" | sed "s/ /$S_RULE/g")"

# Every warning and failure is kept so the summary can list them in one place.
ISSUES=()
ok()   { printf '  [%s OK %s] %s\n' "$C_OK" "$C_OFF" "$*"; }
fail() { ISSUES+=("$*"); printf '  [%sFAIL%s] %s\n' "$C_FAIL" "$C_OFF" "$*" >&2; }
warn() { ISSUES+=("$*"); printf '  [%sWARN%s] %s\n' "$C_WARN" "$C_OFF" "$*"; }
info() { printf '  [%sINFO%s] %s\n' "$C_INFO" "$C_OFF" "$*"; }
die()  { fail "$*"; exit 1; }

# The install runs in parts (the detection engine, then one per add-on), each
# with its own numbered steps: "PART 2 of 4", then "Step 1/4", "Step 2/4", ...
PART_NUM=0; PART_TOTAL=0; PART_TITLE=""; PART_ISSUES=0; STEP_NUM=0; STEP_TOTAL=0
banner() {
  printf '\n\n%s%s\n  %s\n%s%s\n' "${2:-$C_HEAD}" "$RULE" "$1" "$RULE" "$C_OFF"
}
# begin_part "title" steps [numbered=1]
begin_part() {
  PART_TITLE="$1"; STEP_TOTAL="$2"; STEP_NUM=0; PART_ISSUES=${#ISSUES[@]}
  if (( ${3:-1} )); then
    PART_NUM=$((PART_NUM + 1))
    banner "PART $PART_NUM of $PART_TOTAL  ·  $1"
  else
    banner "$1"
  fi
}
step() {
  STEP_NUM=$((STEP_NUM + 1))
  printf '\n%s%s%s Step %d/%d  %s%s\n' "$C_BOLD" "$S_LINE" "$S_LINE" "$STEP_NUM" "$STEP_TOTAL" "$*" "$C_OFF"
}
end_part() {
  local new=$(( ${#ISSUES[@]} - PART_ISSUES ))
  if (( new == 0 )); then
    printf '\n  %s%s %s: %d of %d steps complete%s\n' "$C_OK" "$S_OK" "$PART_TITLE" "$STEP_NUM" "$STEP_TOTAL" "$C_OFF"
  else
    printf '\n  %s%s %s: %d of %d steps done, with %d warning(s) (listed again at the end)%s\n' \
      "$C_WARN" "$S_WARN" "$PART_TITLE" "$STEP_NUM" "$STEP_TOTAL" "$new" "$C_OFF"
  fi
}

# What each component ended up as, for the summary: ok | warn | fail, plus a note.
declare -A STATUS=() STATUS_NOTE=()
set_status() {
  STATUS[$1]="$2"; STATUS_NOTE[$1]="$3"
  (( DRY_RUN )) && [[ "$2" != "skip" ]] && STATUS_NOTE[$1]="$3 (dry run: would be)"
  return 0
}

# Run a command, or only print it under --dry-run.
run() {
  if (( DRY_RUN )); then
    printf '  [DRY ] %s\n' "$*"
  else
    "$@"
  fi
}

# Questions are printed as: the question (bold), an optional explanation (dim,
# may span several lines), then an input line that says what Enter does.
ask_header() {
  local msg="$1" help="${2:-}" line
  echo
  printf '  %s%s%s\n' "$C_BOLD" "$msg" "$C_OFF"
  if [[ -n "$help" ]]; then
    while IFS= read -r line; do
      printf '  %s%s%s\n' "$C_DIM" "$line" "$C_OFF"
    done <<<"$help"
  fi
  return 0
}

# prompt VAR "question" "default" ["explanation"]  — uses $VAR from the environment if set.
prompt() {
  local var="$1" msg="$2" def="${3:-}" help="${4:-}" cur="${!1:-}" reply
  [[ -n "$cur" ]] && def="$cur"
  if (( NON_INTERACTIVE )); then
    printf -v "$var" '%s' "$def"
    return
  fi
  ask_header "$msg" "$help"
  if [[ -n "$def" ]]; then
    read -r -p "  Press Enter for ${C_VALUE}${def}${C_OFF}, or type your own: " reply
  else
    read -r -p "  Type it here (press Enter to leave it empty): " reply
  fi
  printf -v "$var" '%s' "${reply:-$def}"
}

# prompt_secret VAR "question" ["explanation"] ["what Enter does"]
# Typing is hidden. Enter keeps an existing value, or does what the 4th argument says.
prompt_secret() {
  local var="$1" msg="$2" help="${3:-}" enter="${4:-}" cur="${!1:-}" reply
  if (( NON_INTERACTIVE )); then
    return
  fi
  [[ -z "$enter" && -n "$cur" ]] && enter="press Enter to keep the current one"
  ask_header "$msg" "$help"
  if [[ -n "$enter" ]]; then
    read -r -s -p "  Type it (hidden as you type), or $enter: " reply
  else
    read -r -s -p "  Type it (hidden as you type): " reply
  fi
  echo
  [[ -n "$reply" ]] && printf -v "$var" '%s' "$reply"
  return 0
}

# confirm "question" default(Y|N) ["explanation"]
confirm() {
  local msg="$1" def="${2:-N}" help="${3:-}" reply
  if (( NON_INTERACTIVE )); then
    [[ "$def" == "Y" ]]
    return
  fi
  ask_header "$msg" "$help"
  if [[ "$def" == "Y" ]]; then
    read -r -p "  Press Enter for ${C_VALUE}yes${C_OFF}, or type n for no: " reply; reply="${reply:-Y}"
  else
    read -r -p "  Type y for yes, or press Enter for ${C_VALUE}no${C_OFF}: " reply; reply="${reply:-N}"
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
# Print the path of a running Greenbone's gvmd socket, or nothing. The Docker
# install's socket is under a root-only directory, so look with sudo when that
# works without a password prompt.
find_gvm_socket() {
  local path
  for path in ${GVM_SOCKET:+"$GVM_SOCKET"} "$GVM_DEFAULT_SOCKET" "${GVM_OTHER_SOCKETS[@]}"; do
    if [[ -S "$path" ]] || sudo -n test -S "$path" 2>/dev/null; then
      printf '%s' "$path"
      return 0
    fi
  done
  # A Docker install under another project name.
  path="$(sudo -n sh -c 'ls -d /var/lib/docker/volumes/*gvmd_socket*/_data/gvmd.sock' 2>/dev/null | head -n 1 || true)"
  [[ -n "$path" ]] && printf '%s' "$path"
  return 0
}

preflight() {
  step "Check that this machine has what the install needs"
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
  ok "curl available"

  if [[ -n "$ONLY" ]]; then
    step "Check the earlier install this add-on builds on"
    check_base_install
  else
    step "Choose the optional add-ons"
  fi
  choose_maintenance
  choose_triage
  choose_greenbone
  [[ -n "$ONLY" ]] || show_plan
}

# --only adds one add-on to an existing install, so the detection engine's
# Elasticsearch settings must already be in .env. Load them and test them.
check_base_install() {
  load_existing_env "$ENV_FILE" ES_HOST ES_API_KEY ES_USERNAME ES_PASSWORD "${INDEX_KEYS[@]}"
  if [[ ! -f "$ENV_FILE" ]] || is_placeholder "${ES_HOST:-}"; then
    die "SOC-in-a-Box is not set up yet. Run ./deploy.sh first; then add the add-on with ./deploy.sh --only $ONLY"
  fi
  ok "Using the Elasticsearch settings already in .env ($ES_HOST)"
  apply_tls_settings
  connect_es
}

choose_maintenance() {
  if [[ -z "$WITH_MAINTENANCE" ]]; then
    if confirm "Optional add-on: SIEM Maintenance Agent. Install it?" N \
        "Watches the health of your Elasticsearch cluster and whether logs are still
arriving, sends a daily report to Google Chat, and can fix common problems."; then
      WITH_MAINTENANCE="yes"
    else
      WITH_MAINTENANCE="no"
    fi
  fi
  if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
    [[ -f "$ADDON_AGENT_DIR/maintenance_service.py" ]] \
      || die "Add-on not found at $ADDON_DIR (clone the full repository)"
    if (( MAINTENANCE_WIZARD )); then
      (( NON_INTERACTIVE )) && die "--maintenance-wizard is interactive; drop --non-interactive"
      [[ "$MODE" == "venv" ]] || die "--maintenance-wizard only supports --mode venv"
    fi
    ok "Maintenance add-on: enabled"
  elif [[ -z "$ONLY" ]]; then
    info "Maintenance add-on: skipped (add it later with: ./deploy.sh --only maintenance)"
  fi
}

choose_triage() {
  if [[ -z "$WITH_TRIAGE" ]]; then
    if confirm "Optional add-on: Alert Triage Agent. Install it?" N \
        "Investigates Elastic Security alerts for you: gathers related events and IP
reputation, then says whether each alert looks like a real attack or a false
alarm, and why. Has a web page and an API."; then
      WITH_TRIAGE="yes"
    else
      WITH_TRIAGE="no"
    fi
  fi
  if [[ "$WITH_TRIAGE" == "yes" ]]; then
    [[ -f "$TRIAGE_DIR/server.py" ]] || die "Add-on not found at $TRIAGE_DIR (clone the full repository)"
    ok "Triage add-on: enabled (listening on $TRIAGE_LISTEN:$TRIAGE_PORT)"
  elif [[ -z "$ONLY" ]]; then
    info "Triage add-on: skipped (add it later with: ./deploy.sh --only triage)"
  fi
}

# The add-on does not install Greenbone: it sends the results of one already
# running on this server. When the answer is yes, check for it, and if it is
# missing say how to install it and how to add the add-on afterwards.
GREENBONE_MISSING=0
choose_greenbone() {
  GVM_FOUND_SOCKET="$(find_gvm_socket)"
  if [[ -z "$WITH_GREENBONE" ]]; then
    if confirm "Optional add-on: Greenbone scan results. Install it?" N \
        "Sends the results of Greenbone (OpenVAS) vulnerability scans to Elasticsearch
once a week, marked new, fixed or unchanged since the previous scan. Greenbone
itself must already be installed on this server; if you say yes, this script
checks that it is."; then
      WITH_GREENBONE="yes"
    else
      WITH_GREENBONE="no"
    fi
  fi
  if [[ "$WITH_GREENBONE" == "yes" && -z "$GVM_FOUND_SOCKET" ]]; then
    greenbone_install_help
    local enter_does="the rest of the install carries on without this add-on."
    [[ -n "$ONLY" ]] && enter_does="this run stops, and nothing is changed."
    (( NON_INTERACTIVE )) || ask_gvm_socket "$enter_does"
    if [[ -z "$GVM_FOUND_SOCKET" ]]; then
      WITH_GREENBONE="no"
      GREENBONE_MISSING=1
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
    if [[ -n "$GVM_FOUND_SOCKET" ]]; then
      ok "Greenbone add-on: enabled (Greenbone found: $GVM_FOUND_SOCKET)"
    else
      ok "Greenbone add-on: enabled"
    fi
  elif [[ -z "$ONLY" ]] && (( ! GREENBONE_MISSING )); then
    info "Greenbone add-on: skipped (add it later with: ./deploy.sh --only greenbone)"
  fi
}

gvm_socket_at() {
  [[ -S "$1" ]] || sudo test -S "$1" 2>/dev/null
}

# Greenbone may run with its socket in a non-standard place. Ask for the path
# and only accept it when a socket is really there, so a "yes" can never carry
# on without Greenbone. Enter gives up.
ask_gvm_socket() {
  local path
  ask_header "Only if Greenbone IS installed here, with its socket in another place: where is it?" \
    "Find it with: sudo find / -name gvmd.sock 2>/dev/null
If Greenbone is not installed, just press Enter: $1"
  while true; do
    read -r -p "  Path to gvmd.sock, or press Enter to skip: " path
    [[ -z "$path" ]] && return 0
    if gvm_socket_at "$path"; then
      GVM_FOUND_SOCKET="$path"
      ok "Found Greenbone's socket at $path"
      return 0
    fi
    printf '  %sThere is no Greenbone socket at %s. Check the path, or press Enter to skip.%s\n' \
      "$C_WARN" "$path" "$C_OFF"
  done
}

greenbone_install_help() {
  local setup="setup-and-start-greenbone-community-edition.sh"
  warn "Greenbone is not installed on this server (no gvmd socket found), so this add-on cannot be set up yet."
  echo "  This add-on sends Greenbone's scan results to Elasticsearch; it does not install"
  echo "  Greenbone itself. To install Greenbone Community Edition, run Greenbone's own"
  echo "  setup script on this server."
  if ! command -v docker >/dev/null; then
    printf '  %sIt needs Docker, which is not installed here. Install Docker first:%s\n' "$C_WARN" "$C_OFF"
    echo "    https://docs.docker.com/engine/install/"
    echo "  Then run:"
  else
    echo "  Run:"
  fi
  printf '    %scurl -f -O -L https://greenbone.github.io/docs/latest/_static/%s%s\n' "$C_VALUE" "$setup" "$C_OFF"
  printf '    %schmod u+x %s%s\n' "$C_VALUE" "$setup" "$C_OFF"
  printf '    %s./%s%s\n' "$C_VALUE" "$setup" "$C_OFF"
  echo "  It asks for a password for Greenbone's admin user, then downloads the"
  echo "  vulnerability feed, which takes from several minutes to a few hours."
  echo "  Guide: https://greenbone.github.io/docs/latest/22.4/container/"
  echo "  Once Greenbone is running, add just this add-on (the rest stays as it is) with:"
  printf '    %s./deploy.sh --only greenbone%s\n' "$C_VALUE" "$C_OFF"
}

# Say plainly what the answers above mean, before anything is installed: the
# detection engine always comes next, whatever was answered about the add-ons.
show_plan() {
  local greenbone_no="you said no"
  (( GREENBONE_MISSING )) && greenbone_no="Greenbone is not installed here yet: see the steps above"
  echo
  printf '  %sThis is what will be installed:%s\n' "$C_BOLD" "$C_OFF"
  plan_line yes "Detection engine" "always: the core that the add-ons build on" ""
  plan_line "$WITH_MAINTENANCE" "SIEM Maintenance Agent" "you said yes" "you said no"
  plan_line "$WITH_TRIAGE" "Alert Triage Agent" "you said yes" "you said no"
  plan_line "$WITH_GREENBONE" "Greenbone scan results" "you said yes" "$greenbone_no"
}

# plan_line yes|no LABEL "note when yes" "note when no"
plan_line() {
  if [[ "$1" == "yes" ]]; then
    printf '    %s%s %-24s yes%s  (%s)\n' "$C_OK" "$S_OK" "$2" "$C_OFF" "$3"
  else
    printf '    %s%s %-24s no   (%s)%s\n' "$C_DIM" "$S_SKIP" "$2" "$4" "$C_OFF"
  fi
}

# ── Elasticsearch connectivity ───────────────────────────────────────────────
# Credentials go to curl on stdin so they never appear in the process list, and
# are only sent over a verified TLS connection unless --insecure-tls is given.
# The Elasticsearch login as a curl -K config line: the API key when one is set,
# otherwise the username and password. Fed on stdin, so it never shows in ps.
es_curl_auth() {
  if [[ -n "${ES_API_KEY:-}" ]]; then
    printf 'header = "Authorization: ApiKey %s"\n' "${ES_API_KEY//\"/\\\"}"
  elif [[ -n "${ES_USERNAME:-}" ]]; then
    printf 'user = "%s:%s"\n' "${ES_USERNAME//\"/\\\"}" "${ES_PASSWORD//\"/\\\"}"
  elif [[ -n "${ES_ADMIN_USERNAME:-}" ]]; then
    # Only while API keys are being created: the admin login is never saved.
    printf 'user = "%s:%s"\n' "${ES_ADMIN_USERNAME//\"/\\\"}" "${ES_ADMIN_PASSWORD//\"/\\\"}"
  fi
}

# Returns 0 when connected, 2 when the cluster answers but its certificate is
# not trusted, and 1 for anything else.
es_check() {
  local host="$1" out flags=(-sS --max-time 10)
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
  local cfg rc=0
  cfg="$(es_curl_auth)"
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
  if [[ "$out" == *security_exception* && "$out" == *"is unauthorized"* ]]; then
    fail "Elasticsearch at $host accepted the login, but it lacks the monitor cluster privilege (see docs/configuration.md#elasticsearch-api-keys)"
  elif [[ "$out" == *security_exception* ]]; then
    if [[ -n "${ES_API_KEY:-}" ]]; then
      fail "Elasticsearch at $host rejected the API key (wrong, expired or revoked)"
    else
      fail "Elasticsearch at $host rejected the username or password"
    fi
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
# choice again (e.g. trusting worked but the hostname does not match). On any
# other failure, offer to type the address and login again rather than install
# an engine that cannot reach its data.
ES_CONNECTED=0
connect_es() {
  local rc attempts issues_before=${#ISSUES[@]}
  while true; do
    rc=0; attempts=0
    es_check "$ES_HOST" || rc=$?
    while (( rc == 2 && attempts < 3 )) && resolve_untrusted_cert "$ES_HOST"; do
      attempts=$((attempts + 1))
      apply_tls_settings
      rc=0
      es_check "$ES_HOST" || rc=$?
    done
    (( rc == 0 || NON_INTERACTIVE )) && break
    retry_es_login || break
  done
  if (( rc == 0 )); then
    ES_CONNECTED=1
    # Failures settled by the questions above are not problems any more.
    ISSUES=("${ISSUES[@]:0:issues_before}")
  else
    warn "Carrying on without a working connection: fix ES_HOST and the login (ES_API_KEY, or ES_USERNAME and ES_PASSWORD) in .env, then restart the engine"
  fi
  return 0
}

# After a failed connection: 0 = the login was typed again (test it again),
# 1 = carry on without a connection. Choosing to stop exits.
retry_es_login() {
  local choice
  ask_header "Could not connect to Elasticsearch at $ES_HOST. What would you like to do?" "1  Type the address and login again (recommended)
2  Carry on anyway: everything is installed, but the engine cannot work
   until .env has the right address and login
3  Stop here (your settings so far are kept in .env)
The address is the one Elasticsearch is reached on from this server, with
https:// and the port, e.g. https://10.0.0.5:9200. localhost only works when
Elasticsearch runs on this same server."
  read -r -p "  Press Enter for ${C_VALUE}1 (type them again)${C_OFF}, or type 2 or 3: " choice
  case "${choice:-1}" in
    1)
      prompt ES_HOST "Elasticsearch address" "" \
        "The full address, including https:// and the port, e.g. https://10.0.0.5:9200."
      require_value ES_HOST
      ask_es_login
      local key
      for key in ES_HOST ES_API_KEY ES_USERNAME ES_PASSWORD; do
        env_set "$ENV_FILE" "$key" "${!key}"
      done
      ok "Saved to .env; testing again"
      ;;
    2) return 1 ;;
    *) die "Stopped. Your settings so far are in .env; run ./deploy.sh again when ready." ;;
  esac
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
    # Printed, not recorded: the summary lists it once from ES_VERIFY_CERTS.
    printf '  [%sWARN%s] %s\n' "$C_WARN" "$C_OFF" "TLS verification disabled for the pipeline (ES_VERIFY_CERTS=false); lab use only"
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

# ── Elasticsearch logins ─────────────────────────────────────────────────────
# Each part can log in with an API key or a username and password. An API key is
# recommended: it carries only the privileges that part needs, and revoking it
# does not touch any user account. docs/configuration.md#elasticsearch-api-keys
# has a ready-made key for each part.
ES_KEY_HELP="The encoded value Elasticsearch shows once, when the key is created (one long
base64 string). Create one in Kibana: Stack Management > Security > API keys."

# An admin login, asked for only to create API keys. It lives in memory for this
# run and is never written to any file.
ES_ADMIN_USERNAME="${ES_ADMIN_USERNAME:-}"
ES_ADMIN_PASSWORD="${ES_ADMIN_PASSWORD:-}"
CREATE_KEYS=0

ask_admin_login() {
  [[ -n "$ES_ADMIN_USERNAME" && -n "$ES_ADMIN_PASSWORD" ]] && return 0
  if (( ! NON_INTERACTIVE )); then
    ask_header "Admin privileges are needed to create the API keys" \
      "Creating API keys needs an Elasticsearch user with admin privileges: the
manage_api_key privilege, plus every privilege the keys grant. The elastic
superuser has both. This login is used only now, to create the keys. It is not
saved anywhere: each part then logs in with its own key, limited to the SOC
analyst work it does."
  fi
  prompt ES_ADMIN_USERNAME "Admin username" "elastic"
  prompt_secret ES_ADMIN_PASSWORD "Admin password" "The password for that admin user."
  require_value ES_ADMIN_USERNAME
  require_value ES_ADMIN_PASSWORD
}

# Sets ES_API_KEY, or ES_USERNAME and ES_PASSWORD, for the detection engine.
# With CREATE_KEYS=1 both stay empty until create_engine_key runs after the
# connection test, which uses the admin login.
ask_es_login() {
  local method=1 reply
  if [[ -n "${ES_API_KEY:-}" ]]; then
    method=2
  elif [[ -n "${ES_PASSWORD:-}" ]]; then
    method=3
  fi
  if (( NON_INTERACTIVE )); then
    if [[ -n "${ES_API_KEY:-}" ]]; then method=2
    elif [[ -n "$ES_ADMIN_USERNAME" && -n "$ES_ADMIN_PASSWORD" ]]; then method=1
    else method=3
    fi
  else
    ask_header "How should SOC-in-a-Box log in to Elasticsearch?" \
      "1  Create API keys for me (recommended). You type an admin username and
   password once; each part gets its own key with only the privileges it needs,
   and the admin password is not saved
2  Use an API key I already created
3  Use a username and password (saved in .env)"
    read -r -p "  Press Enter for ${C_VALUE}${method}${C_OFF}, or type 1, 2 or 3: " reply
    method="${reply:-$method}"
  fi
  CREATE_KEYS=0
  case "$method" in
    1)
      # Asked again on a retry, in case the admin password was the problem.
      (( NON_INTERACTIVE )) || ES_ADMIN_PASSWORD=""
      ask_admin_login
      CREATE_KEYS=1
      ES_API_KEY=""; ES_USERNAME=""; ES_PASSWORD="" ;;
    2)
      prompt_secret ES_API_KEY "Elasticsearch API key for the detection engine" "$ES_KEY_HELP"
      require_value ES_API_KEY
      ES_USERNAME=""; ES_PASSWORD="" ;;
    *)
      prompt ES_USERNAME "Elasticsearch username" "${ES_USERNAME:-elastic}" \
        "The account the engine uses to read logs and write its alerts."
      prompt_secret ES_PASSWORD "Elasticsearch password" \
        "The password for that account."
      require_value ES_PASSWORD
      ES_API_KEY="" ;;
  esac
}

# The body of a create API key request for one part: its name, and a role that
# grants only what that part does. Index patterns for the engine come from .env.
api_key_body() {
  python3 - "$@" <<'PY'
import json
import sys

part, name, *extra = sys.argv[1:]
alerts = [".alerts-security.alerts-*", ".internal.alerts-security.alerts-*"]


def patterns(values):
    seen = []
    for value in values:
        for pattern in value.split(","):
            pattern = pattern.strip()
            if pattern and pattern not in seen:
                seen.append(pattern)
    return seen


if part == "engine":
    sources = ["logs-endpoint.events.*", ".ds-logs-endpoint.events.*",
               "logs-system.auth-*", ".ds-logs-system.auth-*", *alerts, *extra]
    role = {
        "cluster": ["monitor"],
        "indices": [
            {"names": patterns(sources), "privileges": ["read", "view_index_metadata"]},
            {"names": ["ml-anomalies-custom*", "ml-anomalies-correlated*", ".ml-anomalies-custom-*"],
             "privileges": ["read", "view_index_metadata", "create_index", "index"]},
        ],
    }
elif part == "triage":
    role = {
        "indices": [
            {"names": [*alerts, "logs-*", "filebeat-*", "winlogbeat-*", "auditbeat-*"],
             "privileges": ["read", "view_index_metadata"]},
        ],
    }
elif part == "maintenance":
    role = {
        "cluster": ["monitor", "monitor_ml", "monitor_transform", "monitor_watcher",
                    "monitor_snapshot", "read_ilm", "read_slm"],
        "indices": [
            {"names": ["*"], "privileges": ["monitor", "view_index_metadata"]},
            {"names": ["logs-*", ".ds-logs-*", ".ds-elastic-cloud-logs-*", ".monitoring-es-*",
                       ".ml-anomalies-*", "ml-anomalies-*"],
             "privileges": ["read"]},
        ],
    }
    if "fix" in extra:
        role["cluster"] += ["manage", "manage_ml", "manage_transform", "manage_watcher",
                            "manage_ilm", "manage_slm"]
        role["indices"].append({"names": ["*"], "privileges": ["manage", "delete_index"]})
elif part == "greenbone":
    role = {
        "cluster": ["monitor"],
        "indices": [
            {"names": ["gvm-vulnerabilities*"],
             "privileges": ["create_index", "index", "read", "view_index_metadata", "manage"]},
        ],
    }
else:
    sys.exit(f"unknown part: {part}")

print(json.dumps({
    "name": name,
    "metadata": {"created_by": "SOC-in-a-Box deploy.sh", "part": part},
    "role_descriptors": {f"soc_analyst_{part}": role},
}))
PY
}

# es_admin_request METHOD PATH BODY_FILE: call Elasticsearch with the admin login.
# Prints the body, then the HTTP status on its own last line.
es_admin_request() {
  local flags=(-sS -g --max-time 30 -X "$1" -w '\n%{http_code}' -H 'Content-Type: application/json'
               --data-binary "@$3")
  if [[ "$ES_VERIFY_CERTS" == "false" ]]; then
    flags+=(-k)
  elif [[ -n "${ES_CA_CERT:-}" ]]; then
    flags+=(--cacert "$(ca_cert_path)")
  fi
  printf 'user = "%s:%s"\n' "${ES_ADMIN_USERNAME//\"/\\\"}" "${ES_ADMIN_PASSWORD//\"/\\\"}" \
    | curl "${flags[@]}" -K - "$ES_HOST$2" 2>&1
}

# create_api_key PART VAR [fix]: create PART's API key with the admin login and
# store its encoded value in VAR. A key this script made earlier on this server
# for the same part is revoked first, so re-runs replace keys instead of adding.
create_api_key() {
  local part="$1" var="$2" name tmp out code key
  name="soc-in-a-box-$part-$(hostname -s 2>/dev/null || echo server)"
  if (( DRY_RUN )); then
    printf '  [DRY ] create API key %s\n' "$name"
    printf -v "$var" '%s' "dry-run-api-key"
    return 0
  fi
  tmp="$(mktemp)"
  printf '{"name": "%s"}' "$name" >"$tmp"
  es_admin_request DELETE /_security/api_key "$tmp" >/dev/null || true
  if [[ "$part" == "engine" ]]; then
    api_key_body engine "$name" "${ES_PROCESS_INDEX:-}" "${ES_NETWORK_INDEX:-}" \
      "${ES_DISCOVERY_INDEX:-}" "${ES_METADATA_INDEX:-}" "${ES_ALERTS_INDEX:-}" >"$tmp"
  else
    api_key_body "$part" "$name" "${3:-}" >"$tmp"
  fi
  out="$(es_admin_request POST /_security/api_key "$tmp")" || true
  rm -f "$tmp"
  code="${out##*$'\n'}"
  out="${out%$'\n'*}"
  if [[ "$code" == "200" ]]; then
    key="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["encoded"])' <<<"$out" 2>/dev/null || true)"
    if [[ -n "$key" ]]; then
      printf -v "$var" '%s' "$key"
      ok "Created API key $name (SOC analyst privileges for the $part only)"
      return 0
    fi
  fi
  case "$code" in
    401) fail "Could not create the $part API key: Elasticsearch rejected the admin username or password" ;;
    403) fail "Could not create the $part API key: the admin login is not allowed to create it (it needs manage_api_key and every privilege the key grants; the elastic superuser has them)" ;;
    *)   fail "Could not create the $part API key: ${out:0:200}" ;;
  esac
  return 1
}

# After the connection test with the admin login: create the engine's key, save
# it to .env, and check that the engine can connect with it.
create_engine_key() {
  (( CREATE_KEYS && ES_CONNECTED )) || return 0
  if create_api_key engine ES_API_KEY; then
    env_set "$ENV_FILE" ES_API_KEY "$ES_API_KEY"
    ok "Saved the engine's API key to .env (the admin password is not saved)"
    local rc=0
    es_check "$ES_HOST" || rc=$?
    (( rc == 0 )) || warn "The new API key did not connect; check docs/configuration.md#elasticsearch-api-keys"
    return 0
  fi
  (( NON_INTERACTIVE )) && die "Set ES_API_KEY, or ES_USERNAME and ES_PASSWORD, and run ./deploy.sh again"
  info "Choose another way for the engine to log in"
  CREATE_KEYS=0
  ES_ADMIN_USERNAME=""; ES_ADMIN_PASSWORD=""
  ask_es_login
  local key
  for key in ES_API_KEY ES_USERNAME ES_PASSWORD; do
    env_set "$ENV_FILE" "$key" "${!key}"
  done
  ES_CONNECTED=0
  connect_es
  create_engine_key
}

# ask_component_login PREFIX "who" PART [fix] sets PREFIX_ES_API_KEY,
# PREFIX_ES_USERNAME and PREFIX_ES_PASSWORD for an add-on: a key created now
# from the admin login, a key it already has, its own username and password, or
# the detection engine's login.
ask_component_login() {
  local key_var="${1}_ES_API_KEY" user_var="${1}_ES_USERNAME" pass_var="${1}_ES_PASSWORD"
  local who="$2" part="$3" fix="${4:-}" choice=4 reply
  [[ -n "$ES_ADMIN_USERNAME" && -n "$ES_ADMIN_PASSWORD" ]] && choice=1
  [[ -n "${!user_var:-}" ]] && choice=3
  [[ -n "${!key_var:-}" ]] && choice=2
  if (( ! NON_INTERACTIVE )); then
    ask_header "How should the $who log in to Elasticsearch?" \
      "1  Create its own API key (recommended): limited to what it needs, revoked
   without affecting anything else. Needs an admin login, used once, not saved
2  Use an API key I already created for it
3  Use its own username and password
4  Use the same login as the detection engine"
    read -r -p "  Press Enter for ${C_VALUE}${choice}${C_OFF}, or type 1, 2, 3 or 4: " reply
    choice="${reply:-$choice}"
  fi
  case "$choice" in
    1)
      ask_admin_login
      printf -v "$user_var" '%s' ""; printf -v "$pass_var" '%s' ""
      if ! create_api_key "$part" "$key_var" "$fix"; then
        (( NON_INTERACTIVE )) && die "Could not create the $part API key"
        warn "The $who will use the detection engine's login instead"
        printf -v "$key_var" '%s' "${ES_API_KEY:-}"
        printf -v "$user_var" '%s' "${ES_USERNAME:-}"
        printf -v "$pass_var" '%s' "${ES_PASSWORD:-}"
      fi ;;
    2)
      prompt_secret "$key_var" "Elasticsearch API key for the $who" "$ES_KEY_HELP"
      require_value "$key_var"
      printf -v "$user_var" '%s' ""; printf -v "$pass_var" '%s' "" ;;
    3)
      prompt "$user_var" "Elasticsearch username for the $who" "${!user_var:-}"
      prompt_secret "$pass_var" "Elasticsearch password for the $who"
      # Older --non-interactive installs set only the username and reused ES_PASSWORD.
      [[ -n "${!pass_var:-}" ]] || printf -v "$pass_var" '%s' "${ES_PASSWORD:-}"
      require_value "$user_var"; require_value "$pass_var"
      printf -v "$key_var" '%s' "" ;;
    *)
      printf -v "$key_var" '%s' "${ES_API_KEY:-}"
      printf -v "$user_var" '%s' "${ES_USERNAME:-}"
      printf -v "$pass_var" '%s' "${ES_PASSWORD:-}" ;;
  esac
}

# ── Detection pipeline configuration ─────────────────────────────────────────
configure_detection() {
  step "Elasticsearch address and login (saved in .env)"
  if [[ -f "$ENV_FILE" && $RECONFIGURE -eq 0 ]]; then
    load_existing_env "$ENV_FILE" ES_HOST ES_API_KEY ES_USERNAME ES_PASSWORD "${INDEX_KEYS[@]}"
    if ! is_placeholder "${ES_HOST:-}"; then
      ok "Using existing .env (pass --reconfigure to change it)"
      return
    fi
    info "No Elasticsearch settings saved yet (an earlier run stopped before they were entered)"
  fi

  if [[ ! -f "$ENV_FILE" ]]; then
    run cp "$REPO_ROOT/.env.example" "$ENV_FILE"
    run chmod 600 "$ENV_FILE"
  fi
  load_existing_env "$ENV_FILE" ES_HOST ES_API_KEY ES_USERNAME ES_PASSWORD "${INDEX_KEYS[@]}"
  is_placeholder "${ES_HOST:-}" && ES_HOST=""
  is_placeholder "${ES_USERNAME:-}" && ES_USERNAME=""
  is_placeholder "${ES_PASSWORD:-}" && ES_PASSWORD=""
  is_placeholder "${ES_API_KEY:-}" && ES_API_KEY=""

  local default_host="https://localhost:9200"
  (( LOCAL_ES )) && default_host="https://elasticsearch:9200"
  prompt ES_HOST "Elasticsearch address" "$default_host" \
    "The full address, including https:// and the port, e.g. https://10.0.0.5:9200.
Use localhost if Elasticsearch runs on this server."
  require_value ES_HOST
  ask_es_login

  # Index patterns are not asked for: the defaults match a standard Elastic Agent
  # install. The summary lists them so they can be checked and edited in .env.
  : "${ES_PROCESS_INDEX:=.ds-logs-endpoint.events.process-default-*}"
  : "${ES_NETWORK_INDEX:=.ds-logs-endpoint.events.network-default-*}"
  : "${ES_DISCOVERY_INDEX:=logs-endpoint.events.process-*}"
  : "${ES_METADATA_INDEX:=logs-endpoint.events.process-*,logs-endpoint.events.network-*}"
  : "${ES_ALERTS_INDEX:=.internal.alerts-security.alerts-default-*}"

  local key
  for key in ES_HOST ES_API_KEY ES_USERNAME ES_PASSWORD "${INDEX_KEYS[@]}"; do
    env_set "$ENV_FILE" "$key" "${!key}"
  done
  ok "Wrote .env"
}

test_connection() {
  step "Test the connection to Elasticsearch"
  apply_tls_settings
  if (( LOCAL_ES )); then
    info "Bundled Elasticsearch is not running yet; skipping connectivity check"
  else
    connect_es
    create_engine_key
  fi
}

# GET a path from Elasticsearch with the same TLS settings as the engine. Prints
# the body, then the HTTP status on its own last line.
es_get() {
  local path="$1" flags=(-sS -g --max-time 15 -w '\n%{http_code}') cfg=""
  if [[ "$ES_VERIFY_CERTS" == "false" ]]; then
    flags+=(-k)
  elif [[ -n "${ES_CA_CERT:-}" ]]; then
    flags+=(--cacert "$(ca_cert_path)")
  fi
  cfg="$(es_curl_auth)"
  printf '%s\n' "$cfg" | curl "${flags[@]}" -K - "$ES_HOST$path" 2>/dev/null
}

# "<indices> <documents>" matching an index pattern, or nothing if the cluster
# could not be asked.
index_stats() {
  local out code
  out="$(es_get "/_cat/indices/$1?h=docs.count&expand_wildcards=all")" || return 0
  code="${out##*$'\n'}"
  out="${out%$'\n'*}"
  case "$code" in
    200) awk 'NF { n++; d += $1 } END { printf "%d %d", n, d }' <<<"$out" ;;
    404) printf '0 0' ;;
  esac
}

# The index patterns are not asked for during install: the defaults are the data
# streams Elastic Defend (an Elastic Agent integration) writes. Check each against
# the cluster now, so a different name shows up here rather than as "no anomalies".
declare -A SOURCE_STATE=() SOURCE_NOTE=()
check_data_sources() {
  step "Check the data the engine reads (Elasticsearch index patterns in .env)"
  local key value stats n d
  for key in "${INDEX_KEYS[@]}"; do
    value="$(env_get "$ENV_FILE" "$key")"
    value="${value:-${!key:-}}"
    stats=""
    (( DRY_RUN || LOCAL_ES || ! ES_CONNECTED )) || stats="$(index_stats "$value")"
    if [[ -z "$stats" ]]; then
      SOURCE_STATE[$key]="unchecked"; SOURCE_NOTE[$key]="not checked"
      printf '  [%sSKIP%s] %-19s %s\n' "$C_DIM" "$C_OFF" "$key" "$value"
      continue
    fi
    read -r n d <<<"$stats"
    if (( n > 0 )); then
      SOURCE_STATE[$key]="ok"; SOURCE_NOTE[$key]="$n index(es), $d documents"
      ok "$(printf '%-19s %s  (%s)' "$key" "$value" "${SOURCE_NOTE[$key]}")"
    else
      SOURCE_STATE[$key]="missing"; SOURCE_NOTE[$key]="nothing on the cluster matches"
      warn "$(printf '%-19s %s  (nothing on the cluster matches)' "$key" "$value")"
    fi
  done
  if (( DRY_RUN )); then
    info "Not checked in a dry run"
  elif (( LOCAL_ES )); then
    info "Not checked: the bundled Elasticsearch is not running yet"
  elif (( ! ES_CONNECTED )); then
    info "Not checked: could not connect to Elasticsearch at $ES_HOST"
    for key in "${INDEX_KEYS[@]}"; do
      SOURCE_NOTE[$key]="not checked: could not connect to Elasticsearch"
    done
  fi
}

# ── Maintenance add-on configuration ─────────────────────────────────────────
configure_maintenance() {
  step "Settings (saved in addons/siem-maintenance/.env)"
  if [[ -f "$ADDON_ENV_FILE" && $RECONFIGURE -eq 0 ]]; then
    ok "Using existing add-on .env (pass --reconfigure to change it)"
    sync_addon_env_copy
    return
  fi

  local sys_tz
  sys_tz="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
  KIBANA_HOST="${KIBANA_HOST:-${ES_HOST/:9200/:5601}}"
  (( LOCAL_ES )) && KIBANA_HOST="http://kibana:5601"

  echo "  It uses the same Elasticsearch address as the detection engine (.env)."
  prompt KIBANA_HOST "Kibana address" "$KIBANA_HOST" \
    "Where Kibana is reached. The suggestion is your Elasticsearch server on Kibana's
usual port, 5601."
  prompt GC_ALERT_WEBHOOK "Google Chat webhook URL (optional)" "" \
    "Alerts and the daily report are posted to Google Chat through this link. Create it
in the Chat space: Apps & integrations > Webhooks. Leave it empty to skip Chat."
  prompt GC_ALERT_SPACE_NAME "Name shown on alert messages" "SIEM-MAINTENANCE" \
    "A label printed on each alert so people know where it came from. Any text works."
  prompt MAINTENANCE_IANA_TIMEZONE "Your time zone" "${sys_tz:-UTC}" \
    "Used to send the daily report at the right local time. The suggestion is this
server's time zone. Write it as Region/City, e.g. Africa/Kigali or Africa/Accra."
  prompt DAILY_REPORT_TIME_CAT "Time to send the daily report" "08:30" \
    "24-hour clock, HH:MM, in the time zone above. For example 08:30, or 17:00 for 5 pm."
  prompt ES_HEALTH_MONITOR_INTERVAL_SECONDS "How often to check cluster health, in seconds" "7200" \
    "7200 seconds = every 2 hours. Use 3600 for every hour."

  # LLM narrative is optional; provider is chosen from the model-name prefix.
  LLM_PROVIDER="${LLM_PROVIDER:-none}"
  prompt LLM_PROVIDER "AI-written summary in the daily report" "$LLM_PROVIDER" \
    "Type one of:
  none       no AI summary (the report still has all the numbers)
  ollama     a local model on this server or your network
  openai     OpenAI's API (needs an API key)
  anthropic  Anthropic's Claude API (needs an API key)"
  LLM_ENABLED="true"
  OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
  case "$LLM_PROVIDER" in
    ollama)
      prompt OLLAMA_URL "Ollama address" "$OLLAMA_URL" "Where Ollama is running."
      prompt LLM_MODEL "Ollama model" "llama3.2" "A model already pulled into Ollama (see: ollama list)." ;;
    openai)
      prompt_secret OPENAI_API_KEY "OpenAI API key" "From platform.openai.com > API keys."
      require_value OPENAI_API_KEY
      prompt LLM_MODEL "OpenAI model" "gpt-4o-mini" ;;
    anthropic)
      prompt_secret ANTHROPIC_API_KEY "Anthropic API key" "From console.anthropic.com > API keys."
      require_value ANTHROPIC_API_KEY
      prompt LLM_MODEL "Claude model" "claude-sonnet-4-6" ;;
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
  if (( ! NON_INTERACTIVE )); then
    local choice
    ask_header "Should the agent fix problems on your cluster by itself?" \
      "The agent can fix some common problems for you: clear full caches, restart
stopped ML jobs, delete old snapshots and delete empty indices.

  1) No, only report them  (recommended to start)
     It logs each problem and the fix it would make, but changes nothing.
  2) Yes, fix them automatically
     It makes those changes on your cluster without asking first.

You can switch later: AUTO_REMEDIATION_DRY_RUN in addons/siem-maintenance/.env
(true = only report, false = fix)."
    read -r -p "  Press Enter for ${C_VALUE}1 (only report)${C_OFF}, or type 2 to fix automatically: " choice
    case "${choice:-1}" in
      2) AUTO_REMEDIATION_DRY_RUN="false" ;;
      *) AUTO_REMEDIATION_DRY_RUN="true" ;;
    esac
  fi
  # Automatic fixes change the cluster, so only then does its key get manage privileges.
  local maint_fix=""
  [[ "$AUTO_REMEDIATION_DRY_RUN" == "false" ]] && maint_fix="fix"
  ask_component_login MAINTENANCE "SIEM Maintenance Agent" maintenance "$maint_fix"

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
      if [[ -n "$MAINTENANCE_ES_API_KEY" ]]; then echo "ES_AUTH_TYPE=apikey"; else echo "ES_AUTH_TYPE=userpass"; fi
      echo "ES_API_KEY=$(escape_env "$MAINTENANCE_ES_API_KEY")"
      echo "ES_USERNAME=$(escape_env "$MAINTENANCE_ES_USERNAME")"
      echo "ES_PASSWORD=$(escape_env "$MAINTENANCE_ES_PASSWORD")"
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
  if [[ "$AUTO_REMEDIATION_DRY_RUN" == "true" ]]; then
    ok "Wrote add-on .env (problems are only reported, not fixed)"
  else
    ok "Wrote add-on .env (problems are fixed automatically)"
  fi
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
  step "Settings (saved in addons/alert-triage/.env)"
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

  echo "  The triage agent only reads from Elasticsearch, so a read-only login is safest."
  ask_component_login TRIAGE "Alert Triage Agent" triage
  prompt ELASTIC_INDEX "Where Elastic Security stores its alerts" ".alerts-security.alerts-default" \
    "The suggestion is correct for a standard Elastic Security install."

  AI_PROVIDER="${AI_PROVIDER:-none}"
  prompt AI_PROVIDER "Which AI model should judge each alert: real attack or false alarm?" "$AI_PROVIDER" \
    "After collecting the evidence for an alert, the agent can ask an AI model to decide
whether it is a real attack (true positive) or harmless (false positive), and to
explain why. Type one of:
  none           no AI; the agent still collects all the evidence, you decide
  ollama         a local model on this server or your network
  claude         Anthropic's Claude API (needs an API key)
  openai_compat  any OpenAI-compatible API (OpenAI, LM Studio, vLLM, ...)"
  OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
  case "$AI_PROVIDER" in
    ollama)
      prompt OLLAMA_URL "Ollama address" "$OLLAMA_URL" "Where Ollama is running."
      prompt OLLAMA_MODEL "Ollama model" "llama3.2" "A model already pulled into Ollama (see: ollama list)." ;;
    claude)
      prompt_secret ANTHROPIC_API_KEY "Anthropic API key" "From console.anthropic.com > API keys."
      require_value ANTHROPIC_API_KEY
      prompt CLAUDE_MODEL "Claude model" "claude-haiku-4-5-20251001" ;;
    openai_compat)
      prompt OPENAI_COMPAT_URL "API address" "http://localhost:1234/v1" "The base URL of the OpenAI-compatible API."
      prompt_secret OPENAI_COMPAT_KEY "API key (optional)" "" "press Enter if it needs none"
      prompt OPENAI_COMPAT_MODEL "Model name" "mistral" ;;
    none) ;;
    *) die "Unknown AI provider: $AI_PROVIDER" ;;
  esac
  if [[ "$MODE" == "docker" && "$AI_PROVIDER" == "ollama" && "$OLLAMA_URL" == *localhost* ]]; then
    warn "Inside Docker, localhost is the container. Use http://host.docker.internal:11434 or the host IP."
  fi
  prompt_secret ABUSEIPDB_API_KEY "Check IP addresses against AbuseIPDB? (optional: needs a free API key)" \
    "AbuseIPDB is a public list of IP addresses that people have reported for attacks.
With a key, the agent looks up each IP address in an alert and shows whether it is
known to be malicious. Get a free key: sign up at https://www.abuseipdb.com, then
open Account > API and create a key. Paste it here." \
    "press Enter to skip"
  prompt_secret VIRUSTOTAL_API_KEY "Check files, domains and IPs against VirusTotal? (optional: needs a free API key)" \
    "VirusTotal checks a file (by its hash), a domain or an IP address against dozens of
antivirus and security vendors. With a key, the agent shows how many of them flag
it. Get a free key: sign up at https://www.virustotal.com, then open your profile
menu > API key. Paste it here." \
    "press Enter to skip"

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
      echo "ELASTIC_API_KEY=$(escape_env "$TRIAGE_ES_API_KEY")"
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
  step "Settings (saved in addons/greenbone/.env)"
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

  echo "  It uses the same Elasticsearch address as the detection engine, and writes"
  echo "  scan results to the gvm-vulnerabilities index."
  ask_component_login GREENBONE "Greenbone results push" greenbone
  local socket_help="The suggestion is the standard location for Greenbone's Docker install. Not sure?
Run: sudo find / -name gvmd.sock 2>/dev/null"
  [[ -n "${GVM_FOUND_SOCKET:-}" ]] && socket_help="The suggestion is where this script found it on this server."
  prompt GVM_SOCKET "Where Greenbone's gvmd socket is" "${GVM_SOCKET:-${GVM_FOUND_SOCKET:-$GVM_DEFAULT_SOCKET}}" \
    "$socket_help"
  # The push cannot work without the socket, so do not accept a path without one.
  while (( ! DRY_RUN )) && ! gvm_socket_at "$GVM_SOCKET"; do
    (( NON_INTERACTIVE )) && die "There is no Greenbone socket at $GVM_SOCKET; set GVM_SOCKET to its path"
    printf '  %sThere is no Greenbone socket at %s. Type the right path%s\n' "$C_WARN" "$GVM_SOCKET" "$C_OFF"
    printf '  %s(find it with: sudo find / -name gvmd.sock 2>/dev/null), or press Ctrl+C to stop.%s\n' "$C_WARN" "$C_OFF"
    GVM_SOCKET=""
    prompt GVM_SOCKET "Where Greenbone's gvmd socket is" "${GVM_FOUND_SOCKET:-}"
  done
  prompt GVM_USERNAME "Greenbone username" "" "The account you use to log in to Greenbone's web interface."
  while [[ -z "$GVM_USERNAME" ]] && (( ! NON_INTERACTIVE )); do
    printf '  %sA username is needed: type the one you log in to Greenbone with.%s\n' "$C_WARN" "$C_OFF"
    prompt GVM_USERNAME "Greenbone username" ""
  done
  require_value GVM_USERNAME
  prompt_secret GVM_PASSWORD "Greenbone password" "The password for that account."
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
      echo "ES_API_KEY=$(escape_env "$GREENBONE_ES_API_KEY")"
      echo "ES_USERNAME=$(escape_env "$GREENBONE_ES_USERNAME")"
      echo "ES_PASSWORD=$(escape_env "$GREENBONE_ES_PASSWORD")"
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
  step "Install the Python packages (.venv)"
  make_venv "$VENV_DIR"
  local spec="."
  [[ -n "$EXTRAS" ]] && spec=".[${EXTRAS}]"
  (cd "$REPO_ROOT" && run "$VENV_DIR/bin/python" -m pip install --quiet -e "$spec")
  run mkdir -p "$REPO_ROOT/results/models" "$REPO_ROOT/results/reports" \
    "$REPO_ROOT/results/visualizations" "$REPO_ROOT/logs"
  ok "Installed detection dependencies${EXTRAS:+ (extras: $EXTRAS)}"
}

install_maintenance_venv() {
  step "Install the Python packages (addons/siem-maintenance/.venv)"
  make_venv "$ADDON_VENV_DIR"
  run "$ADDON_VENV_DIR/bin/python" -m pip install --quiet -r "$ADDON_DIR/requirements.txt"
  run mkdir -p "$ADDON_AGENT_DIR/results" "$ADDON_DIR/logs"
  ok "Installed add-on dependencies"
}

check_maintenance_setup() {
  step "Check the settings work (verify_setup.py)"
  if (( DRY_RUN )); then
    run "$ADDON_VENV_DIR/bin/python" "$ADDON_DIR/verify_setup.py"
    return
  fi
  # verify_setup.py logs full tracebacks on connection errors; show only its check lines.
  local out rc=0
  out="$(cd "$ADDON_DIR" && "$ADDON_VENV_DIR/bin/python" verify_setup.py 2>&1)" || rc=$?
  grep -E '^\s*\[(OK|FAIL|WARN|SKIP) *\]' <<<"$out" | sed -e 's/^ */    /' \
    -e 's/\[FAIL\] GC_ALERT_WEBHOOK - empty - Chat cards will not send/[SKIP] GC_ALERT_WEBHOOK - not set, so no Chat messages/' || true
  if (( rc == 0 )); then
    ok "Add-on verify_setup.py passed"
  else
    warn "Add-on verify_setup.py reported problems; fix addons/siem-maintenance/.env and re-run it"
  fi
}

install_triage_venv() {
  step "Install the Python packages (addons/alert-triage/.venv)"
  make_venv "$TRIAGE_VENV_DIR"
  run "$TRIAGE_VENV_DIR/bin/python" -m pip install --quiet -r "$TRIAGE_DIR/requirements.txt" \
    -c "$TRIAGE_CONSTRAINTS"
  ok "Installed triage dependencies"
}

check_triage_loads() {
  step "Check the agent loads with these settings"
  if (( DRY_RUN )); then
    info "Skipped in a dry run"
    return
  fi
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
  step "Install the Python packages (addons/greenbone/.venv)"
  make_venv "$GREENBONE_VENV_DIR"
  run "$GREENBONE_VENV_DIR/bin/python" -m pip install --quiet -r "$GREENBONE_DIR/requirements.txt"
  run mkdir -p "$GREENBONE_DIR/state" "$REPO_ROOT/logs"
  ok "Installed Greenbone add-on dependencies"
}

check_greenbone_connection() {
  step "Test the connection to Greenbone (a dry run; sends nothing)"
  if (( DRY_RUN )); then
    info "Skipped in a dry run"
    return
  fi
  # A dry run logs in to Greenbone and reads every task's latest report, sending nothing.
  info "This needs sudo: Greenbone's socket belongs to root"
  local out socket
  socket="$(env_get "$GREENBONE_ENV_FILE" GVM_SOCKET)"
  if [[ ! -S "$socket" ]] && ! sudo test -S "$socket" 2>/dev/null; then
    warn "Greenbone is not reachable: there is no gvmd socket at $socket"
    info "Is Greenbone installed and running on this server? This add-on does not install it."
    info "If it runs here, find the socket (sudo find / -name gvmd.sock 2>/dev/null), set"
    info "GVM_SOCKET in addons/greenbone/.env, and run ./deploy.sh again."
    return
  fi
  if out="$(sudo "$GREENBONE_VENV_DIR/bin/python" "$GREENBONE_DIR/gvm_siem_push.py" \
      --env-file "$GREENBONE_ENV_FILE" --dry-run 2>&1)"; then
    ok "Greenbone dry run passed"
  else
    warn "Greenbone dry run failed: $(grep -m1 ERROR <<<"$out" || tail -1 <<<"$out")"
    warn "Fix addons/greenbone/.env, then check again with: sudo $(greenbone_push_cmd) --dry-run"
  fi
}

# deploy.sh is meant to run as your normal user (it calls sudo itself). Run with
# sudo, everything it creates belongs to root, including the .env files it locks
# to their owner, and services running as SERVICE_USER cannot read them.
fix_ownership() {
  (( DRY_RUN )) && return 0
  [[ "$(id -u)" -eq 0 && "$SERVICE_USER" != "root" ]] || return 0
  local group path
  group="$(id -gn "$SERVICE_USER")"
  for path in "$@"; do
    [[ -e "$path" ]] && chown -R "$SERVICE_USER:$group" "$path"
  done
  ok "Gave the installed files to $SERVICE_USER, the user the service runs as"
}

# ── systemd ──────────────────────────────────────────────────────────────────
have_systemd() {
  [[ "$(uname -s)" == "Linux" ]] && command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]
}

# "systemctl start" returns before the program has read its settings, so wait a
# moment and check the service is still running; show its last log lines if not.
verify_unit_running() {
  local unit="$1"
  (( DRY_RUN )) && return 0
  sleep 3
  if sudo systemctl is-active --quiet "$unit"; then
    ok "$unit is running (logs: journalctl -u $unit -f)"
    return 0
  fi
  fail "$unit did not stay running. Its last log lines:"
  sudo journalctl -u "$unit" -n 8 --no-pager 2>/dev/null | sed 's/^/         /' || true
  return 1
}

# Record how a systemd unit ended up, for the summary.
unit_status() {
  local key="$1" unit="$2"
  if verify_unit_running "$unit"; then
    set_status "$key" ok "running as a system service ($unit, starts at boot)"
  else
    set_status "$key" fail "installed, but $unit did not stay running (journalctl -u $unit)"
  fi
}

# Returns 0 when it is fine to (re)write the unit: absent, already ours, or --replace-units.
unit_owned_or_absent() {
  local unit="$1" marker="$2" current
  current="$(systemctl cat "$unit" 2>/dev/null | grep -E '^(ExecStart|WorkingDirectory)=' || true)"
  [[ -z "$current" ]] && return 0
  [[ "$current" == *"$marker"* ]] && return 0
  warn "$unit already exists and points somewhere else:"
  sed 's/^/         /' <<<"$current"
  if (( REPLACE_UNITS )) || confirm "Replace it with this copy's version?" N \
      "Only say yes if the service listed above is an old install you no longer use."; then
    return 0
  fi
  return 1
}

install_detection_unit() {
  if ! unit_owned_or_absent "$DETECTION_UNIT" "$REPO_ROOT/"; then
    warn "Left $DETECTION_UNIT unchanged"
    set_status detection warn "installed; the existing $DETECTION_UNIT was left unchanged"
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
  unit_status detection "$DETECTION_UNIT"
}

install_maintenance_unit() {
  if ! unit_owned_or_absent "$MAINTENANCE_UNIT" "$ADDON_AGENT_DIR"; then
    warn "Left $MAINTENANCE_UNIT unchanged"
    set_status maintenance warn "installed; the existing $MAINTENANCE_UNIT was left unchanged"
    return
  fi
  # The add-on ships its own unit installer; it runs the service as SUDO_USER.
  run sudo env SUDO_USER="$SERVICE_USER" bash "$ADDON_DIR/deploy/install-systemd-service.sh" \
    "$ADDON_DIR" "$ADDON_VENV_DIR/bin/python"
  unit_status maintenance "$MAINTENANCE_UNIT"
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
  (( DRY_RUN )) && return 0
  local url i
  url="http://$(triage_probe_host):$TRIAGE_PORT/health"
  for i in $(seq 1 15); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      ok "Triage agent answering at $url"
      return 0
    fi
    sleep 1
  done
  warn "No answer from $url yet; check the service logs"
  set_status triage warn "started, but not answering at $url yet"
}

install_triage_unit() {
  if ! unit_owned_or_absent "$TRIAGE_UNIT" "$TRIAGE_DIR"; then
    warn "Left $TRIAGE_UNIT unchanged"
    set_status triage warn "installed; the existing $TRIAGE_UNIT was left unchanged"
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
  unit_status triage "$TRIAGE_UNIT"
  [[ "${STATUS[triage]}" == "ok" ]] && wait_for_triage
  return 0
}

# A oneshot service plus a timer: the push runs once a week, not as a daemon.
install_greenbone_timer() {
  if ! unit_owned_or_absent "$GREENBONE_SERVICE" "$GREENBONE_DIR"; then
    warn "Left $GREENBONE_SERVICE unchanged"
    set_status greenbone warn "installed; the existing $GREENBONE_SERVICE was left unchanged"
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
Description=Weekly Greenbone results push (SOC-in-a-Box add-on)

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
  set_status greenbone ok "push runs every $GREENBONE_DAY at $GREENBONE_TIME ($GREENBONE_TIMER)"
}

# ── Without systemd ──────────────────────────────────────────────────────────
# Some machines have no systemd, e.g. most containers. There the services run as
# detached background processes, logging to logs/NAME.log with their PID in
# logs/NAME.pid; the Greenbone push runs from addons/greenbone/push_weekly.sh the
# same way. They do not come back after a restart; running deploy.sh again
# starts them.
NO_SYSTEMD_NOTED=0
note_no_systemd() {
  if (( NO_SYSTEMD_NOTED )); then
    info "No systemd here, so this runs as a background process"
    return
  fi
  NO_SYSTEMD_NOTED=1
  info "systemd is not available on this machine (normal inside a container), so the"
  info "services run as background processes instead. They stop if the machine or"
  info "container restarts; run ./deploy.sh again to start them."
}

# Running and not a zombie. Works for root-owned processes too, unlike kill -0.
proc_alive() {
  local state
  state="$(ps -o stat= -p "$1" 2>/dev/null || true)"
  [[ -n "$state" && "$state" != Z* ]]
}

# Send a signal to a PID or process group (-PID), with sudo when it runs as root.
signal_proc() {
  local sig="$1" target="$2" owner
  owner="$(ps -o uid= -p "${target#-}" 2>/dev/null | tr -d ' ' || true)"
  if [[ -n "$owner" && "$owner" != "$(id -u)" && "$(id -u)" -ne 0 ]]; then
    sudo -n kill "-$sig" -- "$target" 2>/dev/null || true
  else
    kill "-$sig" -- "$target" 2>/dev/null || true
  fi
}

# Stop the copy an earlier run started, if that PID is still running our script.
# setsid made it a process group leader, so the whole group is stopped: the
# detection engine starts trainer and detection child processes that would
# otherwise keep running (and the trainer ignores SIGTERM).
stop_background() {
  local name="$1" match="$2" pidfile="$REPO_ROOT/logs/$1.pid" pid cmd target i
  [[ -f "$pidfile" ]] || return 0
  pid="$(cat "$pidfile")"
  if [[ "$pid" =~ ^[0-9]+$ ]] && proc_alive "$pid"; then
    cmd="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
    if [[ "$cmd" == *"$match"* ]]; then
      target="$pid"
      [[ "$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ' || true)" == "$pid" ]] && target="-$pid"
      signal_proc TERM "$target"
      for i in $(seq 1 10); do
        proc_alive "$pid" || break
        sleep 1
      done
      signal_proc KILL "$target"
      info "Stopped the copy an earlier run started (PID $pid)"
    fi
  fi
  rm -f "$pidfile"
}

# start_background NAME DIR COMMAND... — the last argument identifies the
# process, so a later run can recognise it and restart it. With RUN_AS_ROOT=1
# it runs as root (via sudo); otherwise as SERVICE_USER.
start_background() {
  local name="$1" dir="$2"
  shift 2
  local log="$REPO_ROOT/logs/$name.log" pidfile="$REPO_ROOT/logs/$name.pid" pid
  local detach=(nohup) as_user=()
  if (( DRY_RUN )); then
    printf '  [DRY ] start in the background: %s (log: %s)\n' "$*" "${log#"$REPO_ROOT"/}"
    return 0
  fi
  mkdir -p "$REPO_ROOT/logs"
  stop_background "$name" "${*: -1}"
  command -v setsid >/dev/null && detach=(setsid nohup)
  if (( ${RUN_AS_ROOT:-0} )); then
    [[ "$(id -u)" -eq 0 ]] || as_user=(sudo)
  elif [[ "$(id -u)" -eq 0 && "$SERVICE_USER" != "root" ]]; then
    as_user=(sudo -u "$SERVICE_USER")
  fi
  (cd "$dir" && exec "${detach[@]}" "${as_user[@]}" "$@" >>"$log" 2>&1 </dev/null) &
  pid=$!
  printf '%s\n' "$pid" >"$pidfile"
  sleep 3
  if proc_alive "$pid"; then
    ok "Started in the background (PID $pid, log: ${log#"$REPO_ROOT"/})"
    return 0
  fi
  fail "$name stopped right after starting. Its last log lines:"
  tail -n 8 "$log" 2>/dev/null | sed 's/^/         /' || true
  rm -f "$pidfile"
  return 1
}

# Record how a background process ended up, for the summary.
background_status() {
  local key="$1" name="$2"
  shift 2
  if start_background "$name" "$@"; then
    set_status "$key" ok "running in the background (log: logs/$name.log)"
  else
    set_status "$key" fail "stopped right after starting (see logs/$name.log)"
  fi
}

# Without systemd there is usually no cron either (containers), so a small
# scheduler loop runs the push weekly, as root because gvmd's socket is root-owned.
start_greenbone_scheduler() {
  info "systemd is not available here, so a small scheduler (addons/greenbone/push_weekly.sh)"
  info "runs in the background and starts the push every $GREENBONE_DAY at $GREENBONE_TIME."
  if RUN_AS_ROOT=1 start_background greenbone-scheduler "$GREENBONE_DIR" \
      bash "$GREENBONE_DIR/push_weekly.sh" "$GREENBONE_DAY" "$GREENBONE_TIME" $(greenbone_push_cmd); then
    set_status greenbone ok "push runs every $GREENBONE_DAY at $GREENBONE_TIME (background scheduler; log: logs/greenbone-scheduler.log)"
  else
    set_status greenbone fail "the weekly scheduler stopped right after starting (see logs/greenbone-scheduler.log)"
  fi
}

# ── Starting each component ──────────────────────────────────────────────────
start_detection() {
  step "Start the detection engine (it keeps running in the background)"
  if have_systemd; then
    install_detection_unit
  else
    note_no_systemd
    background_status detection realtime_service "$REPO_ROOT" \
      env PYTHONUNBUFFERED=1 "$VENV_DIR/bin/python" -u "$REPO_ROOT/engine/realtime_service.py"
  fi
}

start_maintenance() {
  step "Start the agent (it keeps running in the background)"
  if have_systemd; then
    install_maintenance_unit
  else
    note_no_systemd
    background_status maintenance siem-maintenance "$ADDON_AGENT_DIR" \
      "$ADDON_VENV_DIR/bin/python" "$ADDON_AGENT_DIR/maintenance_service.py"
  fi
}

start_triage() {
  step "Start the agent (it keeps running in the background)"
  if have_systemd; then
    install_triage_unit
  else
    note_no_systemd
    background_status triage alert-triage "$TRIAGE_DIR" \
      "$TRIAGE_VENV_DIR/bin/python" "$TRIAGE_DIR/server.py"
    [[ "${STATUS[triage]}" == "ok" ]] && wait_for_triage
  fi
  return 0
}

schedule_greenbone() {
  step "Schedule the weekly push"
  if have_systemd; then
    install_greenbone_timer
  else
    start_greenbone_scheduler
  fi
}

# ── Docker ───────────────────────────────────────────────────────────────────
COMPOSE_ARGS=()
compose_setup() {
  COMPOSE_ARGS=(--env-file "$ENV_FILE" -f "$COMPOSE_FILE")
  (( LOCAL_ES )) || COMPOSE_ARGS+=(-f "$COMPOSE_EXTERNAL_ES")
  [[ "$WITH_MAINTENANCE" == "yes" ]] && COMPOSE_ARGS+=(--profile maintenance)
  [[ "$WITH_TRIAGE" == "yes" ]] && COMPOSE_ARGS+=(--profile triage)
  return 0
}

# start_container KEY SERVICE — build and start one service, then check it stayed up.
start_container() {
  local key="$1" service="$2" up=(up -d --build) services=("$2") running=""
  # The triage port mapping is interpolated from these; compose defaults to 127.0.0.1:8000.
  local compose_env=(env TRIAGE_BIND="$TRIAGE_LISTEN" TRIAGE_PORT="$TRIAGE_PORT")
  if (( ! LOCAL_ES )); then
    up+=(--no-deps)
  elif [[ "$service" == "detection" ]]; then
    info "Starting the bundled Elasticsearch + Kibana too"
    services=(elasticsearch kibana detection)
  fi
  [[ "$service" == "alert-triage" ]] && run mkdir -p "$TRIAGE_CERT_DIR"
  run "${compose_env[@]}" docker compose "${COMPOSE_ARGS[@]}" "${up[@]}" "${services[@]}"
  if (( DRY_RUN )); then
    set_status "$key" ok "running in Docker (container: $service)"
    return
  fi
  sleep 3
  running="$("${compose_env[@]}" docker compose "${COMPOSE_ARGS[@]}" ps --status running --services 2>/dev/null || true)"
  if grep -qx "$service" <<<"$running"; then
    ok "Container $service is running"
    set_status "$key" ok "running in Docker (container: $service)"
  else
    fail "Container $service is not running. See: docker compose ${COMPOSE_ARGS[*]} logs $service"
    set_status "$key" fail "container $service is not running (docker compose ... logs $service)"
  fi
}

# ── Parts ────────────────────────────────────────────────────────────────────
# Each part runs one component from settings to running. Their step counts must
# match the step calls inside them.
part_detection() {
  local steps=4
  [[ "$MODE" == "venv" ]] && (( INSTALL_SYSTEMD )) && steps=5
  begin_part "Detection engine (the core)" "$steps"
  echo "  Always installed: it turns your endpoint data into ATT&CK-mapped alerts in"
  echo "  Kibana, and the add-ons build on it."
  configure_detection
  test_connection
  check_data_sources
  if [[ "$MODE" == "docker" ]]; then
    step "Build and start the container"
    start_container detection detection
  else
    install_detection_venv
    fix_ownership "$ENV_FILE" "$VENV_DIR" "$REPO_ROOT/results" "$REPO_ROOT/logs" "$REPO_ROOT/config/certs"
    if (( INSTALL_SYSTEMD )); then
      start_detection
    else
      set_status detection warn "installed, not started (--no-systemd)"
    fi
  fi
  # Running is not the same as working: say so when it cannot reach its data.
  if (( ! DRY_RUN && ! LOCAL_ES && ! ES_CONNECTED )) && [[ "${STATUS[detection]:-}" == "ok" ]]; then
    set_status detection warn "${STATUS_NOTE[detection]}, but it cannot reach Elasticsearch at $ES_HOST: fix .env, then restart it"
  fi
  end_part
}

part_maintenance() {
  if (( MAINTENANCE_WIZARD )); then
    begin_part "SIEM Maintenance Agent (add-on)" 1
    step "Run the add-on's own full installer (addons/siem-maintenance/install.sh)"
    (cd "$ADDON_DIR" && run bash ./install.sh)
    set_status maintenance ok "set up by the add-on's own installer"
    end_part
    return
  fi
  if [[ "$MODE" == "docker" ]]; then
    begin_part "SIEM Maintenance Agent (add-on)" 2
    configure_maintenance
    step "Build and start the container"
    start_container maintenance siem-maintenance
    end_part
    return
  fi
  local steps=3
  (( INSTALL_SYSTEMD )) && steps=4
  begin_part "SIEM Maintenance Agent (add-on)" "$steps"
  configure_maintenance
  install_maintenance_venv
  check_maintenance_setup
  fix_ownership "$ADDON_ENV_FILE" "$ADDON_VENV_DIR" "$ADDON_AGENT_DIR/.env" \
    "$ADDON_AGENT_DIR/results" "$ADDON_DIR/logs"
  if (( INSTALL_SYSTEMD )); then
    start_maintenance
  else
    set_status maintenance warn "installed, not started (--no-systemd)"
  fi
  end_part
}

part_triage() {
  if [[ "$MODE" == "docker" ]]; then
    begin_part "Alert Triage Agent (add-on)" 2
    configure_triage
    step "Build and start the container"
    start_container triage alert-triage
    [[ "${STATUS[triage]}" == "ok" ]] && wait_for_triage
    end_part
    return
  fi
  local steps=3
  (( INSTALL_SYSTEMD )) && steps=4
  begin_part "Alert Triage Agent (add-on)" "$steps"
  configure_triage
  install_triage_venv
  check_triage_loads
  fix_ownership "$TRIAGE_ENV_FILE" "$TRIAGE_VENV_DIR" "$TRIAGE_CERT_DIR"
  if (( INSTALL_SYSTEMD )); then
    start_triage
  else
    set_status triage warn "installed, not started (--no-systemd)"
  fi
  end_part
}

# The push reads gvmd's socket on this host, so it always runs from a host venv,
# even when everything else runs in Docker.
part_greenbone() {
  local steps=3
  (( INSTALL_SYSTEMD )) && steps=4
  begin_part "Greenbone vulnerability results (add-on)" "$steps"
  configure_greenbone
  install_greenbone_venv
  check_greenbone_connection
  if (( INSTALL_SYSTEMD )); then
    schedule_greenbone
  else
    set_status greenbone warn "installed; the weekly push is not scheduled (--no-systemd)"
  fi
  end_part
}

# ── Summary ──────────────────────────────────────────────────────────────────
# The command that repeats this install without asking the add-on questions again.
rerun_cmd() {
  local cmd="./deploy.sh" arg
  for arg in "${DEPLOY_ARGS[@]}"; do
    case "$arg" in
      --reconfigure|--dry-run|--with-*|--no-maintenance|--no-triage|--no-greenbone) ;;
      *) cmd+=" $(printf '%q' "$arg")" ;;
    esac
  done
  if [[ -n "$ONLY" ]]; then
    printf '%s' "$cmd"
    return
  fi
  (( MAINTENANCE_WIZARD )) || cmd+=" --$([[ "$WITH_MAINTENANCE" == "yes" ]] && echo with || echo no)-maintenance"
  cmd+=" --$([[ "$WITH_TRIAGE" == "yes" ]] && echo with || echo no)-triage"
  cmd+=" --$([[ "$WITH_GREENBONE" == "yes" ]] && echo with || echo no)-greenbone"
  printf '%s' "$cmd"
}

# How to restart the detection engine after editing .env.
detection_restart_cmd() {
  if [[ "$MODE" == "venv" ]] && (( INSTALL_SYSTEMD )) && have_systemd; then
    printf 'sudo systemctl restart %s' "$DETECTION_UNIT"
  elif [[ "$MODE" == "venv" ]] && (( ! INSTALL_SYSTEMD )); then
    printf 'stop .venv/bin/python engine/realtime_service.py (Ctrl+C) and start it again'
  else
    # Docker recreates the container with the new .env; background mode restarts the process.
    printf '%s' "$(rerun_cmd)"
  fi
}

heading() { printf '\n  %s%s%s\n' "$C_BOLD" "$1" "$C_OFF"; }
detail()  { printf '      %s%-18s%s %s\n' "$C_DIM" "$1" "$C_OFF" "$2"; }

# mark_line STATE LABEL WIDTH TEXT — a coloured ✔ / ! / ✘ / – line.
mark_line() {
  local mark color
  case "$1" in
    ok)          mark="$S_OK";   color="$C_OK" ;;
    warn|missing) mark="$S_WARN"; color="$C_WARN" ;;
    fail)        mark="$S_FAIL"; color="$C_FAIL" ;;
    *)           mark="$S_SKIP"; color="$C_DIM" ;;
  esac
  printf "  %s%s %-${3}s%s %s\n" "$color" "$mark" "$2" "$C_OFF" "$4"
}

component_line() {
  # With --only, components this run did not touch have no status and no line.
  [[ -n "${STATUS[$1]:-}" ]] || return 0
  mark_line "${STATUS[$1]:-skip}" "$2" 24 "${STATUS_NOTE[$1]:-}"
}

summary_components() {
  heading "What was installed"
  component_line detection "Detection engine"
  component_line maintenance "SIEM Maintenance Agent"
  if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
    if [[ "${AUTO_REMEDIATION_DRY_RUN:-$(env_get "$ADDON_ENV_FILE" AUTO_REMEDIATION_DRY_RUN)}" == "false" ]]; then
      detail "Problems found" "fixed automatically"
    else
      detail "Problems found" "only reported (AUTO_REMEDIATION_DRY_RUN=true)"
    fi
  fi
  component_line triage "Alert Triage Agent"
  if [[ "$WITH_TRIAGE" == "yes" ]]; then
    detail "Web page / API" "http://$(triage_probe_host):$TRIAGE_PORT/"
    detail "MCP endpoint" "http://$(triage_probe_host):$TRIAGE_PORT/mcp/mcp"
    if is_loopback "$TRIAGE_LISTEN"; then
      detail "From another PC" "ssh -L $TRIAGE_PORT:127.0.0.1:$TRIAGE_PORT <this host>, then open the address above"
    fi
  fi
  component_line greenbone "Greenbone push"
  if [[ "$WITH_GREENBONE" == "yes" ]]; then
    detail "Results go to" "the gvm-vulnerabilities index (add it as a data view in Kibana)"
    if (( INSTALL_SYSTEMD )) && have_systemd; then
      detail "Push now" "sudo systemctl start $GREENBONE_SERVICE"
    else
      detail "Push now" "sudo $(greenbone_push_cmd)"
    fi
    if (( ! INSTALL_SYSTEMD )); then
      detail "Run it weekly" "sudo addons/greenbone/push_weekly.sh $GREENBONE_DAY $GREENBONE_TIME $(greenbone_push_cmd)"
    fi
  fi
}

summary_data_sources() {
  local key value missing=0 unchecked=0 cert_flag=""
  heading "Data the engine reads (Elasticsearch index patterns, set in .env)"
  for key in "${INDEX_KEYS[@]}"; do
    value="$(env_get "$ENV_FILE" "$key")"
    value="${value:-${!key:-}}"
    case "${SOURCE_STATE[$key]:-unchecked}" in
      missing)   missing=$((missing + 1)) ;;
      unchecked) unchecked=$((unchecked + 1)) ;;
    esac
    mark_line "${SOURCE_STATE[$key]:-unchecked}" "$key" 19 "$value  ${C_DIM}(${SOURCE_NOTE[$key]:-not checked})${C_OFF}"
  done
  (( missing + unchecked == 0 )) && return 0

  if [[ "$ES_VERIFY_CERTS" == "false" ]]; then
    cert_flag="-k "
  elif [[ -n "${ES_CA_CERT:-}" ]]; then
    cert_flag="--cacert $ES_CA_CERT "
  fi
  echo
  if (( missing )); then
    echo "  Nothing on your cluster matches the patterns marked $S_WARN. Either no data has"
    echo "  arrived yet, or your cluster names it differently."
  fi
  echo "  The defaults are the data streams that Elastic Defend (an Elastic Agent"
  echo "  integration) creates. To see the names on your cluster, list its indices:"
  local auth_flag="-u ${ES_USERNAME:-USER}"
  [[ -n "${ES_API_KEY:-}" ]] && auth_flag='-H "Authorization: ApiKey $ES_API_KEY"'
  echo "    curl ${cert_flag}${auth_flag} \"$ES_HOST/_cat/indices/*endpoint*,*alerts*?h=index&expand_wildcards=all\""
  if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
    echo "  Then fix the pattern in .env (and the same line in addons/siem-maintenance/.env),"
  else
    echo "  Then fix the pattern in .env,"
  fi
  echo "  and restart the detection engine so it reads the change:"
  echo "    $(detection_restart_cmd)"
}

# The commands for just the add-on a --only run set up.
summary_commands_only() {
  local unit log service
  case "$ONLY" in
    maintenance) unit="$MAINTENANCE_UNIT"; log="siem-maintenance"; service="siem-maintenance" ;;
    triage)      unit="$TRIAGE_UNIT"; log="alert-triage"; service="alert-triage" ;;
    greenbone)   unit="$GREENBONE_SERVICE"; log="greenbone-scheduler"; service="" ;;
  esac
  heading "Useful commands"
  if [[ "$MODE" == "docker" && -n "$service" ]]; then
    detail "Logs" "docker compose ${COMPOSE_ARGS[*]} logs -f $service"
  elif (( ! INSTALL_SYSTEMD )); then
    detail "Note" "nothing was started (--no-systemd)"
  elif have_systemd; then
    detail "Logs" "journalctl -u $unit -f"
  else
    detail "Logs" "tail -f logs/$log.log"
    detail "Start / restart" "$(rerun_cmd)"
  fi
  [[ "$ONLY" == "greenbone" ]] && detail "Push log" "logs/greenbone-push.log"
  return 0
}

addon_label() {
  case "$1" in
    maintenance) printf 'SIEM Maintenance Agent' ;;
    triage)      printf 'Alert Triage Agent' ;;
    greenbone)   printf 'Greenbone scan results' ;;
  esac
}

summary_commands() {
  if [[ -n "$ONLY" ]]; then
    summary_commands_only
    return
  fi
  heading "Useful commands"
  if [[ "$MODE" == "docker" ]]; then
    detail "Status" "docker compose ${COMPOSE_ARGS[*]} ps"
    detail "Logs" "docker compose ${COMPOSE_ARGS[*]} logs -f"
    return
  fi
  local units="$DETECTION_UNIT"
  [[ "$WITH_MAINTENANCE" == "yes" && $MAINTENANCE_WIZARD -eq 0 ]] && units+=" $MAINTENANCE_UNIT"
  [[ "$WITH_TRIAGE" == "yes" ]] && units+=" $TRIAGE_UNIT"
  if (( ! INSTALL_SYSTEMD )); then
    echo "    Nothing was started (--no-systemd). Start each one yourself:"
    echo "      .venv/bin/python engine/realtime_service.py"
    if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
      echo "      addons/siem-maintenance/.venv/bin/python addons/siem-maintenance/Agent-SIEM-maintenance/maintenance_service.py"
    fi
    if [[ "$WITH_TRIAGE" == "yes" ]]; then
      echo "      (cd addons/alert-triage && .venv/bin/python server.py)"
    fi
  elif have_systemd; then
    detail "Status" "systemctl status $units"
    detail "Logs" "journalctl -u $DETECTION_UNIT -f   (same for the others)"
    detail "Restart" "sudo systemctl restart $units"
  else
    detail "Logs" "tail -f logs/realtime_service.log   (one log per service in logs/)"
    detail "Stop" "kill -- -\$(cat logs/realtime_service.pid)   (one .pid file per service in logs/)"
    detail "Start / restart" "$(rerun_cmd)"
  fi
  detail "Quick checks" ".venv/bin/python engine/main.py --list-jobs"
  detail "" ".venv/bin/python engine/push_all_anomalies.py --dry-run"
  if [[ "$WITH_MAINTENANCE" == "yes" ]]; then
    detail "" "addons/siem-maintenance/.venv/bin/python addons/siem-maintenance/Agent-SIEM-maintenance/maintenance_service.py --once-poll"
  fi
}

summary() {
  local key failed=0 attention=0 issue
  [[ "$ES_VERIFY_CERTS" == "false" ]] \
    && ISSUES+=("TLS verification is off (ES_VERIFY_CERTS=false): the connection is encrypted, but the certificate is not checked. Lab use only.")
  for key in "${!STATUS[@]}"; do
    [[ "${STATUS[$key]}" == "fail" ]] && failed=1
    [[ "${STATUS[$key]}" == "warn" ]] && attention=1
  done
  (( ${#ISSUES[@]} )) && attention=1
  local done_msg="Installation complete"
  [[ -n "$ONLY" ]] && done_msg="$(addon_label "$ONLY") add-on set up"

  if (( DRY_RUN )); then
    banner "Dry run finished: nothing was changed" "$C_BOLD$C_INFO"
  elif (( failed )); then
    banner "$S_FAIL Installation finished, but something is not running (see below)" "$C_BOLD$C_FAIL"
  elif (( attention )); then
    banner "$S_OK $done_msg, with some things to check (see below)" "$C_BOLD$C_WARN"
  else
    banner "$S_OK $done_msg: everything is set up and running" "$C_BOLD$C_OK"
  fi

  summary_components
  [[ -n "$ONLY" ]] || summary_data_sources
  summary_commands

  if (( ${#ISSUES[@]} )); then
    heading "Warnings from the install (${#ISSUES[@]})"
    for issue in "${ISSUES[@]}"; do
      printf '  %s%s%s %s\n' "$C_WARN" "$S_WARN" "$C_OFF" "$issue"
    done
  fi

  if [[ -n "$ONLY" ]]; then
    echo
    return
  fi
  heading "Next"
  echo "    Models train on the engine's first cycle; detections start once that finishes."
  echo "    In Kibana, add ml-anomalies-custom-* as a data view to see them."
  echo "    To confirm alerts arrive, see docs/installation.md, Step 3."
  echo
}

# ── Main ─────────────────────────────────────────────────────────────────────
intro() {
  printf '%sSOC-in-a-Box installer%s (%s)\n' "$C_BOLD" "$C_OFF" "$REPO_ROOT"
  if [[ -n "$ONLY" ]]; then
    cat <<EOF

Adding one add-on to your existing SOC-in-a-Box install: $(addon_label "$ONLY").
It reuses the Elasticsearch settings already saved in .env, and does not touch
the detection engine or the other add-ons. Steps are numbered as before.
EOF
    (( DRY_RUN )) && echo "DRY RUN: no changes will be made"
    return 0
  fi
  cat <<EOF

${C_BOLD}What this installs${C_OFF}
SOC-in-a-Box adds detection and automation on top of your Elastic Stack. It is
one core, the detection engine, plus three optional add-ons that build on it.

  ${C_BOLD}Detection engine  (the core: always installed)${C_OFF}
     Reads the endpoint data your Elastic Agents send to Elasticsearch, learns
     what is normal for each host, user and process, and writes what does not
     fit back as filtered alerts, mapped to MITRE ATT&CK, for you to review in
     Kibana. The add-ons below need it, so it is installed even if you answer
     no to all of them.

  ${C_BOLD}Optional add-ons${C_OFF}  (you are asked about each one next)
     ${C_BOLD}SIEM Maintenance Agent${C_OFF}   keeps an eye on Elasticsearch itself: cluster
                              health, logs still arriving, a daily report.
     ${C_BOLD}Alert Triage Agent${C_OFF}       investigates Elastic Security alerts and says
                              whether each looks like a real attack or a false
                              alarm, and why.
     ${C_BOLD}Greenbone scan results${C_OFF}   sends Greenbone (OpenVAS) vulnerability scans to
                              Elasticsearch weekly. Needs Greenbone installed.
     Any add-on can be added later on its own: ./deploy.sh --only ADD-ON

${C_BOLD}How the install runs${C_OFF}
  Getting started    checks this machine and asks which add-ons you want.
  Detection engine   asks for your Elasticsearch address and login, tests them,
                     installs the engine and starts it.
  One part per add-on you chose: its settings, install, a check, and start.
Each part numbers its steps (Step 1/4, Step 2/4, ...) and says when it is
complete. A summary at the end shows what is running and anything to check.

Most questions come with a suggested answer: press Enter to accept it, or type
your own. It is safe to run again, and ./deploy.sh --dry-run shows every step
without changing anything.
EOF
  (( DRY_RUN )) && echo "DRY RUN: no changes will be made"
  return 0
}

main() {
  intro
  begin_part "Getting started" 2 0
  preflight
  end_part

  PART_TOTAL=1
  [[ -n "$ONLY" ]] && PART_TOTAL=0
  local addon
  for addon in "$WITH_MAINTENANCE" "$WITH_TRIAGE" "$WITH_GREENBONE"; do
    [[ "$addon" == "yes" ]] && PART_TOTAL=$((PART_TOTAL + 1))
  done
  [[ "$MODE" == "docker" ]] && compose_setup
  if [[ -n "$ONLY" ]]; then
    # Nothing else is touched, so the summary only reports this add-on.
    if [[ "$WITH_MAINTENANCE$WITH_TRIAGE$WITH_GREENBONE" != *yes* ]]; then
      echo
      if (( GREENBONE_MISSING )); then
        info "Stopped: nothing was changed. Install Greenbone (steps above), then run ./deploy.sh --only greenbone"
      else
        info "Stopped: nothing was changed."
      fi
      exit 1
    fi
  else
    local greenbone_skip="not installed (add it later: ./deploy.sh --only greenbone)"
    (( GREENBONE_MISSING )) && greenbone_skip="not installed: Greenbone is not on this server yet (then: ./deploy.sh --only greenbone)"
    [[ "$WITH_MAINTENANCE" == "yes" ]] || set_status maintenance skip "not installed (add it later: ./deploy.sh --only maintenance)"
    [[ "$WITH_TRIAGE" == "yes" ]] || set_status triage skip "not installed (add it later: ./deploy.sh --only triage)"
    [[ "$WITH_GREENBONE" == "yes" ]] || set_status greenbone skip "$greenbone_skip"
    part_detection
  fi
  [[ "$WITH_MAINTENANCE" == "yes" ]] && part_maintenance
  [[ "$WITH_TRIAGE" == "yes" ]] && part_triage
  [[ "$WITH_GREENBONE" == "yes" ]] && part_greenbone
  summary
}

# exit on the same line: bash reads a script as it runs, so this stops it reading
# on if the file is edited (e.g. by git pull) while an install is in progress.
main; exit
