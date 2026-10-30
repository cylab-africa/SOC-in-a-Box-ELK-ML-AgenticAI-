#!/usr/bin/env bash
# Full single-node Elastic SOC installer for Ubuntu 20.04+ (including WSL with systemd).
# Usage: sudo bash install-elastic-stack.sh   (guide: docs/elastic-stack.md)
# Installs Elasticsearch, Kibana, Fleet Server, and Elastic Agent on a fresh host.
# Optional System and Elastic Defend integrations are deliberately left for manual setup.
# Review and test on a clean VM before using in production.
set -Eeuo pipefail
umask 077

ELASTIC_MAJOR="${ELASTIC_MAJOR:-8}"
# Set RESUME_PARTIAL=1 only when continuing this installer after a failed/partial run.
RESUME_PARTIAL="${RESUME_PARTIAL:-0}"
SOC_HOSTNAME="${SOC_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"
FLEET_PORT="${FLEET_PORT:-8220}"
ES_PORT="${ES_PORT:-9200}"
KIBANA_PORT="${KIBANA_PORT:-5601}"
# Set FLEET_SERVER_HOST to an IP/DNS name reachable by enrolling endpoints.
# WSL defaults to localhost for local-only testing; regular Ubuntu uses its first host IP.
FLEET_SERVER_HOST="${FLEET_SERVER_HOST:-}"
WORKDIR="/var/tmp/elastic-soc-installer"
LOG_FILE="/var/log/elastic-soc-installer.log"

mkdir -p "$WORKDIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

STEP=0
TOTAL=11
CURRENT_STEP="initialization"

log() { printf '\n\033[1;36m[%s/%s]\033[0m %s\n' "$STEP" "$TOTAL" "$*"; }
ok() { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
run_step() { STEP=$((STEP+1)); CURRENT_STEP="$1"; log "$1"; }

on_error() {
  local rc=$?
  printf '\n[ERROR] Failed during: %s (exit code %s)\n' "$CURRENT_STEP" "$rc" >&2
  printf '[INFO] Log file: %s\n' "$LOG_FILE" >&2
  exit "$rc"
}
trap on_error ERR

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

api() {
  # Usage: api METHOD PATH [JSON_BODY]
  local method="$1" path="$2" body="${3:-}" out code
  local args=(--silent --show-error --insecure --connect-timeout 5 --max-time 30 --user "elastic:${ELASTIC_PASSWORD}" \
    -H 'kbn-xsrf: elastic-soc-installer' -H 'Content-Type: application/json' \
    -X "$method" "${KIBANA_SCHEME}://127.0.0.1:${KIBANA_PORT}${path}" -w '\n%{http_code}')
  if [[ -n "$body" ]]; then args+=(--data "$body"); fi
  log "Kibana API request: ${method} ${path} (30-second request timeout)."
  out="$(curl "${args[@]}")"
  code="${out##*$'\n'}"
  API_BODY="${out%$'\n'*}"
  [[ "$code" =~ ^2[0-9][0-9]$ ]] || {
    printf '[ERROR] Kibana API %s %s returned HTTP %s\n%s\n' "$method" "$path" "$code" "$API_BODY" >&2
    return 1
  }
}

json_get() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); x=d
for k in sys.argv[1].split("."):
    x=x[k]
print(x)' "$1"
}

[[ $EUID -eq 0 ]] || die "Run with sudo: sudo bash $0"
[[ -r /etc/os-release ]] || die "Cannot identify operating system."
source /etc/os-release

[[ "${ID:-}" == "ubuntu" ]] || die "This installer supports Ubuntu only; detected ${PRETTY_NAME:-unknown}."
[[ "${VERSION_ID:-}" =~ ^[0-9]+\.[0-9]+$ ]] || die "Could not parse Ubuntu version: ${VERSION_ID:-unknown}."
dpkg --compare-versions "$VERSION_ID" ge "20.04" || die "Ubuntu 20.04 or newer is required; detected ${PRETTY_NAME:-unknown}."

IS_WSL=false
if grep -qiE 'microsoft|wsl' /proc/sys/kernel/osrelease /proc/version 2>/dev/null || [[ -n "${WSL_DISTRO_NAME:-}" ]]; then
  IS_WSL=true
fi

if [[ -z "$FLEET_SERVER_HOST" ]]; then
  if [[ "$IS_WSL" == true ]]; then
    FLEET_SERVER_HOST="127.0.0.1"
  else
    FLEET_SERVER_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
    FLEET_SERVER_HOST="${FLEET_SERVER_HOST:-$(hostname -f 2>/dev/null || hostname)}"
  fi
fi
[[ "$FLEET_SERVER_HOST" != *"://"* && "$FLEET_SERVER_HOST" != */* && "$FLEET_SERVER_HOST" != *[[:space:]]* ]] || die "FLEET_SERVER_HOST must be a hostname or IP only, without scheme, port, path, or spaces."
FLEET_URL="https://${FLEET_SERVER_HOST}:${FLEET_PORT}"
if [[ "$IS_WSL" == true && "$FLEET_SERVER_HOST" == "127.0.0.1" ]]; then
  warn "Fleet Server is configured for local-only WSL testing. Other PCs will not be able to use 127.0.0.1 as this server's address."
fi

if dpkg --compare-versions "$VERSION_ID" gt "24.04"; then
  warn "Ubuntu ${VERSION_ID} is newer than 24.04. The installer will continue, but verify Elastic's support matrix and package availability for this release."
fi
if dpkg --compare-versions "$VERSION_ID" lt "22.04"; then
  warn "Ubuntu ${VERSION_ID} is an older release. Confirm that the selected Elastic version still supports it before using this outside a test environment."
fi
if [[ "$IS_WSL" == true ]]; then
  warn "WSL detected. This is suitable for testing the installation flow, but Elastic Defend/kernel-level security features may not work as they would on a normal Ubuntu host."
fi

cat <<'BANNER'
============================================================
          ELASTIC SECURITY SOC - SINGLE SERVER
============================================================
This installer installs/configures Elasticsearch, Kibana, Fleet Server,
and Elastic Agent on this Ubuntu host.
It does NOT install Suricata or auto-create System/Defend policies.
Default mode is for a fresh host. Use RESUME_PARTIAL=1 only to continue
a failed run of this same installer on this same host.
============================================================
BANNER

printf "Continue installation on %s? (y/yes/n/no): " "${PRETTY_NAME:-this Ubuntu server}"
IFS= read -r CONFIRM </dev/tty
CONFIRM="${CONFIRM,,}"
case "$CONFIRM" in
  y|yes) ;;
  n|no) die "Cancelled by user." ;;
  *) die "Invalid response. Enter y/yes to continue or n/no to cancel." ;;
esac

run_step "Check system requirements and existing services"
need_cmd apt-get
need_cmd systemctl
need_cmd curl
need_cmd python3
need_cmd openssl
need_cmd dpkg
PID1_COMM="$(ps -p 1 -o comm= 2>/dev/null | tr -d '[:space:]')"
[[ "$PID1_COMM" == "systemd" ]] || die "systemd is not PID 1. This installer needs systemd to manage Elasticsearch, Kibana, and Elastic Agent services. On WSL, enable systemd in /etc/wsl.conf and restart WSL."
SYSTEM_STATE="$(systemctl is-system-running 2>/dev/null || true)"
case "$SYSTEM_STATE" in
  running) ;;
  degraded) warn "systemd reports degraded; continuing, but check failed services if installation errors occur." ;;
  *) die "systemd is not ready (state: ${SYSTEM_STATE:-unknown}). Fix systemd before installing." ;;
esac
RAM_GB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
ROOT_AVAIL_GB=$(df -BG / | awk 'NR==2 {gsub("G", "", $4); print $4}')
CPU_COUNT=$(nproc)
printf 'Hostname: %s\nCPU cores: %s\nRAM: %s GiB\nFree root disk: %s GiB\n' "$SOC_HOSTNAME" "$CPU_COUNT" "$RAM_GB" "$ROOT_AVAIL_GB"
(( RAM_GB >= 8 )) || warn "Less than 8 GiB RAM detected; Elastic Security may be unstable or slow."
(( ROOT_AVAIL_GB >= 30 )) || die "At least 30 GiB free disk space is required for this installer."
EXISTING_ELASTIC=0
for pkg in elasticsearch kibana elastic-agent; do
  if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
    EXISTING_ELASTIC=1
    if [[ "$RESUME_PARTIAL" != "1" ]]; then
      die "$pkg is already installed. For a fresh host, use the default mode. To continue a failed/partial run of this installer, rerun with RESUME_PARTIAL=1 after confirming this is the same deployment."
    fi
    warn "$pkg is already installed; RESUME_PARTIAL=1 allows continuing this partial installation."
  fi
done
ok "Basic checks complete."

run_step "Update Ubuntu and install prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y apt-transport-https ca-certificates curl gnupg jq openssl python3
ok "Prerequisites installed."

run_step "Add the Elastic package repository"
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor --yes -o /usr/share/keyrings/elasticsearch-keyring.gpg
chmod 0644 /usr/share/keyrings/elasticsearch-keyring.gpg
printf 'deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/%s.x/apt stable main\n' "$ELASTIC_MAJOR" > /etc/apt/sources.list.d/elastic-${ELASTIC_MAJOR}.x.list
apt-get update
ok "Elastic repository configured (major version ${ELASTIC_MAJOR}.x)."

run_step "Install Elasticsearch and Kibana"
apt-get install -y elasticsearch kibana
systemctl daemon-reload
systemctl enable elasticsearch
systemctl enable kibana
ok "Packages installed and services enabled."

run_step "Start Elasticsearch and initialize secure access"
systemctl start elasticsearch
ES_HTTP_CODE="000"
for _ in $(seq 1 60); do
  # Elasticsearch security is enabled by default, so HTTP 401 is a valid
  # readiness response: it proves HTTPS is responding but credentials are required.
  ES_HTTP_CODE="$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 5 "https://127.0.0.1:${ES_PORT}" 2>/dev/null || true)"
  if [[ "$ES_HTTP_CODE" == "200" || "$ES_HTTP_CODE" == "401" ]]; then break; fi
  sleep 5
done
[[ "$ES_HTTP_CODE" == "200" || "$ES_HTTP_CODE" == "401" ]] || die "Elasticsearch did not become ready (last HTTP status: ${ES_HTTP_CODE}). Check: journalctl -u elasticsearch"
# Reuse saved credentials when resuming a partial installation.
PASSWORD_FILE="$WORKDIR/elastic-password.txt"
ELASTIC_PASSWORD=""

if [[ "$RESUME_PARTIAL" == "1" && -s "$PASSWORD_FILE" ]]; then
  ELASTIC_PASSWORD="$(cat "$PASSWORD_FILE")"
  if curl -kfsS -u "elastic:${ELASTIC_PASSWORD}" \
      "https://127.0.0.1:${ES_PORT}/" >/dev/null 2>&1; then
    log "Reusing saved Elasticsearch credentials."
  else
    warn "Saved Elasticsearch password is invalid; generating a replacement."
    ELASTIC_PASSWORD=""
  fi
fi

if [[ -z "$ELASTIC_PASSWORD" ]]; then
  ES_RESET_OUT="$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b 2>&1)" || {
    printf '%s\n' "$ES_RESET_OUT" >&2
    die "Could not reset the elastic password. Inspect the existing security configuration."
  }
  ELASTIC_PASSWORD="$(printf '%s\n' "$ES_RESET_OUT" | sed -n -e 's/^New value: //p' -e 's/.* password is \(.*\)$/\1/p' | tail -n1)"
  [[ -n "$ELASTIC_PASSWORD" ]] || {
    printf '%s\n' "$ES_RESET_OUT" >&2
    die "Could not parse the generated elastic password."
  }
  printf '%s\n' "$ELASTIC_PASSWORD" > "$PASSWORD_FILE"
  chmod 600 "$PASSWORD_FILE"
fi

ES_CA="/etc/elasticsearch/certs/http_ca.crt"
[[ -r "$ES_CA" ]] || warn "Expected Elasticsearch CA not found at $ES_CA; local bootstrap requests will use -k."
ok "Elasticsearch is responding over HTTPS (HTTP ${ES_HTTP_CODE}; 401 is expected before authentication). Generated credentials saved with root-only permissions."

run_step "Enroll Kibana and start the web interface"
# Enrollment token is short-lived and kept in memory only.
KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token --scope kibana --force)"
# On a fresh package installation, Kibana can use this token to configure TLS and Elasticsearch connection.
if ! grep -q '^elasticsearch.hosts:' /etc/kibana/kibana.yml; then
  /usr/share/kibana/bin/kibana-keystore create >/dev/null 2>&1 || true
fi
# Use Kibana's supported enrollment flow. Show output as it happens and feed one
# newline to satisfy a default-yes Enter prompt without requiring keyboard input.
if ! systemctl is-active --quiet kibana; then
  log "Running Kibana enrollment setup (90-second timeout; output shown live)."
  if printf '\n' | timeout 90s stdbuf -oL -eL /usr/share/kibana/bin/kibana-setup --enrollment-token "$KIBANA_TOKEN" </dev/stdin; then
    ok "Kibana enrollment setup command completed."
  else
    setup_rc=$?
    warn "Kibana setup exited with status ${setup_rc}; inspect /var/log/kibana/kibana.log and the installer log before continuing."
  fi
fi
# Enrollment can create the CA file as root:group-kibana with mode 0600.
# Kibana runs as the unprivileged `kibana` user, so it must own/read this CA.
# Apply this on every run (including already-enrolled installations) before restart.
fix_kibana_ca_permissions(){
  local ca_file found=0
  [[ -d /var/lib/kibana ]] || { warn "Kibana data directory /var/lib/kibana does not exist yet; skipping CA permission repair."; return 0; }
  while IFS= read -r -d '' ca_file; do
    [[ -f "$ca_file" ]] || continue
    chown kibana:kibana "$ca_file"
    chmod 640 "$ca_file"
    log "Ensured Kibana can read its CA certificate: $ca_file (kibana:kibana, mode 0640)."
    found=1
  done < <(find /var/lib/kibana -maxdepth 1 -type f -name 'ca_*.crt' -print0)
  if [[ "$found" -eq 0 ]]; then
    log "No generated ca_*.crt files found in /var/lib/kibana; no CA permission changes needed."
  fi
}
fix_kibana_ca_permissions
systemctl restart kibana
# Kibana may be configured for HTTP or HTTPS depending on whether enrollment
# completed. Probe both protocols rather than treating an HTTP/TLS mismatch as
# a Kibana startup failure.
KIBANA_SCHEME=""
for _ in $(seq 1 60); do
  if curl -kfsS --max-time 5 "https://127.0.0.1:${KIBANA_PORT}/login" >/dev/null 2>&1; then
    KIBANA_SCHEME="https"
    break
  elif curl -fsS --max-time 5 "http://127.0.0.1:${KIBANA_PORT}/login" >/dev/null 2>&1; then
    KIBANA_SCHEME="http"
    break
  fi
  sleep 5
done
[[ -n "$KIBANA_SCHEME" ]] || die "Kibana did not become ready over HTTP or HTTPS. Check: journalctl -u kibana"
warn "Kibana is responding over ${KIBANA_SCHEME^^}; using that protocol for local setup/API requests."

run_step "Initialize Fleet and create the Fleet Server policy"
# Wait for Fleet APIs to become available.
log "Waiting for Kibana status API (up to 150 seconds; each request has a 30-second timeout)."
FLEET_API_READY=0
for _ in $(seq 1 30); do
  if curl -kfsS --connect-timeout 3 --max-time 5 -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' "${KIBANA_SCHEME}://127.0.0.1:${KIBANA_PORT}/api/status" >/dev/null 2>&1; then FLEET_API_READY=1; break; fi
  sleep 5
done
[[ "$FLEET_API_READY" -eq 1 ]] || die "Kibana status API did not become ready. Check: journalctl -u kibana and /var/log/kibana/kibana.log"
log "Kibana status API is ready; initializing Fleet."
api POST /api/fleet/setup '{}'
# Reuse the Fleet Server policy if a previous partial run already created it.
FLEET_POLICY_ID="$(curl -kfsS --connect-timeout 5 --max-time 30 -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' "${KIBANA_SCHEME}://127.0.0.1:${KIBANA_PORT}/api/fleet/agent_policies" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next((p["id"] for p in d.get("items",[]) if p.get("name")=="SOC Fleet Server Policy"), ""))')"
if [[ -z "$FLEET_POLICY_ID" ]]; then
  api POST '/api/fleet/agent_policies?sys_monitoring=true' '{"name":"SOC Fleet Server Policy","description":"Fleet Server and local SOC host telemetry","namespace":"default","monitoring_enabled":["logs","metrics"]}'
  FLEET_POLICY_ID="$(printf '%s' "$API_BODY" | json_get item.id)"
else
  log "Reusing existing SOC Fleet Server Policy (${FLEET_POLICY_ID}) from the previous partial run."
fi
# Resolve the package version, then use the versioned Fleet package installation API.
log "Looking up Fleet Server integration package version (30-second timeout)."
FLEET_PKG_VERSION="$(curl -kfsS --connect-timeout 5 --max-time 30 -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' "${KIBANA_SCHEME}://127.0.0.1:${KIBANA_PORT}/api/fleet/epm/packages/fleet_server" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("item") or d).get("version", ""))')"
[[ -n "$FLEET_PKG_VERSION" ]] || die "Could not determine Fleet Server integration package version."
log "Ensuring Fleet Server integration package ${FLEET_PKG_VERSION} is installed."
api POST "/api/fleet/epm/packages/fleet_server/${FLEET_PKG_VERSION}" '{"force":true,"ignore_constraints":true}'
FLEET_PKG_BODY="$(python3 - "$FLEET_POLICY_ID" "$FLEET_PKG_VERSION" "$FLEET_PORT" <<'PYBODY'
import json
import sys

policy_id, version, port = sys.argv[1:]

print(json.dumps({
    "name": "fleet_server",
    "namespace": "default",
    "policy_id": policy_id,
    "enabled": True,
    "package": {
        "name": "fleet_server",
        "title": "Fleet Server",
        "version": version
    },
    "inputs": [{
        "type": "fleet-server",
        "enabled": True,
        "streams": [],
        "vars": {
            "host": {
                "type": "text",
                "value": "0.0.0.0"
            },
            "port": {
                "type": "integer",
                "value": int(port)
            }
        }
    }]
}))
PYBODY
)"
log "Checking whether a Fleet Server package policy already exists (30-second timeout)."
FLEET_PACKAGE_POLICY_ID="$(curl -kfsS --connect-timeout 5 --max-time 30 \
  -u "elastic:${ELASTIC_PASSWORD}" \
  -H 'kbn-xsrf: true' \
  "${KIBANA_SCHEME}://127.0.0.1:${KIBANA_PORT}/api/fleet/package_policies" |
  python3 -c 'import json,sys; pid=sys.argv[1]; d=json.load(sys.stdin); print(next((p.get("id","") for p in d.get("items",[]) if p.get("policy_id")==pid and (p.get("package") or {}).get("name")=="fleet_server"), ""))' \
  "$FLEET_POLICY_ID")"

if [[ -z "$FLEET_PACKAGE_POLICY_ID" ]]; then
  api POST /api/fleet/package_policies "$FLEET_PKG_BODY"
  FLEET_PACKAGE_POLICY_ID="$(printf '%s' "$API_BODY" | json_get item.id)"
  [[ -n "$FLEET_PACKAGE_POLICY_ID" ]] || die "Fleet Server package policy creation failed."
else
  log "Reusing existing Fleet Server package policy (${FLEET_PACKAGE_POLICY_ID})."
fi
# Configure the Fleet Server host agents will use. Prefer updating this installer's
# own named host, otherwise the existing default host, otherwise create a new one.
FLEET_HOSTS_BODY="$(python3 - "$FLEET_URL" <<'PYBODY'
import json, sys
print(json.dumps({
    "name": "SOC Fleet Server",
    "host_urls": [sys.argv[1]],
    "is_default": True
}))
PYBODY
)"
log "Checking Fleet Server host configuration."
api GET /api/fleet/fleet_server_hosts
FLEET_HOST_ID="$(printf '%s' "$API_BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); items=d.get("items",[]); p=next((x for x in items if x.get("name")=="SOC Fleet Server"), None) or next((x for x in items if x.get("is_default")), None); print((p or {}).get("id",""))')"
if [[ -n "$FLEET_HOST_ID" ]]; then
  api PUT "/api/fleet/fleet_server_hosts/${FLEET_HOST_ID}" "$FLEET_HOSTS_BODY"
  log "Updated Fleet Server host setting to ${FLEET_URL}."
else
  api POST /api/fleet/fleet_server_hosts "$FLEET_HOSTS_BODY"
  log "Created Fleet Server host setting ${FLEET_URL}."
fi

# Avoid rotating the service token if a working Fleet Server agent is already installed.
# Rotating it during a resume can break a running installation or its next restart.
AGENT_ALREADY_ACTIVE=0
if [[ -x /opt/Elastic/Agent/elastic-agent ]]; then
  if systemctl is-active --quiet elastic-agent; then
    AGENT_ALREADY_ACTIVE=1
    warn "An Elastic Agent is already installed and active; preserving its credentials and configuration."
  else
    die "Elastic Agent files exist but the service is not active. Inspect 'systemctl status elastic-agent' before resuming; this installer will not overwrite it."
  fi
fi

SERVICE_TOKEN=""
if [[ "$AGENT_ALREADY_ACTIVE" -eq 0 ]]; then
  # Remove an old token only when installing a new Fleet Server agent.
  curl -ksS --connect-timeout 5 --max-time 30 -u "elastic:${ELASTIC_PASSWORD}" \
    -X DELETE \
    "https://127.0.0.1:${ES_PORT}/_security/service/elastic/fleet-server/credential/token/soc-fleet-server" \
    >/dev/null 2>&1 || true

  log "Requesting the Fleet Server service token (30-second timeout)."
  SERVICE_TOKEN="$(curl -kfsS --connect-timeout 5 --max-time 30 -u "elastic:${ELASTIC_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -X POST \
    "https://127.0.0.1:${ES_PORT}/_security/service/elastic/fleet-server/credential/token/soc-fleet-server" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["token"]["value"])')"
fi
# Elasticsearch CA fingerprint is used to bootstrap Fleet Server TLS trust.
ES_FINGERPRINT="$(openssl x509 -fingerprint -sha256 -noout -in "$ES_CA" 2>/dev/null | cut -d= -f2 | tr -d ':' || true)"
[[ -n "$ES_FINGERPRINT" ]] || die "Could not calculate Elasticsearch CA fingerprint at $ES_CA."
ok "Fleet APIs initialized; Fleet Server host setting verified."

run_step "Install Elastic Agent as Fleet Server on this same host"
if [[ "$AGENT_ALREADY_ACTIVE" -eq 1 ]]; then
  warn "Elastic Agent is already installed; preserving the existing agent and skipping its download."
else
  AGENT_VERSION="$(dpkg-query -W -f='${Version}' elasticsearch 2>/dev/null | sed 's/^[0-9]*://' | sed 's/-.*//' | cut -d+ -f1)"
  [[ "$AGENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Could not determine a valid Elasticsearch version for Elastic Agent (got: ${AGENT_VERSION:-empty}). Check the Elasticsearch package version."
  AGENT_ARCH="$(dpkg --print-architecture)"
  case "$AGENT_ARCH" in amd64) AGENT_ARCH="x86_64" ;; arm64) AGENT_ARCH="aarch64" ;; *) die "Unsupported architecture for Elastic Agent tarball: $AGENT_ARCH" ;; esac
  AGENT_TGZ="elastic-agent-${AGENT_VERSION}-linux-${AGENT_ARCH}.tar.gz"
  AGENT_URL="https://artifacts.elastic.co/downloads/beats/elastic-agent/${AGENT_TGZ}"
  curl -fL --retry 3 "$AGENT_URL" -o "$WORKDIR/$AGENT_TGZ"
  tar -xzf "$WORKDIR/$AGENT_TGZ" -C "$WORKDIR"
  AGENT_DIR="$WORKDIR/elastic-agent-${AGENT_VERSION}-linux-${AGENT_ARCH}"
  [[ -x "$AGENT_DIR/elastic-agent" ]] || die "Elastic Agent binary was not found after extraction."
  "$AGENT_DIR/elastic-agent" install --non-interactive \
    --url="$FLEET_URL" \
    --fleet-server-es="https://127.0.0.1:${ES_PORT}" \
    --fleet-server-service-token="$SERVICE_TOKEN" \
    --fleet-server-policy="$FLEET_POLICY_ID" \
    --fleet-server-es-ca-trusted-fingerprint="$ES_FINGERPRINT" \
    --fleet-server-host="0.0.0.0" \
    --fleet-server-port="$FLEET_PORT" \
    --insecure
fi
systemctl enable --now elastic-agent
ok "Elastic Agent installed with the Fleet Server role on the SOC host."

run_step "Leave optional host integrations for manual setup"
log "Skipping automatic System and Elastic Defend integration policy creation."
log "Add System and Elastic Defend later in Kibana > Integrations if required."
ok "Core Elasticsearch, Kibana, Fleet Server, and Elastic Agent setup retained."

run_step "Verify services and agent status"
systemctl is-active --quiet elasticsearch || die "Elasticsearch service is not active."
systemctl is-active --quiet kibana || die "Kibana service is not active."
systemctl is-active --quiet elastic-agent || die "Elastic Agent service is not active."
ES_HEALTH="$(curl -kfsS --connect-timeout 5 --max-time 30 -u "elastic:${ELASTIC_PASSWORD}" "https://127.0.0.1:${ES_PORT}/_cluster/health" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("status="+d["status"]+", nodes="+str(d["number_of_nodes"]))')"
AGENT_STATUS=""
for _ in $(seq 1 12); do
  AGENT_STATUS="$(/opt/Elastic/Agent/elastic-agent status 2>&1)" || true
  if printf '%s' "$AGENT_STATUS" | grep -q 'HEALTHY' &&
     printf '%s' "$AGENT_STATUS" | grep -q 'Connected' &&
     printf '%s' "$AGENT_STATUS" | grep -q 'Running'; then
    break
  fi
  sleep 5
done
printf '\nElasticsearch: %s\n' "$ES_HEALTH"
printf 'Kibana: active\nFleet Server agent: active\n\nElastic Agent status:\n%s\n' "$AGENT_STATUS"
if ! printf '%s' "$AGENT_STATUS" | grep -q 'HEALTHY' ||
   ! printf '%s' "$AGENT_STATUS" | grep -q 'Connected' ||
   ! printf '%s' "$AGENT_STATUS" | grep -q 'Running'; then
  die "Elastic Agent is active but has not reached HEALTHY / Connected / Running status. Inspect the status above and journalctl -u elastic-agent."
fi

run_step "Write deployment summary"
PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
SUMMARY_FILE="/root/elastic-soc-deployment-summary.txt"
if [[ "$IS_WSL" == true ]]; then
  PUBLIC_IP="127.0.0.1"
  ACCESS_NOTE="WSL test deployment: use localhost from the Windows host; the WSL IP may change and is not a stable LAN address."
else
  PUBLIC_IP="${PUBLIC_IP:-127.0.0.1}"
  ACCESS_NOTE="For remote access, configure routing and firewall rules to allow only trusted management networks."
fi
cat > "$SUMMARY_FILE" <<SUMMARY
Elastic Security SOC deployment summary
Generated: $(date -Is)
Hostname: ${SOC_HOSTNAME}
Operating system: ${PRETTY_NAME:-Ubuntu}
WSL detected: ${IS_WSL}
Kibana URL (local): ${KIBANA_SCHEME}://127.0.0.1:${KIBANA_PORT}
Kibana URL (host/network): ${KIBANA_SCHEME}://${PUBLIC_IP}:${KIBANA_PORT}
Elasticsearch URL (local): https://127.0.0.1:${ES_PORT}
Fleet Server URL: ${FLEET_URL}
Access note: ${ACCESS_NOTE}
Fleet Server policy ID: ${FLEET_POLICY_ID}
Fleet Server package policy ID: ${FLEET_PACKAGE_POLICY_ID}
Elastic username: elastic
Password file: ${WORKDIR}/elastic-password.txt (root-only)
Installer log: ${LOG_FILE}

Security notes:
- The generated elastic password is stored in a root-only file; retrieve it with sudo.
- This script uses local curl --insecure only for bootstrap API calls because the initial local TLS chain may not be trusted by curl. Do not use --insecure for remote production clients.
- Ensure firewall rules allow only trusted management networks to reach ports 5601, 8220, and (only where needed) 9200. On WSL, use this as a local test deployment; do not treat the WSL IP as a stable production address.
- System and Elastic Defend integrations are not automatically created by this installer. Add them later from Kibana > Integrations if needed.
- Review Elastic subscription requirements for any optional security features you enable.
SUMMARY
chmod 600 "$SUMMARY_FILE"

cat <<EOF

============================================================
                 INSTALLATION SUMMARY
============================================================
[OK] Elasticsearch and Kibana are running.
[OK] Fleet Server and its Elastic Agent are installed on this host.
[OK] Optional System and Elastic Defend policies were left for manual setup in Kibana.

Kibana:       ${KIBANA_SCHEME}://${PUBLIC_IP}:${KIBANA_PORT}
Fleet Server: ${FLEET_URL}
Username:     elastic
Password:     sudo cat ${WORKDIR}/elastic-password.txt
Summary:      ${SUMMARY_FILE}
Log:          ${LOG_FILE}

Next: sign in to Kibana and verify Fleet > Agents. Add System and/or
Elastic Defend from Kibana > Integrations if you need host telemetry or endpoint protection.
============================================================
EOF
