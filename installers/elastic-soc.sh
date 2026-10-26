#!/usr/bin/env bash
# Elastic Security single-node installer for Ubuntu 24.04 (the SOC-in-a-Box base).
# Installs Elasticsearch, Kibana, Fleet Server (via Elastic Agent), and configures
# local System telemetry, Elastic Defend, and an enrollment policy for other Linux
# hosts through the Fleet API. deploy.sh runs it when you choose to install the
# Elastic stack on this host; it can also be run on its own:
#
#   sudo bash installers/elastic-soc.sh            asks for confirmation
#   sudo bash installers/elastic-soc.sh --yes      unattended
#
# Safe to re-run: each step checks what is already done. It refuses to touch an
# Elasticsearch it did not install, because resetting the elastic password would
# lock existing users out.
# Review and test on a clean VM before using in production.
set -Eeuo pipefail
umask 077

ELASTIC_MAJOR="${ELASTIC_MAJOR:-8}"
SOC_HOSTNAME="${SOC_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"
# Address browsers and remote agents use to reach this host (default: primary IP).
SOC_ADVERTISE_ADDR="${SOC_ADVERTISE_ADDR:-}"
FLEET_PORT="${FLEET_PORT:-8220}"
ES_PORT="${ES_PORT:-9200}"
KIBANA_PORT="${KIBANA_PORT:-5601}"
# Prebuilt detection rules to enable: linux (Linux rules, no ML jobs), all, none.
ELASTIC_RULES="${ELASTIC_RULES:-linux}"
ASSUME_YES="${ELASTIC_SOC_ASSUME_YES:-0}"

WORKDIR="/var/tmp/elastic-soc-installer"      # downloads only; nothing secret
STATE_DIR="/etc/elastic-soc"                  # credentials and certificates
CERT_DIR="$STATE_DIR/certs"
PASSWORD_FILE="$STATE_DIR/elastic-password"
ENROLL_FILE="$STATE_DIR/endpoint-enrollment-token"
CONNECTION_FILE="$STATE_DIR/connection.env"   # read by deploy.sh
OWNED_MARKER="$STATE_DIR/installed-by-soc-in-a-box"
SOC_CA="$CERT_DIR/soc-ca.crt"
ES_CA="/etc/elasticsearch/certs/http_ca.crt"
KIBANA_YML="/etc/kibana/kibana.yml"
KIBANA_CERT_DIR="/etc/kibana/certs"
LOG_FILE="/var/log/elastic-soc-installer.log"
FLEET_POLICY_NAME="SOC Fleet Server Policy"
ENDPOINT_POLICY_NAME="SOC Linux Endpoints"

usage() {
  cat <<'EOF'
Usage: sudo bash installers/elastic-soc.sh [--yes]

  --yes, -y    Do not ask for confirmation (also: ELASTIC_SOC_ASSUME_YES=1)

Environment:
  ELASTIC_MAJOR=8               Elastic major version to install
  SOC_ADVERTISE_ADDR=ADDR       Address in the Kibana/Fleet URLs and certificates
                                (default: this host's primary IP)
  ELASTIC_RULES=linux|all|none  Prebuilt detection rules to enable (default: linux)
  ES_PORT, KIBANA_PORT, FLEET_PORT
  ELASTIC_SOC_ALLOW_UNSUPPORTED_OS=1   Run on something other than Ubuntu 24.04
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

STEP=0
TOTAL=10
CURRENT_STEP="initialization"

log() { printf '\n\033[1;36m[%s/%s]\033[0m %s\n' "$STEP" "$TOTAL" "$*"; }
ok() { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
run_step() { STEP=$((STEP+1)); CURRENT_STEP="$1"; log "$1"; }

on_error() {
  local rc=$?
  printf '\n[ERROR] Failed during: %s (exit code %s)\n' "$CURRENT_STEP" "$rc" >&2
  printf '[INFO] Log file: %s. Fix the cause and re-run; finished steps are skipped.\n' "$LOG_FILE" >&2
  exit "$rc"
}
trap on_error ERR

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }
# Package scripts create files other service users must read, so not under umask 077.
apt_get() { (umask 022; apt-get "$@"); }

[[ $EUID -eq 0 ]] || die "Run with sudo: sudo bash $0"
[[ -r /etc/os-release ]] || die "Cannot identify operating system."
source /etc/os-release
if [[ "${ID:-}" != ubuntu || "${VERSION_ID:-}" != "24.04" ]]; then
  [[ "${ELASTIC_SOC_ALLOW_UNSUPPORTED_OS:-0}" == 1 ]] \
    || die "This installer targets Ubuntu 24.04; detected ${PRETTY_NAME:-unknown}. Set ELASTIC_SOC_ALLOW_UNSUPPORTED_OS=1 to try anyway."
  warn "Unsupported OS ${PRETTY_NAME:-unknown}; continuing because ELASTIC_SOC_ALLOW_UNSUPPORTED_OS=1"
fi
case "$ELASTIC_RULES" in linux|all|none) ;; *) die "ELASTIC_RULES must be linux, all, or none" ;; esac

mkdir -p "$WORKDIR"
install -d -m 0755 "$STATE_DIR"
install -d -m 0700 "$CERT_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

if [[ -z "$SOC_ADVERTISE_ADDR" ]]; then
  SOC_ADVERTISE_ADDR="$(hostname -I | awk '{print $1}')"
  [[ -n "$SOC_ADVERTISE_ADDR" ]] || SOC_ADVERTISE_ADDR="$SOC_HOSTNAME"
fi
KIBANA_URL="https://${SOC_ADVERTISE_ADDR}:${KIBANA_PORT}"
FLEET_URL="https://${SOC_ADVERTISE_ADDR}:${FLEET_PORT}"

# ── Helpers ───────────────────────────────────────────────────────────────────
# The elastic password goes to curl as a config file on stdin, so it never
# appears in the process list.
curl_auth() {
  local pw="${ELASTIC_PASSWORD//\\/\\\\}"
  pw="${pw//\"/\\\"}"
  printf 'user = "elastic:%s"\n' "$pw" | curl -K - "$@"
}

kibana_curl() {
  # Usage: kibana_curl METHOD PATH [JSON_BODY]; prints the body, then the HTTP code on the last line.
  local method="$1" path="$2" body="${3:-}"
  local args=(--silent --show-error --cacert "$SOC_CA" \
    -H 'kbn-xsrf: elastic-soc-installer' -H 'Content-Type: application/json' -H 'elastic-api-version: 2023-10-31' \
    -X "$method" "https://127.0.0.1:${KIBANA_PORT}${path}" -w '\n%{http_code}')
  if [[ -n "$body" ]]; then args+=(--data "$body"); fi
  curl_auth "${args[@]}"
}

api() {
  # Usage: api METHOD PATH [JSON_BODY]; sets API_BODY, returns 1 on a non-2xx answer.
  local out code
  out="$(kibana_curl "$@")" || { printf '[ERROR] Kibana API %s %s: request failed\n' "$1" "$2" >&2; return 1; }
  code="${out##*$'\n'}"
  API_BODY="${out%$'\n'*}"
  [[ "$code" =~ ^2[0-9][0-9]$ ]] || {
    printf '[ERROR] Kibana API %s %s returned HTTP %s\n%s\n' "$1" "$2" "$code" "$API_BODY" >&2
    return 1
  }
}

es_api() {
  # Usage: es_api METHOD PATH [JSON_BODY]; prints the response body, fails on HTTP errors.
  local method="$1" path="$2" body="${3:-}"
  local args=(-fsS --cacert "$ES_CA" -H 'Content-Type: application/json' -X "$method" "https://127.0.0.1:${ES_PORT}${path}")
  if [[ -n "$body" ]]; then args+=(--data "$body"); fi
  curl_auth "${args[@]}"
}

json_get() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); x=d
for k in sys.argv[1].split("."):
    x=x[int(k)] if isinstance(x, list) else x[k]
print(x)' "$1"
}

# Quote a value for connection.env the way deploy.sh's env_get reads it.
env_quote() {
  local v="${1//\\/\\\\}"
  printf '"%s"' "${v//\"/\\\"}"
}

# Find a Fleet object by exact name: find_id API_PATH NAME -> id or empty.
find_id() {
  api GET "$1?perPage=100"
  printf '%s' "$API_BODY" | python3 -c 'import json,sys
items=[i for i in json.load(sys.stdin)["items"] if i.get("name")==sys.argv[1]]
print(items[0]["id"] if items else "")' "$2"
}

# Issue a server certificate signed by the SOC CA: issue_cert NAME DIR OWNER_GROUP
issue_cert() {
  local name="$1" dir="$2" group="$3" san ip_re='^[0-9.]+$|:'
  [[ -s "$dir/$name.crt" && -s "$dir/$name.key" ]] && return 0
  san="DNS:localhost,IP:127.0.0.1,DNS:${SOC_HOSTNAME}"
  if [[ "$SOC_ADVERTISE_ADDR" =~ $ip_re ]]; then san+=",IP:${SOC_ADVERTISE_ADDR}"; else san+=",DNS:${SOC_ADVERTISE_ADDR}"; fi
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${SOC_HOSTNAME}" \
    -keyout "$dir/$name.key" -out "$WORKDIR/$name.csr" 2>/dev/null
  openssl x509 -req -in "$WORKDIR/$name.csr" -CA "$SOC_CA" -CAkey "$CERT_DIR/soc-ca.key" -CAcreateserial \
    -days 825 -sha256 -out "$dir/$name.crt" -extfile <(printf '%s\n' \
      "subjectAltName=$san" "basicConstraints=CA:FALSE" \
      "keyUsage=critical,digitalSignature,keyEncipherment" "extendedKeyUsage=serverAuth") 2>/dev/null
  rm -f "$WORKDIR/$name.csr"
  chown "root:$group" "$dir/$name.crt" "$dir/$name.key"
  chmod 0640 "$dir/$name.crt" "$dir/$name.key"
}

# ── Start ────────────────────────────────────────────────────────────────────
cat <<'BANNER'
============================================================
          ELASTIC SECURITY SOC - SINGLE SERVER
============================================================
This installer will configure Elasticsearch, Kibana, Fleet
Server, local host telemetry, and an Elastic Defend policy.
It does NOT install Suricata or configure a network sensor.
============================================================
BANNER

if [[ "$ASSUME_YES" != 1 ]]; then
  read -r -p "Continue on this Ubuntu 24.04 server? Type YES: " CONFIRM
  [[ "$CONFIRM" == "YES" ]] || die "Cancelled by user."
fi

run_step "Check system requirements and existing services"
need_cmd apt-get
need_cmd systemctl
need_cmd curl
need_cmd python3
need_cmd openssl
RAM_GB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
ROOT_AVAIL_GB=$(df -BG / | awk 'NR==2 {gsub("G", "", $4); print $4}')
CPU_COUNT=$(nproc)
printf 'Hostname: %s\nAdvertised address: %s\nCPU cores: %s\nRAM: %s GiB\nFree root disk: %s GiB\n' \
  "$SOC_HOSTNAME" "$SOC_ADVERTISE_ADDR" "$CPU_COUNT" "$RAM_GB" "$ROOT_AVAIL_GB"
(( RAM_GB >= 8 )) || warn "Less than 8 GiB RAM detected; Elastic Security may be unstable or slow."
if [[ ! -e "$OWNED_MARKER" ]]; then
  (( ROOT_AVAIL_GB >= 30 )) || die "At least 30 GiB free disk space is required for this installer."
  if [[ "$(dpkg-query -W -f='${Status}' elasticsearch 2>/dev/null || true)" == "install ok installed" ]] \
     || systemctl is-active --quiet elasticsearch; then
    die "Elasticsearch is already installed but not by this script. Use it as an existing cluster instead (deploy.sh --external-es)."
  fi
  : >"$OWNED_MARKER"
else
  ok "Previous run of this installer found; finished steps will be skipped."
fi
ok "Basic checks complete."

run_step "Update Ubuntu and install prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt_get update
apt_get install -y apt-transport-https ca-certificates curl gnupg jq openssl python3
ok "Prerequisites installed."

run_step "Add the Elastic package repository"
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor --yes -o /usr/share/keyrings/elasticsearch-keyring.gpg
chmod 0644 /usr/share/keyrings/elasticsearch-keyring.gpg
printf 'deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/%s.x/apt stable main\n' "$ELASTIC_MAJOR" > "/etc/apt/sources.list.d/elastic-${ELASTIC_MAJOR}.x.list"
chmod 0644 "/etc/apt/sources.list.d/elastic-${ELASTIC_MAJOR}.x.list"
apt_get update
ok "Elastic repository configured (major version ${ELASTIC_MAJOR}.x)."

run_step "Install Elasticsearch and Kibana"
apt_get install -y elasticsearch kibana
systemctl daemon-reload
systemctl enable elasticsearch
systemctl enable kibana
ok "Packages installed and services enabled."

run_step "Start Elasticsearch and initialize secure access"
systemctl start elasticsearch
[[ -r "$ES_CA" ]] || die "Elasticsearch CA not found at $ES_CA; security auto-configuration did not run."
for _ in $(seq 1 60); do
  if curl -sS --cacert "$ES_CA" -o /dev/null "https://127.0.0.1:${ES_PORT}" 2>/dev/null; then break; fi
  sleep 5
done
curl -sS --cacert "$ES_CA" -o /dev/null "https://127.0.0.1:${ES_PORT}" || die "Elasticsearch did not become ready. Check: journalctl -u elasticsearch"
if [[ -s "$PASSWORD_FILE" ]]; then
  ELASTIC_PASSWORD="$(cat "$PASSWORD_FILE")"
fi
if [[ -z "${ELASTIC_PASSWORD:-}" ]] || ! es_api GET /_security/_authenticate >/dev/null 2>&1; then
  # Reset password non-interactively and capture it only in a root-readable file.
  ES_RESET_OUT="$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b -s 2>&1)" || {
    printf '%s\n' "$ES_RESET_OUT" >&2
    die "Could not reset the elastic password."
  }
  ELASTIC_PASSWORD="$(printf '%s\n' "$ES_RESET_OUT" | sed -n -e 's/^New value: //p' -e '/^[^ ]*$/p' | tail -n1)"
  [[ -n "$ELASTIC_PASSWORD" ]] || die "Could not parse the generated elastic password from installer output."
  ( umask 077; printf '%s\n' "$ELASTIC_PASSWORD" > "$PASSWORD_FILE" )
fi
es_api GET /_security/_authenticate >/dev/null || die "The stored elastic password does not authenticate."
ES_FINGERPRINT="$(openssl x509 -fingerprint -sha256 -noout -in "$ES_CA" | cut -d= -f2 | tr -d ':')"
ok "Elasticsearch is responding over verified HTTPS. Credentials saved with root-only permissions."

run_step "Enroll Kibana and serve it over HTTPS"
# A private CA for Kibana and Fleet Server, so browsers and remote agents can verify both.
if [[ ! -s "$SOC_CA" ]]; then
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -subj "/CN=SOC-in-a-Box CA (${SOC_HOSTNAME})" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$CERT_DIR/soc-ca.key" -out "$SOC_CA" 2>/dev/null
  chmod 0600 "$CERT_DIR/soc-ca.key"
fi
chmod 0644 "$SOC_CA"
chmod 0711 "$CERT_DIR"
install -d -m 0750 -o root -g kibana "$KIBANA_CERT_DIR"
issue_cert kibana "$KIBANA_CERT_DIR" kibana
issue_cert fleet-server "$CERT_DIR" root

if ! grep -q '^elasticsearch.hosts:' "$KIBANA_YML"; then
  # Enrollment token is short-lived and kept in memory only.
  KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)"
  systemctl stop kibana 2>/dev/null || true
  (umask 027; /usr/share/kibana/bin/kibana-setup --enrollment-token "$KIBANA_TOKEN") \
    || die "kibana-setup failed; inspect /var/log/kibana/kibana.log"
  # kibana-setup runs as root; the files it writes must stay readable by Kibana.
  chown -R kibana:kibana /var/lib/kibana
  chgrp kibana "$KIBANA_YML"
  chmod 0660 "$KIBANA_YML"
fi
if ! grep -q '^# BEGIN elastic-soc-installer' "$KIBANA_YML"; then
  for key in server.host server.publicBaseUrl server.ssl.enabled server.ssl.certificate server.ssl.key \
             xpack.encryptedSavedObjects.encryptionKey xpack.reporting.encryptionKey xpack.security.encryptionKey; do
    grep -q "^${key//./\\.}:" "$KIBANA_YML" && die "$KIBANA_YML already sets $key; remove it or configure Kibana TLS by hand."
  done
  # Fleet and detection rules need stable saved-object encryption keys.
  ENC_KEYS="$(/usr/share/kibana/bin/kibana-encryption-keys generate -q 2>/dev/null | grep -E '^xpack\.(encryptedSavedObjects|reporting|security)\.encryptionKey:' || true)"
  [[ $(printf '%s\n' "$ENC_KEYS" | grep -c . || true) -eq 3 ]] || die "Could not generate Kibana encryption keys."
  {
    printf '\n# BEGIN elastic-soc-installer\n'
    printf 'server.host: "0.0.0.0"\n'
    printf 'server.publicBaseUrl: "%s"\n' "$KIBANA_URL"
    printf 'server.ssl.enabled: true\n'
    printf 'server.ssl.certificate: %s/kibana.crt\n' "$KIBANA_CERT_DIR"
    printf 'server.ssl.key: %s/kibana.key\n' "$KIBANA_CERT_DIR"
    printf '%s\n' "$ENC_KEYS"
    printf '# END elastic-soc-installer\n'
  } >> "$KIBANA_YML"
fi
systemctl restart kibana
for _ in $(seq 1 60); do
  if curl -fsS --cacert "$SOC_CA" -o /dev/null "https://127.0.0.1:${KIBANA_PORT}/login" 2>/dev/null; then break; fi
  sleep 5
done
curl -fsS --cacert "$SOC_CA" -o /dev/null "https://127.0.0.1:${KIBANA_PORT}/login" || die "Kibana did not become ready. Check: journalctl -u kibana"
ok "Kibana is responding over verified HTTPS at $KIBANA_URL."

run_step "Initialize Fleet and create the Fleet Server policy"
# Wait until every Kibana plugin, Fleet included, reports available.
for _ in $(seq 1 60); do
  KIBANA_STATUS="$(kibana_curl GET /api/status 2>/dev/null || true)"
  if [[ "$KIBANA_STATUS" == *'"overall":{"level":"available"'* ]]; then break; fi
  sleep 5
done
api POST /api/fleet/setup '{}'
# The Fleet Server policy: has_fleet_server adds the Fleet Server integration and
# sys_monitoring adds the System integration (local logs and metrics).
FLEET_POLICY_ID="$(find_id /api/fleet/agent_policies "$FLEET_POLICY_NAME")"
if [[ -z "$FLEET_POLICY_ID" ]]; then
  api POST '/api/fleet/agent_policies?sys_monitoring=true' "$(python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[1],"description":"Fleet Server and local SOC host telemetry","namespace":"default","monitoring_enabled":["logs","metrics"],"has_fleet_server":True}))' "$FLEET_POLICY_NAME")"
  FLEET_POLICY_ID="$(printf '%s' "$API_BODY" | json_get item.id)"
fi
# Remote agents find Fleet Server at this URL; it must match the certificate.
api GET /api/fleet/fleet_server_hosts
if ! printf '%s' "$API_BODY" | python3 -c 'import json,sys; sys.exit(0 if any(sys.argv[1] in i.get("host_urls",[]) for i in json.load(sys.stdin)["items"]) else 1)' "$FLEET_URL"; then
  api POST /api/fleet/fleet_server_hosts "$(python3 -c 'import json,sys; print(json.dumps({"name":"SOC Fleet Server","host_urls":[sys.argv[1]],"is_default":True}))' "$FLEET_URL")"
fi
ok "Fleet APIs initialized; Fleet Server policy $FLEET_POLICY_ID ready."

run_step "Install Elastic Agent as Fleet Server on this same host"
if systemctl is-active --quiet elastic-agent; then
  warn "Elastic Agent is already running; not reinstalling it."
else
  AGENT_VERSION="$(dpkg-query -W -f='${Version}' elasticsearch | sed 's/-.*//' | cut -d+ -f1)"
  [[ -n "$AGENT_VERSION" ]] || die "Could not determine the installed Elasticsearch version."
  AGENT_ARCH="$(dpkg --print-architecture)"
  case "$AGENT_ARCH" in amd64) AGENT_ARCH="x86_64" ;; arm64) AGENT_ARCH="arm64" ;; *) die "Unsupported architecture for Elastic Agent tarball: $AGENT_ARCH" ;; esac
  AGENT_TGZ="elastic-agent-${AGENT_VERSION}-linux-${AGENT_ARCH}.tar.gz"
  AGENT_URL="https://artifacts.elastic.co/downloads/beats/elastic-agent/${AGENT_TGZ}"
  curl -fL --retry 3 "$AGENT_URL" -o "$WORKDIR/$AGENT_TGZ"
  curl -fsSL --retry 3 "$AGENT_URL.sha512" -o "$WORKDIR/$AGENT_TGZ.sha512"
  (cd "$WORKDIR" && sha512sum -c "$AGENT_TGZ.sha512") || die "Elastic Agent download failed its checksum."
  tar -xzf "$WORKDIR/$AGENT_TGZ" -C "$WORKDIR"
  AGENT_DIR="$WORKDIR/elastic-agent-${AGENT_VERSION}-linux-${AGENT_ARCH}"
  [[ -x "$AGENT_DIR/elastic-agent" ]] || die "Elastic Agent binary was not found after extraction."
  # A fresh service token each attempt; it is passed by file, not on the command line.
  es_api DELETE /_security/service/elastic/fleet-server/credential/token/soc-fleet-server >/dev/null 2>&1 || true
  TOKEN_FILE="$STATE_DIR/fleet-server-service-token"
  ( umask 077; es_api POST /_security/service/elastic/fleet-server/credential/token/soc-fleet-server | json_get token.value > "$TOKEN_FILE" )
  "$AGENT_DIR/elastic-agent" install --non-interactive \
    --url="$FLEET_URL" \
    --certificate-authorities="$SOC_CA" \
    --fleet-server-es="https://127.0.0.1:${ES_PORT}" \
    --fleet-server-es-ca-trusted-fingerprint="$ES_FINGERPRINT" \
    --fleet-server-service-token-path="$TOKEN_FILE" \
    --fleet-server-policy="$FLEET_POLICY_ID" \
    --fleet-server-port="$FLEET_PORT" \
    --fleet-server-cert="$CERT_DIR/fleet-server.crt" \
    --fleet-server-cert-key="$CERT_DIR/fleet-server.key"
  rm -f "$TOKEN_FILE"
fi
systemctl enable --now elastic-agent
ok "Elastic Agent installed with the Fleet Server role on the SOC host."

run_step "Configure Elastic Defend and detection rules"
api GET /api/fleet/epm/packages/endpoint
ENDPOINT_VERSION="$(printf '%s' "$API_BODY" | json_get item.version)"
api POST "/api/fleet/epm/packages/endpoint/${ENDPOINT_VERSION}" '{}'

# Elastic Defend on a policy: defend_policy POLICY_ID NAME
defend_policy() {
  [[ -n "$(find_id /api/fleet/package_policies "$2")" ]] && return 0
  api POST /api/fleet/package_policies "$(python3 - "$1" "$2" "$ENDPOINT_VERSION" <<'PY'
import json,sys
policy,name,version=sys.argv[1:]
print(json.dumps({"name":name,"namespace":"default","policy_id":policy,"enabled":True,
  "package":{"name":"endpoint","title":"Elastic Defend","version":version},
  "inputs":[{"enabled":True,"streams":[],"type":"ENDPOINT_INTEGRATION_CONFIG",
             "config":{"_config":{"value":{"type":"endpoint","endpointConfig":{"preset":"EDRComplete"}}}}}]}))
PY
)"
}
# This host: Fleet Server, System, and Elastic Defend on one agent.
defend_policy "$FLEET_POLICY_ID" soc-elastic-defend
# Other Linux hosts: System and Elastic Defend, enrolled with their own token.
ENDPOINT_POLICY_ID="$(find_id /api/fleet/agent_policies "$ENDPOINT_POLICY_NAME")"
if [[ -z "$ENDPOINT_POLICY_ID" ]]; then
  api POST '/api/fleet/agent_policies?sys_monitoring=true' "$(python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[1],"description":"Linux hosts monitored by SOC-in-a-Box","namespace":"default","monitoring_enabled":["logs","metrics"]}))' "$ENDPOINT_POLICY_NAME")"
  ENDPOINT_POLICY_ID="$(printf '%s' "$API_BODY" | json_get item.id)"
fi
defend_policy "$ENDPOINT_POLICY_ID" soc-elastic-defend-endpoints
api GET "/api/fleet/enrollment_api_keys?perPage=100"
ENROLL_TOKEN="$(printf '%s' "$API_BODY" | python3 -c 'import json,sys
keys=[k for k in json.load(sys.stdin)["items"] if k.get("policy_id")==sys.argv[1] and k.get("active")]
print(keys[0]["api_key"] if keys else "")' "$ENDPOINT_POLICY_ID")"
if [[ -z "$ENROLL_TOKEN" ]]; then
  api POST /api/fleet/enrollment_api_keys "$(printf '{"policy_id":"%s","name":"SOC Linux endpoints"}' "$ENDPOINT_POLICY_ID")"
  ENROLL_TOKEN="$(printf '%s' "$API_BODY" | json_get item.api_key)"
fi
( umask 077; printf '%s\n' "$ENROLL_TOKEN" > "$ENROLL_FILE" )

# Install Elastic's prebuilt rules, then enable the chosen subset. Machine-learning
# rules are left off: they need ML jobs and a subscription. Some rules may still
# fail to enable; record that as a warning rather than claiming success.
if [[ "$ELASTIC_RULES" != none ]]; then
  if api PUT /api/detection_engine/rules/prepackaged; then
    RULES_QUERY='alert.attributes.params.immutable: true AND alert.attributes.enabled: false AND NOT alert.attributes.params.type: machine_learning'
    [[ "$ELASTIC_RULES" == linux ]] && RULES_QUERY+=' AND alert.attributes.tags: "OS: Linux"'
    if api POST /api/detection_engine/rules/_bulk_action "$(python3 -c 'import json,sys; print(json.dumps({"action":"enable","query":sys.argv[1]}))' "$RULES_QUERY")"; then
      printf 'Rules enabled: %s\n' "$(printf '%s' "$API_BODY" | json_get attributes.summary.succeeded 2>/dev/null || echo '?')"
    else
      warn "Some prebuilt rules could not be enabled; review Security > Rules."
    fi
  else
    warn "Could not install prebuilt rules; install them from Security > Rules."
  fi
fi
ok "Elastic Defend policies created; prebuilt rules: $ELASTIC_RULES."

run_step "Verify services and agent status"
systemctl is-active --quiet elasticsearch || die "Elasticsearch service is not active."
systemctl is-active --quiet kibana || die "Kibana service is not active."
systemctl is-active --quiet elastic-agent || die "Elastic Agent service is not active."
ES_HEALTH="$(es_api GET /_cluster/health | python3 -c 'import json,sys; d=json.load(sys.stdin); print("status="+d["status"]+", nodes="+str(d["number_of_nodes"]))')"
AGENT_STATUS="$(elastic-agent status 2>&1 || true)"
printf '\nElasticsearch: %s\n' "$ES_HEALTH"
printf 'Kibana: active\nFleet Server agent: active\n\nElastic Agent status:\n%s\n' "$AGENT_STATUS"

run_step "Write deployment summary"
# Connection details for deploy.sh and the SOC-in-a-Box services (root-only: holds the password).
( umask 077; {
  printf '# Written by installers/elastic-soc.sh on %s\n' "$(date -Is)"
  printf 'ES_HOST=%s\n' "https://localhost:${ES_PORT}"
  printf 'ES_HOST_LAN=%s\n' "https://${SOC_ADVERTISE_ADDR}:${ES_PORT}"
  printf 'ES_USERNAME=elastic\n'
  printf 'ES_PASSWORD=%s\n' "$(env_quote "$ELASTIC_PASSWORD")"
  printf 'ES_CA_CERT=%s\n' "$ES_CA"
  printf 'KIBANA_URL=%s\n' "$KIBANA_URL"
  printf 'SOC_CA_CERT=%s\n' "$SOC_CA"
  printf 'FLEET_URL=%s\n' "$FLEET_URL"
} > "$CONNECTION_FILE" )

SUMMARY_FILE="/root/elastic-soc-deployment-summary.txt"
cat > "$SUMMARY_FILE" <<SUMMARY
Elastic Security SOC deployment summary
Generated: $(date -Is)
Hostname: ${SOC_HOSTNAME}
Kibana URL: ${KIBANA_URL}
Elasticsearch URL (local): https://127.0.0.1:${ES_PORT}
Fleet Server URL: ${FLEET_URL}
Fleet Server policy ID: ${FLEET_POLICY_ID}
Linux endpoint policy ID: ${ENDPOINT_POLICY_ID}
Elastic username: elastic
Password file: ${PASSWORD_FILE} (root-only)
Endpoint enrollment token: ${ENROLL_FILE} (root-only)
SOC CA certificate (Kibana, Fleet Server): ${SOC_CA}
Elasticsearch CA certificate: ${ES_CA}
Installer log: ${LOG_FILE}

Enroll another Linux host (copy ${SOC_CA} to it first):
  sudo ./elastic-agent install --url=${FLEET_URL} \\
    --enrollment-token=<contents of ${ENROLL_FILE}> \\
    --certificate-authorities=/path/to/soc-ca.crt

Security notes:
- Kibana and Fleet Server use certificates from the SOC CA above; import it into
  browsers and pass it to remote agents instead of disabling verification.
- Ensure firewall rules allow only trusted management networks to reach ports
  ${KIBANA_PORT} and ${FLEET_PORT}, and ${ES_PORT} only where needed.
- Fleet Server, System, and Elastic Defend share one policy for the local agent.
  Validate this combined policy on your exact Elastic version and subscription.
- Review subscription requirements for Elastic Defend and machine-learning features.
SUMMARY
chmod 600 "$SUMMARY_FILE"

cat <<EOF

============================================================
                 INSTALLATION SUMMARY
============================================================
[OK] Elasticsearch and Kibana are running.
[OK] Fleet Server and its Elastic Agent are installed on this host.
[OK] System and Elastic Defend are on the local agent policy.
[OK] "${ENDPOINT_POLICY_NAME}" policy is ready for other Linux hosts.

Kibana:       ${KIBANA_URL}
Fleet Server: ${FLEET_URL}
Username:     elastic
Password:     sudo cat ${PASSWORD_FILE}
SOC CA:       ${SOC_CA}
Summary:      sudo cat ${SUMMARY_FILE}
Log:          ${LOG_FILE}

Next: sign in to Kibana, verify Fleet > Agents and Security > Rules,
and confirm the local agent is healthy and telemetry is arriving.
============================================================
EOF
