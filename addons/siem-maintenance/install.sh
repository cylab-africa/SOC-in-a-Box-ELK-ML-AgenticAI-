#!/usr/bin/env bash
# Interactive install: Elasticsearch / Chat / LLM prompts, writes .env, pip install.
# Validates every component as it goes so the user finishes with a working system.
# Usage:  bash install.sh    OR   chmod +x install.sh && ./install.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$REPO_ROOT/Agent-SIEM-maintenance"
REQ_FILE="$REPO_ROOT/requirements.txt"
VENV_DIR="$REPO_ROOT/.venv"

# ── Helpers ──────────────────────────────────────────────────────────────────

prompt() {
  local msg="$1"
  local def="$2"
  local r
  if [[ -n "$def" ]]; then
    read -r -p "$msg [default: $def]: " r
    echo "${r:-$def}"
  else
    read -r -p "$msg: " r
    echo "$r"
  fi
}

prompt_secret() {
  local msg="$1"
  local r
  read -r -s -p "$msg: " r
  echo >&2
  printf '%s' "$r"
}

escape_env() {
  local v="$1"
  if [[ "$v" =~ [\ \#\"\&$'\t'$'\n'] ]]; then
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    printf '"%s"' "$v"
  else
    printf '%s' "$v"
  fi
}

ok()   { printf '  [\e[32m OK \e[0m] %s\n' "$*"; }
fail() { printf '  [\e[31mFAIL\e[0m] %s\n' "$*"; }
warn() { printf '  [\e[33mWARN\e[0m] %s\n' "$*"; }
info() { printf '  [\e[36mINFO\e[0m] %s\n' "$*"; }
hr()   { printf '\n%s\n' "────────────────────────────────────────────────────"; }

# ── Python / venv ────────────────────────────────────────────────────────────

ensure_venv_capable() {
  if python3 -c "import ensurepip" 2>/dev/null; then
    return 0
  fi

  local ver
  ver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"

  if [[ -f /etc/debian_version ]] && command -v apt-get >/dev/null 2>&1; then
    echo ""
    echo "Python ensurepip is missing (required for python3 -m venv). Installing via apt..."
    if sudo -n true 2>/dev/null || sudo -v; then
      if sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq; then
        if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "python${ver}-venv"; then
          sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv || true
        fi
      fi
    else
      echo "Could not run sudo — install manually, then re-run this script:" >&2
      echo "  sudo apt update && sudo apt install -y python${ver}-venv" >&2
    fi
  elif command -v dnf >/dev/null 2>&1 && [[ -f /etc/redhat-release ]]; then
    echo ""
    echo "Attempting: sudo dnf install -y python3 (venv support)..."
    if sudo -n true 2>/dev/null || sudo -v; then
      sudo dnf install -y python3 || true
    fi
  fi

  if python3 -c "import ensurepip" 2>/dev/null; then
    echo "venv support is ready."
    return 0
  fi

  echo "" >&2
  echo "ERROR: ensurepip is still unavailable — cannot create .venv." >&2
  echo "  Debian/Ubuntu: sudo apt update && sudo apt install -y python${ver}-venv" >&2
  echo "  Then re-run: bash install.sh" >&2
  exit 1
}

# ── Ollama helpers ───────────────────────────────────────────────────────────

_find_ollama_bin() {
  local p
  p="$(command -v ollama 2>/dev/null)" && { echo "$p"; return; }
  for p in /usr/local/bin/ollama /usr/bin/ollama /bin/ollama; do
    [[ -x "$p" ]] && { echo "$p"; return; }
  done
}

ensure_ollama_running() {
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    if systemctl list-unit-files ollama.service >/dev/null 2>&1; then
      if ! systemctl is-active --quiet ollama 2>/dev/null; then
        echo ""
        echo "Ollama service is installed but not running. Starting it..."
        if sudo -n true 2>/dev/null || sudo -v; then
          sudo systemctl start ollama
          sleep 1
          if systemctl is-active --quiet ollama 2>/dev/null; then
            ok "Ollama service started"
          else
            warn "Could not start Ollama service. Check: sudo systemctl status ollama"
          fi
        else
          warn "Could not get sudo to start Ollama. Run: sudo systemctl start ollama"
        fi
      else
        ok "Ollama service is running"
      fi
      return
    fi
  fi

  if pgrep -x ollama >/dev/null 2>&1; then
    ok "Ollama process detected"
    return
  fi

  local ollama_bin
  ollama_bin="$(_find_ollama_bin)"
  if [[ -n "$ollama_bin" ]]; then
    echo ""
    echo "Ollama is not running. Starting 'ollama serve' in the background..."
    nohup "$ollama_bin" serve >/dev/null 2>&1 &
    sleep 2
    if pgrep -x ollama >/dev/null 2>&1; then
      ok "Ollama started (PID $!)"
    else
      warn "Could not start Ollama. Ensure it is installed and try: ollama serve"
    fi
  else
    warn "Ollama binary not found. Install from https://ollama.com"
  fi
}

pick_openai_model() {
  echo "OpenAI model preset (default = 1):" >&2
  echo "  1 = gpt-4o-mini   2 = gpt-4o   3 = gpt-4-turbo   4 = gpt-3.5-turbo   5 = custom" >&2
  read -r -p "Choice [default: 1]: " _c
  _c="${_c:-1}"
  case "$_c" in
    2) printf '%s' "gpt-4o" ;;
    3) printf '%s' "gpt-4-turbo" ;;
    4) printf '%s' "gpt-3.5-turbo" ;;
    5) prompt "Custom OpenAI model id" "gpt-4o-mini" ;;
    *) printf '%s' "gpt-4o-mini" ;;
  esac
}

pick_anthropic_model() {
  echo "Anthropic Claude model preset (default = 1):" >&2
  echo "  1 = claude-sonnet-4-6   2 = claude-haiku-4-5-20251001   3 = claude-opus-4-6   4 = custom" >&2
  read -r -p "Choice [default: 1]: " _c
  _c="${_c:-1}"
  case "$_c" in
    2) printf '%s' "claude-haiku-4-5-20251001" ;;
    3) printf '%s' "claude-opus-4-6" ;;
    4) prompt "Custom Anthropic model id" "claude-sonnet-4-6" ;;
    *) printf '%s' "claude-sonnet-4-6" ;;
  esac
}

pick_ollama_model() {
  echo "Ollama model preset (default = 1):" >&2
  echo "  1 = llama3.2   2 = llama3.1   3 = mistral   4 = gemma2:2b   5 = phi3   6 = custom" >&2
  echo "  (or type a model tag directly, e.g. gemma4:e2b)" >&2
  read -r -p "Choice [default: 1]: " _c
  _c="${_c:-1}"
  case "$_c" in
    1) printf '%s' "llama3.2" ;;
    2) printf '%s' "llama3.1" ;;
    3) printf '%s' "mistral" ;;
    4) printf '%s' "gemma2:2b" ;;
    5) printf '%s' "phi3" ;;
    6) prompt "Custom Ollama model tag" "llama3.2" ;;
    # Anything else is a model tag typed directly; it used to fall back to llama3.2.
    *) printf '%s' "$_c" ;;
  esac
}

# Resolve bare model name (e.g. "llama3.2") to the exact tag installed on the
# Ollama server (e.g. "llama3.2:1b").  Falls back to the bare name if the
# server has "model:latest" or if it cannot be reached.
resolve_ollama_tag() {
  local base_url="$1" want="$2"
  local tags exact
  tags="$(curl -sf --max-time 5 "${base_url}/api/tags" 2>/dev/null)" || { printf '%s' "$want"; return; }
  # Exact match first (e.g. "llama3.2:latest")
  exact="$(printf '%s' "$tags" | python3 -c "
import json, sys
data = json.load(sys.stdin)
want = '$want'
names = [m.get('name','') for m in (data.get('models') or [])]
# exact
if want in names:
    print(want); sys.exit(0)
# want:latest
for n in names:
    if n == want + ':latest':
        print(n); sys.exit(0)
# want:<tag>  (first match)
for n in names:
    if n.startswith(want + ':'):
        print(n); sys.exit(0)
# substring
for n in names:
    if want in n:
        print(n); sys.exit(0)
print(want)
" 2>/dev/null)"
  printf '%s' "${exact:-$want}"
}

# ── Banner ───────────────────────────────────────────────────────────────────

echo ""
echo "          _____ _           _   _      ____                      _     "
echo "         | ____| | __ _ ___| |_(_) ___|/ ___|  ___  __ _ _ __ ___| |__  "
echo "         |  _| | |/ _\` / __| __| |/ __|\\___ \\ / _ \\/ _\` | '__/ __| '_ \\ "
echo "         | |___| | (_| \\__ \\ |_| | (__ ___) |  __/ (_| | | | (__| | | |"
echo "         |_____|_|\\__,_|___/\\__|_|\\___|____/ \\___|\\__,_|_|  \\___|_| |_|"
echo ""
echo "=== SIEM-Maintenance — interactive setup ==="
echo "Repository: $REPO_ROOT"
echo ""

command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }
python3 --version

# ── Pre-flight: ensure repo tree is writable by the current user ────────────
# If a prior install ran as root, the entire repo may be root-owned.
# Fix it once here so every later step can write without surprises.
if [[ ! -w "$REPO_ROOT" || ! -w "$AGENT_DIR" ]]; then
  warn "Repository files are not writable by $(whoami) — fixing ownership"
  if sudo -n true 2>/dev/null || sudo -v; then
    sudo chown -R "$(id -u):$(id -g)" "$REPO_ROOT"
    ok "Ownership fixed for $REPO_ROOT"
  else
    fail "Cannot fix repo ownership. Run manually:"
    echo "  sudo chown -R \$(id -u):\$(id -g) $REPO_ROOT"
    exit 1
  fi
fi

# ── 1. Python venv ───────────────────────────────────────────────────────────
hr
echo "STEP 1/9  Python environment"

read -r -p "Create/use venv at .venv? (Y/n): " use_venv
use_venv="${use_venv:-Y}"

if [[ "$use_venv" =~ ^[Nn]$ ]]; then
  PIP=(python3 -m pip)
  PY_EXE="python3"
  "${PIP[@]}" install --upgrade pip
else
  if [[ -d "$VENV_DIR" ]] && [[ -f "$VENV_DIR/bin/activate" ]] && [[ -x "$VENV_DIR/bin/python" ]]; then
    echo "Using existing venv at $VENV_DIR"
    # Fix ownership if venv was created/installed as root but we're running as a regular user
    if [[ -n "$(find "$VENV_DIR" -maxdepth 1 ! -writable 2>/dev/null)" ]]; then
      warn ".venv is not writable by $(whoami) — fixing ownership"
      if sudo -n true 2>/dev/null || sudo -v; then
        sudo chown -R "$(id -u):$(id -g)" "$VENV_DIR"
        ok ".venv ownership fixed"
      else
        fail "Cannot fix .venv permissions. Run: sudo chown -R $(id -u):$(id -g) $VENV_DIR"
        exit 1
      fi
    fi
  else
    if [[ -d "$VENV_DIR" ]]; then
      echo "Removing incomplete .venv..."
      if [[ ! -w "$VENV_DIR" ]]; then
        sudo rm -rf "$VENV_DIR"
      else
        rm -rf "$VENV_DIR"
      fi
    fi
    # Ensure repo root is writable before creating venv
    if [[ ! -w "$REPO_ROOT" ]]; then
      warn "Repo directory is not writable by $(whoami) — fixing ownership"
      sudo chown "$(id -u):$(id -g)" "$REPO_ROOT" || {
        fail "Cannot write to $REPO_ROOT"
        echo "  Run manually:  sudo chown -R \$(id -u):\$(id -g) $REPO_ROOT"
        exit 1
      }
    fi
    ensure_venv_capable
    echo "Creating venv at $VENV_DIR..."
    if ! python3 -m venv "$VENV_DIR"; then
      echo "python3 -m venv failed. See messages above (often: apt install python3-venv)." >&2
      rm -rf "$VENV_DIR" 2>/dev/null || true
      exit 1
    fi
  fi
  # shellcheck source=/dev/null
  source "$VENV_DIR/bin/activate"
  pip install --upgrade pip
  PIP=(pip)
  PY_EXE="$VENV_DIR/bin/python"
fi

echo ""
echo "Checking build dependencies (needed for cryptography / google-auth)..."
_missing_build=()
if ! command -v gcc >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; then
  _missing_build+=(gcc)
fi
if ! "$PY_EXE" -c "import _ctypes" 2>/dev/null; then
  _missing_build+=(libffi-dev)
fi
if [[ ${#_missing_build[@]} -gt 0 ]]; then
  warn "Missing build tools: ${_missing_build[*]}"
  if [[ -f /etc/debian_version ]] && command -v apt-get >/dev/null 2>&1; then
    info "Attempting: sudo apt-get install -y build-essential libffi-dev python3-dev"
    if sudo -n true 2>/dev/null || sudo -v; then
      sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libffi-dev python3-dev || true
    else
      warn "Could not sudo. Install manually: sudo apt install -y build-essential libffi-dev python3-dev"
    fi
  elif command -v dnf >/dev/null 2>&1; then
    info "Attempting: sudo dnf install -y gcc libffi-devel python3-devel"
    if sudo -n true 2>/dev/null || sudo -v; then
      sudo dnf install -y gcc libffi-devel python3-devel || true
    fi
  else
    warn "Install a C compiler and libffi headers before continuing."
  fi
fi

echo ""
echo "Installing dependencies..."
if ! "${PIP[@]}" install -r "$REQ_FILE"; then
  fail "pip install failed — check output above for errors"
  warn "Common fix: sudo apt install -y build-essential libffi-dev python3-dev"
  exit 1
fi
ok "Python dependencies installed"

# ── 2. Elasticsearch ─────────────────────────────────────────────────────────
hr
echo "STEP 2/9  Elasticsearch connection"
echo ""

ES_HOST="$(prompt "IP address or URL where Elasticsearch is installed (ES_HOST)" "https://localhost:9200")"
KIB_DEF="${ES_HOST/:9200/:5601}"
KIBANA_HOST="$(prompt "IP address or URL where Kibana is installed (KIBANA_HOST)" "$KIB_DEF")"

echo ""
echo "Authentication method:"
echo "  1 = Username / Password"
echo "  2 = API Key  (recommended — no shared password, revocable per key)"
read -r -p "Choice [default: 1]: " _auth_choice
_auth_choice="${_auth_choice:-1}"

ES_USER=""
ES_PASS=""
ES_API_KEY=""
ES_AUTH_TYPE="userpass"

if [[ "$_auth_choice" == "2" ]]; then
  ES_AUTH_TYPE="apikey"
  echo ""
  echo "  How to create an Elasticsearch API key:"
  echo "  ─────────────────────────────────────────────────────────────"
  echo "  1. Open Kibana → Stack Management → Security → API Keys"
  echo "  2. Click 'Create API key'"
  echo "  3. Give it a name (e.g. siem-maintenance-agent) and set"
  echo "     an expiry if desired."
  echo "  4. Under 'Control security privileges' you can restrict to"
  echo "     cluster:monitor and read on the relevant indices, or leave"
  echo "     unrestricted for a service account."
  echo "  5. Click 'Create API key' and copy the 'Encoded' value —"
  echo "     it looks like a long base64 string. That is your ES_API_KEY."
  echo "  Note: API keys are revocable any time from the same screen"
  echo "        without changing cluster passwords."
  echo "  ─────────────────────────────────────────────────────────────"
  echo ""
  ES_API_KEY="$(prompt_secret "Paste your Elasticsearch API key (Encoded value)")"
else
  echo ""
  ES_USER="$(prompt "Elasticsearch username (leave empty if none)" "")"
  ES_PASS="$(prompt_secret "Elasticsearch password (leave empty if none)")"
fi

echo ""
echo "Testing Elasticsearch connection..."
set +e
if [[ "$ES_AUTH_TYPE" == "apikey" ]]; then
  es_test="$("$PY_EXE" -W ignore -c "
import warnings
warnings.filterwarnings('ignore')
from elasticsearch import Elasticsearch
es = Elasticsearch(hosts=['$ES_HOST'],
    api_key='$ES_API_KEY',
    verify_certs=False, request_timeout=15)
info = es.info()
v = info.get('version',{}).get('number','?')
cn = info.get('cluster_name','?')
print(f'{cn} (v{v})')
" 2>&1)"
else
  es_test="$("$PY_EXE" -W ignore -c "
import warnings
warnings.filterwarnings('ignore')
from elasticsearch import Elasticsearch
es = Elasticsearch(hosts=['$ES_HOST'],
    basic_auth=('$ES_USER', '$ES_PASS') if '$ES_USER' else None,
    verify_certs=False, request_timeout=15)
info = es.info()
v = info.get('version',{}).get('number','?')
cn = info.get('cluster_name','?')
print(f'{cn} (v{v})')
" 2>&1)"
fi
es_ec=$?
set -e
if [[ "$es_ec" -eq 0 && -n "$es_test" && ! "$es_test" =~ "Error" && ! "$es_test" =~ "Traceback" ]]; then
  ok "Elasticsearch reachable: $es_test"
  ES_OK=true
else
  fail "Could not reach Elasticsearch at $ES_HOST"
  warn "Error: ${es_test:0:200}"
  warn "The scheduler will still run but health checks will fail until ES is reachable."
  ES_OK=false
fi

echo ""
echo "--- Index patterns (for data freshness checks) ---"
echo "These are the Elasticsearch index patterns used to check if agents are sending data."
echo "The defaults work for standard Elastic Agent setups — press Enter to keep them."
echo ""
PROC="$(prompt "Process events index pattern" ".ds-logs-endpoint.events.process-default-*")"
NET="$(prompt "Network events index pattern" ".ds-logs-endpoint.events.network-default-*")"
DISC="$(prompt "Discovery events index pattern" "logs-endpoint.events.process-*")"

# ── 3. Google Chat ───────────────────────────────────────────────────────────
hr
echo "STEP 3/9  Google Chat webhook"
echo ""
echo "The daily report and health alerts are sent as cards to a Google Chat space."
echo "Create a webhook: Chat space > Apps & integrations > Webhooks > Add."
echo ""

WEBHOOK="$(prompt "Paste your Google Chat webhook URL (leave empty to skip)" "")"
SPACE="$(prompt "Name for your Chat space (shown in alert cards)" "SIEM-MAINTENANCE")"

GC_OK=false
if [[ -n "$WEBHOOK" ]]; then
  echo ""
  echo "Testing Google Chat webhook..."
  set +e
  gc_test="$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 \
    -H "Content-Type: application/json" \
    -d '{"text":"SIEM-Maintenance install test — this message confirms the webhook is working."}' \
    "$WEBHOOK" 2>&1)"
  set -e
  if [[ "$gc_test" == "200" ]]; then
    ok "Webhook works (HTTP 200) — check your Chat space for the test message"
    GC_OK=true
  else
    fail "Webhook returned HTTP $gc_test"
    warn "Cards will not be delivered. Verify the webhook URL."
  fi
else
  warn "No webhook set — daily reports and alerts will not be sent to Chat"
fi

echo ""
echo "--- Card logo ---"
echo "An image URL shown in the card header (leave empty for no logo)."
GC_LOGO="$(prompt "Logo image URL for alert cards (leave empty for none)" "https://avatars.githubusercontent.com/u/6764390?s=128")"

if [[ -n "$GC_LOGO" ]]; then
  set +e
  logo_code="$(curl -sfI -o /dev/null -w "%{http_code}" --max-time 8 "$GC_LOGO" 2>&1)"
  set -e
  if [[ "$logo_code" == "200" ]]; then
    ok "Logo URL reachable"
  else
    warn "Logo URL returned HTTP $logo_code — card will render without an image"
  fi
fi

# ── 4. LLM ───────────────────────────────────────────────────────────────────
hr
echo "STEP 4/9  LLM — AI analysis for daily reports + health alerts"
echo ""
echo "  1 = OpenAI     (gpt-* models; requires API key)"
echo "  2 = Ollama     (local/remote; e.g. llama3.2 — recommended for airgapped)"
echo "  3 = Anthropic  (Claude models; requires API key)"
echo "  4 = Off        (metrics-only, no AI narrative)"
echo ""

while true; do
  read -r -p "Enter 1, 2, 3, or 4 [default: 2]: " prov
  prov="${prov:-2}"
  case "$prov" in
    1|2|3|4) break ;;
    *) echo "Please enter 1, 2, 3, or 4." ;;
  esac
done

LLM_ENABLED_VAR="true"
OPENAI_KEY=""
ANTHROPIC_KEY=""
OLLAMA_URL_VAR="http://localhost:11434"
LLM_MODEL_VAR="llama3.2"
LLM_OK=false

case "$prov" in
  1)
    LLM_MODEL_VAR="$(pick_openai_model)"
    OPENAI_KEY="$(prompt_secret "Your OpenAI API key")"
    OLLAMA_URL_VAR="$(prompt "Ollama URL as fallback (optional, press Enter to skip)" "http://localhost:11434")"

    echo ""
    echo "Testing OpenAI API..."
    set +e
    oai_test="$("$PY_EXE" -c "
import requests, os
r = requests.get('https://api.openai.com/v1/models',
    headers={'Authorization': 'Bearer $OPENAI_KEY'}, timeout=15)
if r.status_code == 200:
    print('OK')
else:
    print(f'HTTP {r.status_code}')
" 2>&1)"
    set -e
    if [[ "$oai_test" == "OK" ]]; then
      ok "OpenAI API key valid"
      LLM_OK=true
    else
      fail "OpenAI: $oai_test"
      warn "AI analysis will be skipped until the key is fixed."
    fi
    ;;
  2)
    OLLAMA_URL_VAR="$(prompt "Ollama server URL (where Ollama is running)" "http://localhost:11434")"
    echo ""
    ensure_ollama_running
    echo ""
    echo "--- This machine: suggested Ollama tags ---"
    "$PY_EXE" "$REPO_ROOT/ollama_preflight.py" recommend || true
    echo ""
    LLM_MODEL_VAR="$(pick_ollama_model)"

    # Pull if missing
    echo ""
    export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"
    set +e
    read -r -p "Pull model if missing from Ollama? (Y/n): " pull_missing
    pull_missing="${pull_missing:-Y}"
    if [[ ! "$pull_missing" =~ ^[Nn]$ ]]; then
      "$PY_EXE" "$REPO_ROOT/ollama_preflight.py" ensure --url "$OLLAMA_URL_VAR" --model "$LLM_MODEL_VAR"
    else
      "$PY_EXE" "$REPO_ROOT/ollama_preflight.py" ensure --url "$OLLAMA_URL_VAR" --model "$LLM_MODEL_VAR" --no-pull
    fi
    set -e

    # Resolve to exact tag so the .env has the real name
    resolved_tag="$(resolve_ollama_tag "$OLLAMA_URL_VAR" "$LLM_MODEL_VAR")"
    if [[ "$resolved_tag" != "$LLM_MODEL_VAR" ]]; then
      info "Resolved model tag: $LLM_MODEL_VAR -> $resolved_tag"
      LLM_MODEL_VAR="$resolved_tag"
    fi

    # Test actual generation
    echo ""
    echo "Testing Ollama generation with $LLM_MODEL_VAR..."
    set +e
    gen_test="$(curl -sf --max-time 60 "${OLLAMA_URL_VAR}/api/generate" \
      -d "{\"model\":\"$LLM_MODEL_VAR\",\"prompt\":\"Reply with exactly: OK\",\"stream\":false,\"options\":{\"num_predict\":5}}" 2>&1)"
    gen_ec=$?
    set -e
    if [[ "$gen_ec" -eq 0 ]] && echo "$gen_test" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if d.get('response','').strip() else 1)" 2>/dev/null; then
      ok "Ollama generation works ($LLM_MODEL_VAR)"
      LLM_OK=true
    else
      fail "Ollama generation failed for $LLM_MODEL_VAR"
      warn "AI analysis will be skipped. Check: ollama list, or pull: ollama pull $LLM_MODEL_VAR"
    fi
    ;;
  3)
    LLM_MODEL_VAR="$(pick_anthropic_model)"
    ANTHROPIC_KEY="$(prompt_secret "Your Anthropic API key")"
    OLLAMA_URL_VAR="$(prompt "Ollama URL as fallback (optional, press Enter to skip)" "http://localhost:11434")"

    echo ""
    echo "Testing Anthropic API..."
    set +e
    ant_test="$("$PY_EXE" -c "
import requests
r = requests.post('https://api.anthropic.com/v1/messages',
    headers={'x-api-key': '$ANTHROPIC_KEY', 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json'},
    json={'model': '$LLM_MODEL_VAR', 'max_tokens': 5, 'messages': [{'role': 'user', 'content': 'Reply with exactly: OK'}]},
    timeout=30)
if r.status_code == 200:
    print('OK')
else:
    print(f'HTTP {r.status_code}')
" 2>&1)"
    set -e
    if [[ "$ant_test" == "OK" ]]; then
      ok "Anthropic API key valid ($LLM_MODEL_VAR)"
      LLM_OK=true
    else
      fail "Anthropic: $ant_test"
      warn "AI analysis will be skipped until the key is fixed."
    fi
    ;;
  4)
    LLM_ENABLED_VAR="false"
    LLM_MODEL_VAR="$(prompt "LLM model name (stored for later if you enable LLM)" "llama3.2")"
    OLLAMA_URL_VAR="$(prompt "Ollama server URL (optional, press Enter to skip)" "http://localhost:11434")"
    LLM_OK=true
    info "LLM disabled — daily reports will include metrics only (no AI narrative)"
    ;;
esac

# ── 5. Scheduler ─────────────────────────────────────────────────────────────
hr
echo "STEP 5/9  Scheduler settings"
echo ""

TZ_IANA="$(prompt "Your timezone (IANA format, e.g. America/New_York)" "Africa/Johannesburg")"
DAILY="$(prompt "What time should the daily report be sent? (HH:MM in your timezone)" "08:30")"
POLL="$(prompt "How often to check cluster health, in seconds (e.g. 7200 = every 2 hours)" "7200")"
COOL="$(prompt "Minimum hours between repeat alerts for the same issue" "2")"

# ── 6. Feedback loop ────────────────────────────────────────────────────────
hr
echo "STEP 6/9  Feedback loop (closed-loop learning from analyst verdicts)"
echo ""
echo "The feedback loop lets analysts mark alerts as TP/FP via Google Chat buttons."
echo "Verdicts are collected in a Google Sheet, polled by the feedback poller, and"
echo "applied to SYSTEM_MEMORY.md so future analysis improves over time."
echo ""
echo "Requirements:"
echo "  - A Google Cloud service-account JSON key with Chat API + Sheets API scopes"
echo "  - A Google Sheet shared with the service account (editor)"
echo ""

read -r -p "Enable the feedback loop? (Y/n): " fb_enable
fb_enable="${fb_enable:-Y}"

SA_KEY_PATH=""
FB_SHEET_ID=""
FB_PORT="8090"
FB_OK=false

if [[ ! "$fb_enable" =~ ^[Nn]$ ]]; then

  SA_KEY_DEFAULT="$AGENT_DIR/siem-chat-bot-key.json"
  SA_KEY_PATH="$(prompt "Path to Google service-account JSON key" "$SA_KEY_DEFAULT")"

  if [[ -f "$SA_KEY_PATH" ]]; then
    ok "Service-account key found at $SA_KEY_PATH"
    set +e
    sa_email="$("$PY_EXE" -c "
import json, sys
with open('$SA_KEY_PATH') as f:
    d = json.load(f)
print(d.get('client_email', '(unknown)'))
" 2>&1)"
    set -e
    info "Service account: $sa_email"
  else
    fail "File not found: $SA_KEY_PATH"
    warn "Copy your service-account key there before starting the feedback services."
  fi

  echo ""
  echo "The feedback Sheet ID is the long string in the Google Sheets URL:"
  echo "  https://docs.google.com/spreadsheets/d/<SHEET_ID>/edit"
  FB_SHEET_ID="$(prompt "Google Sheet ID for feedback collection" "1uOqnq1HYOocLlqcZdJAJrZUWYIbPHuPasKVp0d4tXgM")"

  FB_PORT="$(prompt "Feedback server port" "8090")"

  # Extract space ID from webhook URL as a sensible default
  _space_default=""
  if [[ -n "${WEBHOOK:-}" ]]; then
    _space_default="$(echo "$WEBHOOK" | grep -oP 'spaces/[^/]+' || true)"
  fi
  echo ""
  echo "The Chat Space ID is required for interactive feedback buttons (Helpful / Not Helpful / Custom)."
  echo "Format: spaces/XXXXXXXXX  (extract from your webhook URL or Google Chat API)."
  if [[ -n "$_space_default" ]]; then
    echo "  Detected from your webhook URL: $_space_default"
  fi
  GC_SPACE_ID="$(prompt "Google Chat Space ID" "$_space_default")"

  if [[ -n "$GC_SPACE_ID" && -f "$SA_KEY_PATH" ]]; then
    echo ""
    echo "Testing Chat API access (space: $GC_SPACE_ID)..."
    set +e
    chat_test="$("$PY_EXE" -c "
from google.oauth2 import service_account
from googleapiclient.discovery import build
creds = service_account.Credentials.from_service_account_file(
    '$SA_KEY_PATH',
    scopes=['https://www.googleapis.com/auth/chat.bot'],
)
svc = build('chat', 'v1', credentials=creds)
space = svc.spaces().get(name='$GC_SPACE_ID').execute()
print(space.get('displayName', space.get('name', 'OK')))
" 2>&1)"
    chat_ec=$?
    set -e
    if [[ "$chat_ec" -eq 0 && -n "$chat_test" && ! "$chat_test" =~ "Error" && ! "$chat_test" =~ "Traceback" ]]; then
      ok "Chat API works — space: $chat_test"
    else
      fail "Could not access space $GC_SPACE_ID via Chat API"
      warn "Error: ${chat_test:0:200}"
      warn "Interactive feedback buttons will fall back to link mode."
    fi
  fi

  if [[ -f "$SA_KEY_PATH" && -n "$FB_SHEET_ID" ]]; then
    echo ""
    echo "Testing Sheets API access..."
    set +e
    sheets_test="$("$PY_EXE" -c "
from google.oauth2 import service_account
from googleapiclient.discovery import build
creds = service_account.Credentials.from_service_account_file(
    '$SA_KEY_PATH',
    scopes=['https://www.googleapis.com/auth/spreadsheets.readonly'],
)
svc = build('sheets', 'v4', credentials=creds)
result = svc.spreadsheets().get(spreadsheetId='$FB_SHEET_ID', fields='properties.title').execute()
print(result['properties']['title'])
" 2>&1)"
    sheets_ec=$?
    set -e
    if [[ "$sheets_ec" -eq 0 && -n "$sheets_test" && ! "$sheets_test" =~ "Error" && ! "$sheets_test" =~ "Traceback" ]]; then
      ok "Sheets API works — sheet: $sheets_test"
      FB_OK=true
    else
      fail "Could not read sheet $FB_SHEET_ID"
      warn "Error: ${sheets_test:0:200}"
      warn "Ensure the sheet is shared with the service account (editor)."
    fi
  fi

else
  info "Feedback loop disabled — analysts will not be able to submit verdicts via Chat"
fi

# ── 7. Auto-remediation + advanced settings ─────────────────────────────────
hr
echo "STEP 7/9  Auto-remediation + advanced settings"
echo ""
echo "Auto-remediation runs safe, reversible fixes for known health issues"
echo "(cache clearing, shard reroute, ILM retry, stale index cleanup, etc.)."
echo "It runs automatically 5 minutes after the daily report so it can act"
echo "on any issues the report detects."
echo ""

# Auto-derive: daily report time + 5 minutes
_rem_hour="${DAILY%%:*}"
_rem_min="${DAILY##*:}"
_rem_hour="${_rem_hour#0}"   # strip leading zero for arithmetic
_rem_min="${_rem_min#0}"
_rem_min=$(( (_rem_min + 5) ))
if [[ "$_rem_min" -ge 60 ]]; then
  _rem_min=$(( _rem_min - 60 ))
  _rem_hour=$(( (_rem_hour + 1) % 24 ))
fi
AUTO_REM_TIME="$(printf '%02d:%02d' "$_rem_hour" "$_rem_min")"
info "Auto-remediation will run daily at $AUTO_REM_TIME (5 min after report at $DAILY)"

echo ""
echo "--- Disabled health scenarios ---"
echo "Comma-separated list of health-check scenario names to skip (leave empty for none)."
echo "Example: disk_space,shard_count"
ES_DISABLED_SCENARIOS="$(prompt "ES_HEALTH_DISABLED_SCENARIOS" "")"

# Bootstrap SYSTEM_MEMORY.md if it does not exist
SYSMEM_PATH="$AGENT_DIR/SYSTEM_MEMORY.md"
# Ensure AGENT_DIR is writable before writing SYSTEM_MEMORY.md
if [[ ! -w "$AGENT_DIR" ]]; then
  warn "Agent directory is not writable by $(whoami) — fixing ownership"
  sudo chown -R "$(id -u):$(id -g)" "$AGENT_DIR" || {
    fail "Cannot fix ownership of $AGENT_DIR"
    echo "  Run manually:  sudo chown -R \$(id -u):\$(id -g) $AGENT_DIR"
    exit 1
  }
fi
if [[ ! -f "$SYSMEM_PATH" ]]; then
  echo ""
  info "Initializing SYSTEM_MEMORY.md (empty — the feedback judge populates it)"
  "$PY_EXE" -c "
import sys
sys.path.insert(0, '$AGENT_DIR')
from system_memory import initialize_system_memory
initialize_system_memory()
"
  if [[ -f "$SYSMEM_PATH" ]]; then
    ok "Created $SYSMEM_PATH"
  else
    warn "Could not create SYSTEM_MEMORY.md — it will be created on first feedback"
  fi
else
  ok "SYSTEM_MEMORY.md already exists"
fi

# ── 8. Write .env ────────────────────────────────────────────────────────────
hr
echo "STEP 8/9  Writing configuration"
echo ""

ENV_FILE="$REPO_ROOT/.env"

# If .env exists but is owned by root (e.g. prior install ran as root), fix it
if [[ -f "$ENV_FILE" && ! -w "$ENV_FILE" ]]; then
  warn ".env exists but is not writable by $(whoami) — fixing ownership"
  if ! sudo chown "$(id -u):$(id -g)" "$ENV_FILE"; then
    fail "Cannot fix ownership of $ENV_FILE"
    echo "  Run manually:  sudo chown \$(id -u):\$(id -g) $ENV_FILE"
    exit 1
  fi
fi
# Ensure the parent directory is writable (covers fresh installs where repo dir is root-owned)
if [[ ! -w "$(dirname "$ENV_FILE")" ]]; then
  warn "Repo directory is not writable by $(whoami) — fixing ownership"
  if ! sudo chown "$(id -u):$(id -g)" "$(dirname "$ENV_FILE")"; then
    fail "Cannot write to $(dirname "$ENV_FILE")"
    echo "  Run manually:  sudo chown -R \$(id -u):\$(id -g) $REPO_ROOT"
    exit 1
  fi
fi

{
  echo "# Generated by install.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  echo "# ── Elasticsearch ──"
  echo "ES_HOST=$(escape_env "$ES_HOST")"
  echo "KIBANA_HOST=$(escape_env "$KIBANA_HOST")"
  echo "ES_AUTH_TYPE=$(escape_env "$ES_AUTH_TYPE")"
  if [[ "$ES_AUTH_TYPE" == "apikey" ]]; then
    echo "ES_API_KEY=$(escape_env "$ES_API_KEY")"
    echo "ES_USERNAME="
    echo "ES_PASSWORD="
  else
    echo "ES_API_KEY="
    echo "ES_USERNAME=$(escape_env "$ES_USER")"
    echo "ES_PASSWORD=$(escape_env "$ES_PASS")"
  fi
  echo ""
  echo "ES_PROCESS_INDEX=$(escape_env "$PROC")"
  echo "ES_NETWORK_INDEX=$(escape_env "$NET")"
  echo "ES_DISCOVERY_INDEX=$(escape_env "$DISC")"
  echo ""
  echo "ES_QUERY_SLOW_SEC=2.0"
  echo "ES_QUERY_CRITICAL_SEC=10.0"
  echo ""
  echo "# ── Google Chat ──"
  echo "GC_ALERT_WEBHOOK=$(escape_env "$WEBHOOK")"
  echo "GC_ALERT_SPACE_NAME=$(escape_env "$SPACE")"
  echo "GC_CARD_LOGO_URL=$(escape_env "$GC_LOGO")"
  echo ""
  echo "# ── Logging ──"
  echo "LOG_LEVEL=INFO"
  echo ""
  echo "# ── Alerting ──"
  echo "ES_ALERT_COOLDOWN_HOURS=$COOL"
  echo "ES_HEALTH_MONITOR_INTERVAL_SECONDS=$POLL"
  echo ""
  echo "# ── LLM ──"
  echo "LLM_ENABLED=$LLM_ENABLED_VAR"
  echo "LLM_MODEL=$(escape_env "$LLM_MODEL_VAR")"
  echo "ES_HEALTH_LLM_MODEL=$(escape_env "$LLM_MODEL_VAR")"
  echo "OLLAMA_URL=$(escape_env "$OLLAMA_URL_VAR")"
  if [[ -n "${OPENAI_KEY:-}" ]]; then
    echo "OPENAI_API_KEY=$(escape_env "$OPENAI_KEY")"
  fi
  if [[ -n "${ANTHROPIC_KEY:-}" ]]; then
    echo "ANTHROPIC_API_KEY=$(escape_env "$ANTHROPIC_KEY")"
  fi
  echo ""
  echo "# ── Scheduler ──"
  echo "MAINTENANCE_IANA_TIMEZONE=$(escape_env "$TZ_IANA")"
  echo "DAILY_REPORT_TIME_CAT=$(escape_env "$DAILY")"
  echo ""
  echo "# ── Feedback loop ──"
  if [[ -n "${SA_KEY_PATH:-}" ]]; then
    echo "GOOGLE_CHAT_SA_KEY=$(escape_env "$SA_KEY_PATH")"
  fi
  if [[ -n "${GC_SPACE_ID:-}" ]]; then
    echo "GOOGLE_CHAT_SPACE_ID=$(escape_env "$GC_SPACE_ID")"
  fi
  if [[ -n "${FB_SHEET_ID:-}" ]]; then
    echo "FEEDBACK_SHEET_ID=$(escape_env "$FB_SHEET_ID")"
  fi
  echo "FEEDBACK_SERVER_PORT=${FB_PORT:-8090}"
  echo ""
  echo "# ── Auto-remediation ──"
  echo "AUTO_REMEDIATION_TIME=$(escape_env "$AUTO_REM_TIME")"
  echo "AUTO_REMEDIATION_DRY_RUN=false"
  if [[ -n "${ES_DISABLED_SCENARIOS:-}" ]]; then
    echo "ES_HEALTH_DISABLED_SCENARIOS=$(escape_env "$ES_DISABLED_SCENARIOS")"
  fi
  echo ""
  echo "# ── Miscellaneous ──"
  echo "ML_FILE_RETENTION_DAYS=7"
  echo "DAILY_REPORT_ATTACH_ES_LOGS=false"
  echo "DAILY_REPORT_ATTACH_ES_JSON=false"
} > "$ENV_FILE"

# Ensure AGENT_DIR is writable so we can copy .env into it
if [[ ! -w "$AGENT_DIR" ]]; then
  warn "Agent directory is not writable by $(whoami) — fixing ownership"
  sudo chown -R "$(id -u):$(id -g)" "$AGENT_DIR" || {
    fail "Cannot fix ownership of $AGENT_DIR"
    echo "  Run manually:  sudo chown -R \$(id -u):\$(id -g) $AGENT_DIR"
    exit 1
  }
fi
# If the target .env already exists but is not writable, fix it
if [[ -f "$AGENT_DIR/.env" && ! -w "$AGENT_DIR/.env" ]]; then
  warn "$AGENT_DIR/.env is not writable by $(whoami) — fixing ownership"
  sudo chown "$(id -u):$(id -g)" "$AGENT_DIR/.env" || {
    fail "Cannot fix ownership of $AGENT_DIR/.env"
    echo "  Run manually:  sudo chown \$(id -u):\$(id -g) $AGENT_DIR/.env"
    exit 1
  }
fi

cp "$ENV_FILE" "$AGENT_DIR/.env"
ok "Wrote $ENV_FILE (and copied to Agent-SIEM-maintenance/.env)"

# ── 9. Verification + start ─────────────────────────────────────────────────
hr
echo "STEP 9/9  Verify and start"
echo ""

read -r -p "Run verify_setup.py? (Y/n): " verify_ans
verify_ans="${verify_ans:-Y}"
if [[ ! "$verify_ans" =~ ^[Nn]$ ]]; then
  echo ""
  echo "--- Verification ---"
  set +e
  (cd "$REPO_ROOT" && "$PY_EXE" "$REPO_ROOT/verify_setup.py")
  verify_ec=$?
  set -e
  if [[ "$verify_ec" -ne 0 ]]; then
    warn "verify_setup.py exited $verify_ec — review issues above"
  fi
fi

# Systemd or nohup
MS_PATH="$AGENT_DIR/maintenance_service.py"
LOG_DIR="$REPO_ROOT/logs"
OUT_LOG="$LOG_DIR/maintenance_service.log"
PID_FILE="$LOG_DIR/maintenance_service.pid"

systemd_started=false
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] && [[ "$(uname -s)" == "Linux" ]]; then
  echo ""
  read -r -p "Install systemd service siem-maintenance.service (survives reboot)? (Y/n): " inst_unit
  inst_unit="${inst_unit:-Y}"
  if [[ ! "$inst_unit" =~ ^[Nn]$ ]]; then
    echo ""
    SD_SCRIPT="$REPO_ROOT/deploy/install-systemd-service.sh"
    if [[ ! -f "$SD_SCRIPT" ]]; then
      warn "Missing $SD_SCRIPT — skipping systemd"
    elif sudo -n true 2>/dev/null || sudo -v; then
      set +e
      sudo bash "$SD_SCRIPT" "$REPO_ROOT" "$PY_EXE"
      sd_ec=$?
      set -e
      if [[ "$sd_ec" -eq 0 ]]; then
        systemd_started=true
        ok "Scheduler managed by systemd"
      else
        warn "systemd install exited $sd_ec — run: sudo bash $SD_SCRIPT $REPO_ROOT $PY_EXE"
      fi
    else
      warn "Could not get sudo; run later: sudo bash $SD_SCRIPT $REPO_ROOT $PY_EXE"
    fi
  fi
fi

fb_systemd_ok=false
if [[ "$systemd_started" == true && ! "$fb_enable" =~ ^[Nn]$ ]]; then
  echo ""
  read -r -p "Install feedback systemd services (feedback server + poller)? (Y/n): " inst_fb_units
  inst_fb_units="${inst_fb_units:-Y}"
  if [[ ! "$inst_fb_units" =~ ^[Nn]$ ]]; then
    FB_SVC_UNIT="$REPO_ROOT/deploy/siem-feedback.service"
    FB_POLL_UNIT="$REPO_ROOT/deploy/siem-feedback-poller.service"

    # Generate correctly-pathed unit files from templates
    _fb_svc_tmp="$(mktemp)"
    _fb_poll_tmp="$(mktemp)"
    trap 'rm -f "$_fb_svc_tmp" "$_fb_poll_tmp"' EXIT

    cat > "$_fb_svc_tmp" <<FBSVC
[Unit]
Description=SIEM-MAINTENANCE feedback server (Google Chat webhook receiver)
After=network-online.target siem-maintenance.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$AGENT_DIR
User=$(whoami)
Group=$(id -gn)
ExecStart=$PY_EXE $AGENT_DIR/feedback_server.py --host 0.0.0.0 --port ${FB_PORT:-8090}
Restart=on-failure
RestartSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=siem-feedback

[Install]
WantedBy=multi-user.target
FBSVC

    cat > "$_fb_poll_tmp" <<FBPOLL
[Unit]
Description=SIEM feedback poller (reads Google Sheet, runs judge, updates SYSTEM_MEMORY.md)
Documentation=https://github.com/cylab-africa/Siem-Maintenance-Agent-Monitoring
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$AGENT_DIR
User=$(whoami)
Group=$(id -gn)
ExecStart=$PY_EXE $AGENT_DIR/feedback_poller.py --loop 60
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=siem-feedback-poller

[Install]
WantedBy=multi-user.target
FBPOLL

    if sudo -n true 2>/dev/null || sudo -v; then
      set +e
      sudo cp "$_fb_svc_tmp" /etc/systemd/system/siem-feedback.service
      sudo cp "$_fb_poll_tmp" /etc/systemd/system/siem-feedback-poller.service
      sudo chmod 0644 /etc/systemd/system/siem-feedback.service /etc/systemd/system/siem-feedback-poller.service
      sudo systemctl daemon-reload
      sudo systemctl enable siem-feedback.service siem-feedback-poller.service
      sudo systemctl restart siem-feedback.service siem-feedback-poller.service
      fb_sd_ec=$?
      set -e
      if [[ "$fb_sd_ec" -eq 0 ]]; then
        fb_systemd_ok=true
        ok "Feedback server + poller managed by systemd"
      else
        warn "Feedback systemd install had issues — check: systemctl status siem-feedback siem-feedback-poller"
      fi
    else
      warn "Could not get sudo — install manually:"
      warn "  sudo cp $_fb_svc_tmp /etc/systemd/system/siem-feedback.service"
      warn "  sudo cp $_fb_poll_tmp /etc/systemd/system/siem-feedback-poller.service"
      warn "  sudo systemctl daemon-reload && sudo systemctl enable --now siem-feedback siem-feedback-poller"
    fi
  fi
fi

if [[ "$systemd_started" != true ]]; then
  echo ""
  read -r -p "Start the maintenance scheduler in the background now? (Y/n): " start_sched
  start_sched="${start_sched:-Y}"
  if [[ ! "$start_sched" =~ ^[Nn]$ ]]; then
    if [[ ! -f "$MS_PATH" ]]; then
      warn "maintenance_service.py not found at $MS_PATH"
    else
      # Ensure log directory exists and is writable
      if [[ -d "$LOG_DIR" && ! -w "$LOG_DIR" ]]; then
        warn "Log directory is not writable by $(whoami) — fixing ownership"
        sudo chown -R "$(id -u):$(id -g)" "$LOG_DIR" || {
          fail "Cannot fix ownership of $LOG_DIR"
          echo "  Run manually:  sudo chown -R \$(id -u):\$(id -g) $LOG_DIR"
          exit 1
        }
      elif [[ ! -d "$LOG_DIR" && ! -w "$REPO_ROOT" ]]; then
        warn "Repo root is not writable — fixing ownership to create logs/"
        sudo chown "$(id -u):$(id -g)" "$REPO_ROOT" || {
          fail "Cannot write to $REPO_ROOT"
          echo "  Run manually:  sudo chown -R \$(id -u):\$(id -g) $REPO_ROOT"
          exit 1
        }
      fi
      mkdir -p "$LOG_DIR"
      if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
        warn "Scheduler may already be running (PID $(cat "$PID_FILE"))."
        read -r -p "Start a second copy anyway? (y/N): " start_anyway
        if [[ ! "$start_anyway" =~ ^[Yy]$ ]]; then
          echo "Skipped. Stop the old process with: kill $(cat "$PID_FILE")"
          start_sched="n"
        fi
      fi
      if [[ ! "$start_sched" =~ ^[Nn]$ ]]; then
        nohup "$PY_EXE" "$MS_PATH" >>"$OUT_LOG" 2>&1 &
        sched_pid=$!
        echo "$sched_pid" >"$PID_FILE"
        ok "Scheduler started (PID $sched_pid)"
        info "Log: $OUT_LOG"
        info "Stop: kill $sched_pid"
      fi
    fi
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
hr
echo ""
echo "  SETUP COMPLETE"
echo ""
printf '  %-28s ' "Elasticsearch:"
if [[ "$ES_OK" == true ]]; then
  printf '\e[32m%s\e[0m\n' "connected ($es_test)"
else
  printf '\e[31m%s\e[0m\n' "not reachable"
fi
printf '  %-28s ' "ES auth:"
if [[ "${ES_AUTH_TYPE:-userpass}" == "apikey" ]]; then
  printf '%s\n' "API key"
else
  printf '%s\n' "username/password"
fi
printf '  %-28s ' "Google Chat webhook:"
if [[ "$GC_OK" == true ]]; then
  printf '\e[32m%s\e[0m\n' "working"
elif [[ -z "$WEBHOOK" ]]; then
  printf '\e[33m%s\e[0m\n' "not configured"
else
  printf '\e[31m%s\e[0m\n' "failed"
fi
printf '  %-28s ' "Card logo:"
if [[ -n "$GC_LOGO" ]]; then
  printf '%s\n' "set"
else
  printf '%s\n' "none"
fi
printf '  %-28s ' "LLM:"
if [[ "$prov" == "4" ]]; then
  printf '%s\n' "disabled"
elif [[ "$LLM_OK" == true ]]; then
  _prov_name="Ollama"
  [[ "$prov" == "1" ]] && _prov_name="OpenAI"
  [[ "$prov" == "3" ]] && _prov_name="Anthropic"
  printf '\e[32m%s\e[0m\n' "$LLM_MODEL_VAR ($_prov_name)"
else
  printf '\e[31m%s\e[0m\n' "not working ($LLM_MODEL_VAR)"
fi
printf '  %-28s %s\n' "Daily report:" "${DAILY} ${TZ_IANA}"
printf '  %-28s %ss\n' "Health poll interval:" "$POLL"
printf '  %-28s %sh\n' "Alert cooldown:" "$COOL"
printf '  %-28s ' "Feedback loop:"
if [[ "$FB_OK" == true ]]; then
  printf '\e[32m%s\e[0m\n' "enabled (sheet + SA key verified)"
elif [[ ! "${fb_enable:-Y}" =~ ^[Nn]$ && -n "${SA_KEY_PATH:-}" ]]; then
  printf '\e[33m%s\e[0m\n' "enabled (SA key set, sheet not verified)"
else
  printf '\e[33m%s\e[0m\n' "disabled"
fi
printf '  %-28s ' "Chat App (interactive btns):"
if [[ -n "${GC_SPACE_ID:-}" && -n "${SA_KEY_PATH:-}" ]]; then
  printf '\e[32m%s\e[0m\n' "enabled ($GC_SPACE_ID)"
else
  printf '\e[33m%s\e[0m\n' "disabled (GOOGLE_CHAT_SPACE_ID not set)"
fi
printf '  %-28s ' "Auto-remediation:"
printf '\e[32m%s\e[0m\n' "daily at ${AUTO_REM_TIME} ${TZ_IANA} (report +5 min)"
printf '  %-28s ' "Scheduler:"
if [[ "$systemd_started" == true ]]; then
  printf '\e[32m%s\e[0m\n' "systemd (siem-maintenance.service)"
elif [[ "${sched_pid:-}" ]]; then
  printf '\e[32m%s\e[0m\n' "background (PID $sched_pid)"
else
  printf '\e[33m%s\e[0m\n' "not started"
fi
printf '  %-28s ' "Feedback services:"
if [[ "${fb_systemd_ok:-false}" == true ]]; then
  printf '\e[32m%s\e[0m\n' "systemd (siem-feedback + siem-feedback-poller)"
elif [[ ! "${fb_enable:-Y}" =~ ^[Nn]$ ]]; then
  printf '\e[33m%s\e[0m\n' "not installed as systemd (run manually)"
else
  printf '\e[33m%s\e[0m\n' "disabled"
fi
echo ""
echo "  Config: $ENV_FILE"
if [[ "$use_venv" =~ ^[Nn]$ ]]; then
  echo "  Run:    python3 $MS_PATH"
else
  echo "  Run:    source $VENV_DIR/bin/activate && python $MS_PATH"
fi
echo "  Logs:   journalctl -u siem-maintenance -f  (systemd)"
echo "          tail -f $OUT_LOG  (nohup)"
if [[ "${fb_systemd_ok:-false}" == true ]]; then
  echo "          journalctl -u siem-feedback -f  (feedback server)"
  echo "          journalctl -u siem-feedback-poller -f  (feedback poller)"
fi
echo ""
