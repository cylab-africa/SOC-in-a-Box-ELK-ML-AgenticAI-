# SIEM Maintenance Agent

Watches your Elasticsearch security cluster around the clock, alerts your team
on Google Chat when something goes wrong, and can fix common problems itself.

- **Health checks:** cluster status, node heap, disk and CPU, rejected
  requests, and whether endpoint data is still arriving.
- **Daily report** to Google Chat every morning, with optional AI-written
  analysis (OpenAI, Anthropic Claude or a local Ollama model).
- **Alerts** to Google Chat when a check crosses a threshold, spaced out by a
  cooldown so the channel is not flooded.
- **Automatic fixes** for common problems (optional; off by default in
  SOC-in-a-Box).

Designed by Noah Shumba ([nshumba@andrew.cmu.edu](mailto:nshumba@andrew.cmu.edu)),
CMU-Africa Upanzi Network.

## Before you install

| You need | Notes |
|---|---|
| Python 3.10+ | On Debian/Ubuntu also: `sudo apt install -y python3-venv` |
| Elasticsearch address and login | |
| A Google Chat webhook URL | [How to get one](#get-a-google-chat-webhook) |
| An AI model (optional) | OpenAI or Anthropic API key, or Ollama. Without one, reports and alerts still work, without the AI text |

### Get a Google Chat webhook

1. In Google Chat, open or create the space for the alerts (e.g. `SIEM-MAINTENANCE`).
2. Click the space name → **Apps & integrations** → **Add webhooks**.
3. Name it (e.g. `SIEM Maintenance Bot`) → **Save**, and copy the URL. It looks like
   `https://chat.googleapis.com/v1/spaces/AAAA.../messages?key=...&token=...`

No webhook option? Your Google Workspace admin must allow incoming webhooks:
**Admin Console → Apps → Google Chat**.

## Install with SOC-in-a-Box

From the repository root:

```bash
./deploy.sh --only maintenance
```

It reuses the Elasticsearch settings and asks for the Chat webhook, timezone,
report time, AI model, and whether fixes are applied automatically or only
reported. To also set up the Chat feedback buttons, use the full installer
instead: `./deploy.sh --maintenance-wizard`.

| To... | Run |
|---|---|
| Check it is running | `systemctl status siem-maintenance` |
| Follow its log | `journalctl -u siem-maintenance -f` |
| Restart after editing `.env` | `sudo systemctl restart siem-maintenance` |
| Stop it | `sudo systemctl disable --now siem-maintenance` |

Without systemd, its log is `logs/siem-maintenance.log` in the repository root.

## Install on its own

From this directory:

```bash
bash install.sh                                          # Linux / macOS
powershell -ExecutionPolicy Bypass -File .\install.ps1   # Windows
```

The installer creates `.venv`, asks for the settings above, writes `.env` (and
copies it to `Agent-SIEM-maintenance/.env`), checks the setup and starts the
agent. On Linux with systemd it offers to install `siem-maintenance.service`,
which starts at boot. Otherwise it starts the agent in the background (log:
`logs/maintenance_service.log`; stop it with `kill $(cat logs/maintenance_service.pid)`).

`bash run-all.sh` (or `run-all.ps1`) does the install, the checks and a
foreground start in one go.

**Windows has no systemd:** to start it at boot, create a Task Scheduler task
that runs `.venv\Scripts\python.exe Agent-SIEM-maintenance\maintenance_service.py`
in the `Agent-SIEM-maintenance` folder.

## Check it works

```bash
python verify_setup.py                  # checks .env, packages, Elasticsearch and Ollama
python verify_setup.py --skip-network   # only .env and packages
```

Run one job now instead of waiting for its schedule (from this directory, with
`.venv` active):

```bash
python Agent-SIEM-maintenance/maintenance_service.py --once-poll        # health check
python Agent-SIEM-maintenance/maintenance_service.py --once-daily       # daily report
python Agent-SIEM-maintenance/maintenance_service.py --once-remediate   # fixes
```

## When things run

Finishing the install does not send a message straight away. The agent runs
these on its own schedule:

| Job | When | Settings |
|---|---|---|
| Daily report | Every day at 08:30 | `DAILY_REPORT_TIME_CAT`, `MAINTENANCE_IANA_TIMEZONE` |
| Health check | Every 2 hours; a Chat alert only when a threshold is crossed, then at most once per cooldown (2 hours) | `ES_HEALTH_MONITOR_INTERVAL_SECONDS`, `ES_ALERT_COOLDOWN_HOURS` |
| Automatic fixes | Every day, 5 minutes after the report | `AUTO_REMEDIATION_TIME`, `AUTO_REMEDIATION_DRY_RUN` |

## Settings

In `.env`. The installer writes most of them; after editing, copy it to
`Agent-SIEM-maintenance/.env` and restart.

| Setting | What it is |
|---|---|
| `ES_HOST`, `ES_USERNAME`, `ES_PASSWORD` | Elasticsearch login |
| `KIBANA_HOST` | Kibana address, for the detection-rule status in the daily report |
| `GC_ALERT_WEBHOOK`, `GC_ALERT_SPACE_NAME` | Google Chat webhook and space name |
| `GC_CARD_LOGO_URL` | Image shown on every Chat card (optional) |
| `LLM_ENABLED`, `LLM_MODEL` | AI text on or off, and the model. `gpt-*` uses OpenAI, `claude-*` uses Anthropic, anything else uses Ollama |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_URL` | AI provider access |
| `MAINTENANCE_IANA_TIMEZONE`, `DAILY_REPORT_TIME_CAT` | Timezone and time of the daily report |
| `ES_HEALTH_MONITOR_INTERVAL_SECONDS`, `ES_ALERT_COOLDOWN_HOURS` | How often to check, and minimum time between repeated alerts |
| `ES_PROCESS_INDEX`, `ES_NETWORK_INDEX`, `ES_DISCOVERY_INDEX` | Indices checked for fresh data |
| `AUTO_REMEDIATION_TIME`, `AUTO_REMEDIATION_DRY_RUN` | Time of the daily fixes; `true` = only report what it would fix |
| `SNAPSHOT_RETENTION_DAYS`, `EMPTY_INDEX_RETENTION_DAYS` | Age before old snapshots (30 days) and empty indices (90 days) are deleted |
| `MAX_FORCE_MERGE_PER_RUN`, `MAX_EMPTY_INDEX_DELETE_PER_RUN` | Limits per run (2 and 20) |
| `DAILY_REPORT_GREETING` | First line of the report (default `Good morning team!`) |
| `DAILY_REPORT_ATTACH_ES_LOGS` | `true` adds the last 24 hours of Elasticsearch warnings and errors |
| `OLLAMA_TIMEOUT_SECONDS`, `OLLAMA_NUM_CTX` | Ollama time limit (180 s) and context size (8192); raise the context if the AI text comes back empty |

## Automatic fixes

`auto_remediate.py` investigates the cluster and applies safe, reversible
fixes. Each fix checks first, has a cooldown so it is not repeated too often,
and reports to Google Chat. Every action is logged to
`Agent-SIEM-maintenance/results/auto_remediation_log.jsonl`.

Indices holding endpoint data and alerts (`.ds-logs-endpoint.events.*`,
`.internal.alerts-*`) are never deleted or changed.

| Fix | What it does | When |
|---|---|---|
| `scroll-contexts` | Clears abandoned search scrolls | Over 80% of the limit, or over 50 |
| `unassigned-shards` | Retries failed shard allocation | Any unassigned shards |
| `thread-pools` | Raises search and write queue sizes (temporary) | Over 100 search or 50 write rejections |
| `fielddata` | Clears the fielddata cache | Over 100 MB |
| `caches` | Clears request and query caches | A node's heap at 80% or more |
| `ilm` | Restarts index lifecycle management, retries failed indices | ILM stopped or indices in error |
| `force-merge` | Merges over-segmented read-only indices | Over 50 segments per shard, 1 GB or more, not essential |
| `cleanup` | Deletes old ML result files | Older than `ML_FILE_RETENTION_DAYS` |
| `transforms` | Restarts failed or stopped transforms | Any |
| `snapshots` | Deletes old completed snapshots | Older than `SNAPSHOT_RETENTION_DAYS` |
| `empty-indices` | Deletes old empty indices | Over 90 days, 0 documents, not essential |
| `watermark-reset` | Removes the read-only block after disk space recovers | Block set and disk under 90% |
| `watchers` | Restarts a stopped Watcher | Watcher stopped |

Run it by hand, from `Agent-SIEM-maintenance/`:

```bash
python3 auto_remediate.py --investigate-only       # diagnose, change nothing
python3 auto_remediate.py --auto-fix --dry-run     # show what it would fix
python3 auto_remediate.py --auto-fix               # apply all fixes
python3 auto_remediate.py --fix watermark-reset    # apply one fix
```

## Feedback buttons (optional)

Alert cards can carry **Helpful / Not Helpful / Incorrect** buttons. Each click
is judged by an AI model, which adds, confirms or rejects a rule in
`Agent-SIEM-maintenance/SYSTEM_MEMORY.md`. Those rules are given to the AI on
later alerts, so its analysis improves with your team's feedback.

| Section of `SYSTEM_MEMORY.md` | Content | Used as |
|---|---|---|
| Active rules | Confirmed by 2 or more clicks (`FEEDBACK_PROMOTION_THRESHOLD`) | Rules to follow |
| Pending hypotheses | One click so far | Not used yet |
| Rejected patterns | Contradicted | Patterns to avoid |

Buttons need a Google Cloud project, because webhook messages cannot receive
clicks. One-time setup:

**1. Create a service account** for the bot, and save its key:

```bash
gcloud iam service-accounts create siem-chat-bot \
  --display-name="SIEM Maintenance Bot" --project=<PROJECT_ID>
gcloud iam service-accounts keys create Agent-SIEM-maintenance/siem-chat-bot-key.json \
  --iam-account=siem-chat-bot@<PROJECT_ID>.iam.gserviceaccount.com
gcloud services enable chat.googleapis.com sheets.googleapis.com script.googleapis.com \
  --project=<PROJECT_ID>
```

**2. Create a Google Sheet** named `SIEM Feedback`. Share it with the service
account's email as **Editor**, and copy its ID (between `/d/` and `/edit` in
the URL).

**3. Add the Apps Script:** in the Sheet, **Extensions → Apps Script**. Paste in
`Agent-SIEM-maintenance/deploy/Code.gs` and save. In **Project Settings**, set
your Google Cloud project number. Then **Deploy → New deployment → Google
Workspace Add-on**, and copy the **Head deployment ID**. Turn on **Google Apps
Script API** at <https://script.google.com/home/usersettings>.

**4. Register the Chat app** in Google Cloud Console → Google Chat API →
Configuration:

| Field | Value |
|---|---|
| App name | `SIEM Maintenance Bot` |
| Description | `Receives feedback on SIEM alerts` |
| Functionality | Direct messages, and joining spaces |
| Connection | **Apps Script**, with the Head deployment ID from step 3 |
| Visibility | Specific people: your email |

**5. Add the bot to your space:** space name → **Apps & integrations** → **Add
apps** → **SIEM Maintenance Bot**.

**6. Find the space ID:**

```bash
python3 -c "
from google.oauth2 import service_account
from googleapiclient.discovery import build
creds = service_account.Credentials.from_service_account_file('Agent-SIEM-maintenance/siem-chat-bot-key.json', scopes=['https://www.googleapis.com/auth/chat.bot'])
for s in build('chat', 'v1', credentials=creds).spaces().list().execute().get('spaces', []):
    print(s['name'], s.get('displayName'))
"
```

**7. Add to `.env`:**

```bash
GOOGLE_CHAT_SA_KEY=/full/path/to/Agent-SIEM-maintenance/siem-chat-bot-key.json
GOOGLE_CHAT_SPACE_ID=spaces/XXXXXXXX
GOOGLE_CHAT_VERIFICATION_TOKEN=<token from the Chat API configuration>
FEEDBACK_SHEET_ID=<sheet id from step 2>
```

**8. Process the clicks**, from `Agent-SIEM-maintenance/`:

```bash
python3 feedback_poller.py            # once
python3 feedback_poller.py --loop 60  # every 60 seconds
```

`deploy/siem-feedback-poller.service` runs the poller as a systemd service.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ensurepip is not available` | `sudo apt install -y python3-venv`, then install again |
| Import errors | `pip install -r requirements.txt` in `.venv`, then `python verify_setup.py` |
| `401` / `403` from Elasticsearch | The user needs read access to the cluster APIs and the configured indices |
| No Chat message after install | Normal: see [When things run](#when-things-run). Check the agent is running, or send one now with `--once-daily` |
| The card has no AI text | The card says why: `Ollama not reachable`, `model '<x>' not pulled` (run `ollama pull <x>`), `Ollama timed out`, or `empty response` (raise `OLLAMA_NUM_CTX`). For OpenAI, check the key and quota |
| Too many or too few alerts | Change `ES_ALERT_COOLDOWN_HOURS` and `ES_HEALTH_MONITOR_INTERVAL_SECONDS` |

## More detail

Design notes, thresholds and the alert and fix logic are in [docs/](docs/),
starting with [what is watched](docs/01-what-is-watched.md). Some describe the
target design rather than what is built today: see
[design vs this code](docs/00-design-spec-vs-this-repo.md).

## License

[MIT](LICENSE)
