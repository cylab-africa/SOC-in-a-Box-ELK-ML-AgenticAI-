# Greenbone scan results (gvm-siem-push)

Sends finished [Greenbone / OpenVAS](https://www.greenbone.net/) vulnerability
scans to Elasticsearch, so you can search them in Kibana. Each finding is
labelled with what changed since the previous scan.

- Reads each scan task's latest finished report through Greenbone's local
  `gvmd` socket.
- Keeps the findings Greenbone's own report view shows: severity above 0,
  Quality of Detection 70 or more, overrides applied.
- Labels every finding `new`, `same`, `changed` or `fixed` compared with the
  task's previous scan.
- Sends each report once. Sending it again overwrites; it never duplicates.

## Requirements

- **Greenbone installed and running on the same server.** This add-on does not
  install it. To install Greenbone Community Edition (needs Docker):

  ```bash
  curl -f -O -L https://greenbone.github.io/docs/latest/_static/setup-and-start-greenbone-community-edition.sh
  chmod u+x setup-and-start-greenbone-community-edition.sh
  ./setup-and-start-greenbone-community-edition.sh
  ```

  Guide: [Greenbone Community Containers](https://greenbone.github.io/docs/latest/22.4/container/).
- A Greenbone user that can see the scan tasks and reports.
- An Elasticsearch 8 user that can create and write the target index (not a
  superuser).
- Python 3.9 or later.

Tested with Greenbone Community Edition (Docker Compose, feed 24.10) and
Elasticsearch 8.

## Install with SOC-in-a-Box

From the repository root, once Greenbone is running:

```bash
./deploy.sh --only greenbone
```

It reuses the Elasticsearch settings, finds Greenbone's socket, asks for your
Greenbone login, tests the connection, and schedules a push **every Sunday at
06:00** (as root, because the socket belongs to root).

Another day or time: `GREENBONE_DAY=Sat GREENBONE_TIME=03:00 ./deploy.sh --only greenbone`.

| To... | Run (from the repository root) |
|---|---|
| See the next push | `systemctl list-timers gvm-siem-push.timer` |
| Push now | `sudo systemctl start gvm-siem-push.service` |
| See what the last push did | `journalctl -u gvm-siem-push.service`, or `logs/greenbone-push.log` |
| Preview without sending | `sudo addons/greenbone/.venv/bin/python addons/greenbone/gvm_siem_push.py --env-file addons/greenbone/.env --dry-run` |
| Stop the weekly push | `sudo systemctl disable --now gvm-siem-push.timer` |

Settings are in `addons/greenbone/.env`.

## Install on its own

Without SOC-in-a-Box, on the Greenbone server. Any paths work; these are a
suggestion:

```bash
sudo mkdir -p /opt/gvm-siem /etc/gvm-siem /var/log/gvm-siem
sudo cp gvm_siem_push.py requirements.txt /opt/gvm-siem/
sudo python3 -m venv /opt/gvm-siem/venv
sudo /opt/gvm-siem/venv/bin/pip install -r /opt/gvm-siem/requirements.txt

sudo cp examples/gvm-siem.env.example /etc/gvm-siem/gvm-siem.env
sudo chmod 600 /etc/gvm-siem/gvm-siem.env
sudo nano /etc/gvm-siem/gvm-siem.env      # fill in the values
```

Run it (always start with `--dry-run`: it reads everything and sends nothing):

```bash
PUSH="sudo /opt/gvm-siem/venv/bin/python /opt/gvm-siem/gvm_siem_push.py --env-file /etc/gvm-siem/gvm-siem.env"
$PUSH --dry-run    # preview
$PUSH              # send reports finished since the last successful run
$PUSH --full       # resend every task's latest report (first run, or after deleting the index)
```

Schedule it weekly with cron, a few hours after your scans finish
([example](examples/crontab.example)):

```
# sudo crontab -e
0 6 * * 0 /opt/gvm-siem/venv/bin/python /opt/gvm-siem/gvm_siem_push.py --env-file /etc/gvm-siem/gvm-siem.env >> /var/log/gvm-siem/cron.log 2>&1
```

A report still running at push time is sent on the next run.

## Settings

From environment variables, or the file given with `--env-file` (default
`~/.gvm_elastic.env`). Environment variables win. Example:
[`examples/gvm-siem.env.example`](examples/gvm-siem.env.example).

| Setting | Required | Default | Purpose |
| --- | --- | --- | --- |
| `GVM_SOCKET` | Yes | | Path to Greenbone's `gvmd.sock` |
| `GVM_USERNAME` | No | `admin` | Greenbone user |
| `GVM_PASSWORD` | Yes | | Greenbone password |
| `ES_HOST` | Yes | | Elasticsearch address, e.g. `https://10.0.0.5:9200` |
| `ES_USERNAME`, `ES_PASSWORD` | Yes | | Elasticsearch login |
| `ES_INDEX` | No | `gvm-vulnerabilities` | Target index |
| `ES_CA_CERTS` | No | | Certificate authority for Elasticsearch (`ES_CA_CERT` also works) |
| `ES_VERIFY_CERTS` | No | `true` | `false` only if you have no CA certificate |
| `ES_COMPAT_VERSION` | No | | Only for a 9.x Python client against Elasticsearch 8 |
| `MIN_SEVERITY` | No | `0.0` | Send only findings above this severity |
| `MIN_QOD` | No | `70` | Minimum Quality of Detection |
| `APPLY_OVERRIDES` | No | `true` | Apply overrides set in Greenbone |
| `COMPARE_PREVIOUS` | No | `true` | Add the `delta_status` labels |
| `GVM_TIMEOUT` | No | `600` | Seconds to wait for Greenbone per request |
| `STATE_FILE` | No | `~/.gvm_last_run` | Where the last successful run time is kept |
| `LOG_FILE` | No | | Log file (rotated at 5 MB, 5 kept) |
| `LOG_LEVEL` | No | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |

## Using the data in Kibana

Add `gvm-vulnerabilities` as a data view. Each document is one finding.

| `delta_status` | Meaning |
| --- | --- |
| `new` | Not in the previous scan of this task |
| `same` | In both scans, unchanged |
| `changed` | In both scans, but its text changed (usually version details) |
| `fixed` | In the previous scan, gone from this one |
| `baseline` | The task's first scan: nothing to compare with |
| `unknown` | The comparison failed; the finding is still sent |

| Question | KQL |
| --- | --- |
| What is new since the last scan? | `delta_status : new` |
| What was fixed? | `delta_status : fixed` |
| Open findings only | `not delta_status : fixed` |
| Is a CVE present anywhere? | `cve : "CVE-2024-12345"` |
| Critical and High only | `severity_label : (Critical or High)` |

Main fields: `task_name`, `report_id`, `previous_report_id`, `delta_status`,
`scan_end`, `host`, `hostname`, `port`, `name`, `nvt_oid`, `severity`,
`severity_label`, `cvss_base`, `cve`, `qod`, `solution`, `solution_type`.

To count open vulnerabilities on a dashboard, exclude `delta_status : fixed`
and use only each task's latest `scan_end`, or older scans are counted again.

Example output of a run:

```
[INFO] Weekly Scan: report 1a2b3c4d-... (finished 2026-01-10T01:30:00+00:00)
[INFO]   75 finding(s) in this scan; compared with 9f8e7d6c-...: changed 25, fixed 1, same 50
[INFO]   Indexed 76 document(s).
[INFO] Done. 1 report(s) pushed, 3 skipped. Index: gvm-vulnerabilities
```

## Troubleshooting

| Message or symptom | Fix |
| --- | --- |
| `Missing required settings: ...` | Add the setting to the env file; check `--env-file` points to it |
| `Permission denied` on the socket | Run with `sudo` |
| `Elasticsearch error: ...` | Check `ES_HOST`, the login and `ES_CA_CERTS` |
| `Could not compare with the previous scan (timed out)` | Raise `GVM_TIMEOUT`. Findings are still sent, labelled `unknown` |
| `Some documents failed to index` | Read the first error in the log. The next run retries in full |
| `Could not read this report from GVM` | That task is retried next run; the others are still sent |
| Every task says `latest report already pushed`, but data is missing | Run once with `--full` |

Tasks in Greenbone's trashcan are ignored. The exit code is 0 on success and 1
on any error.

## Security

- Keep the env file readable only by its owner (`chmod 600`). Never commit it.
- Prefer `ES_CA_CERTS` over `ES_VERIFY_CERTS=false`.
- Give the Elasticsearch user write access to the target index only.

## License

[MIT](../../LICENSE)
