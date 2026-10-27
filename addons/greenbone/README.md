# gvm-siem-push

Send finished [Greenbone / OpenVAS](https://www.greenbone.net/) scan results to Elasticsearch, labelled with what changed since the previous scan, so SOC analysts can search and analyse them in Kibana.

- Reads each scan task's latest finished report through gvmd's local socket.
- Filters findings like Greenbone's own report view: severity above 0, Quality of Detection at least 70, overrides applied.
- Compares each report with the same task's previous report and labels every finding `new`, `same`, `changed` or `fixed`.
- Sends each task's latest report if it finished since the last successful run, and never creates duplicates.
- Runs by hand or from cron; all settings and secrets live in an env file.

## How it works

On each run the script:

1. Lists the scan tasks in Greenbone and takes each task's latest finished report.
2. Skips reports already sent by a previous successful run.
3. Reads the report's findings with the filters above.
4. Asks Greenbone to compare the report with the task's previous finished report.
5. Indexes one document per finding, plus one `fixed` document for each finding that disappeared.
6. Saves the run time, but only if every document was indexed. A failed run is retried in full next time.

Each finding is stored under its Greenbone result ID, so sending the same report twice overwrites documents instead of duplicating them.

| `delta_status` | Meaning |
| --- | --- |
| `new` | In this scan, not in the previous scan of the same task |
| `same` | In both scans, unchanged |
| `changed` | In both scans, but its text differs (usually version details in the description) |
| `fixed` | In the previous scan, gone from this one; stored as its own document |
| `baseline` | The task's first scan, nothing to compare with |
| `unknown` | The comparison failed; findings are still indexed |

## Requirements

- Python 3.9 or later.
- Runs on the same server as Greenbone, with read and write access to the gvmd Unix socket. In the Docker Compose install the socket is root-owned, so the script normally runs as root.
- A Greenbone user that can see the scan tasks and reports.
- An Elasticsearch 8 user that can create and write to the target index. It does not need to be a superuser.

Tested with Greenbone Community Edition (Docker Compose, feed release 24.10) and Elasticsearch 8.

## Installation

**With SOC-in-a-Box:** run `./deploy.sh --with-greenbone` from the repository root on the
server where SOC-in-a-Box and Greenbone are installed. It reuses the Elasticsearch settings, asks for the Greenbone login, installs
the script, and schedules a daily push with a systemd timer. The rest of this section is the
manual install.

The paths below are a suggested layout. Any paths work as long as the env file and cron lines point to them.

```sh
sudo mkdir -p /opt/gvm-siem /etc/gvm-siem /var/log/gvm-siem /var/lib/gvm-siem
sudo cp gvm_siem_push.py requirements.txt /opt/gvm-siem/
sudo python3 -m venv /opt/gvm-siem/venv
sudo /opt/gvm-siem/venv/bin/pip install -r /opt/gvm-siem/requirements.txt

sudo cp examples/gvm-siem.env.example /etc/gvm-siem/gvm-siem.env
sudo chmod 600 /etc/gvm-siem/gvm-siem.env
sudo nano /etc/gvm-siem/gvm-siem.env      # fill in the values
```

## Configuration

Settings come from environment variables or an env file passed with `--env-file` (default `~/.gvm_elastic.env`). Variables already set in the environment win. See [`examples/gvm-siem.env.example`](examples/gvm-siem.env.example).

| Setting | Required | Default | Purpose |
| --- | --- | --- | --- |
| `GVM_SOCKET` | Yes | | Path to the gvmd Unix socket |
| `GVM_USERNAME` | No | `admin` | Greenbone user |
| `GVM_PASSWORD` | Yes | | Greenbone password |
| `ES_HOST` | Yes | | Elasticsearch URL, e.g. `https://elastic.example.org:9200` |
| `ES_USERNAME` | Yes | | Elasticsearch user |
| `ES_PASSWORD` | Yes | | Elasticsearch password |
| `ES_INDEX` | No | `gvm-vulnerabilities` | Target index |
| `ES_CA_CERTS` | No | | CA certificate for Elasticsearch's TLS certificate (`ES_CA_CERT` also works) |
| `ES_VERIFY_CERTS` | No | `true` | Set `false` only if no CA certificate is available |
| `ES_COMPAT_VERSION` | No | | Only needed if you installed a 9.x Python client against an Elasticsearch 8 server; `requirements.txt` pins 8.x |
| `MIN_SEVERITY` | No | `0.0` | Only send findings above this severity |
| `MIN_QOD` | No | `70` | Minimum Quality of Detection |
| `APPLY_OVERRIDES` | No | `true` | Apply overrides set in Greenbone |
| `COMPARE_PREVIOUS` | No | `true` | Add the `delta_status` labels |
| `GVM_TIMEOUT` | No | `600` | Seconds to wait for gvmd per request |
| `STATE_FILE` | No | `~/.gvm_last_run` | Where the last successful run time is kept |
| `LOG_FILE` | No | | Log file, rotated at 5 MB with 5 old files kept |
| `LOG_LEVEL` | No | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |

## Running it manually

Start with a dry run: it reads everything and sends nothing.

```sh
# See what would be sent
sudo /opt/gvm-siem/venv/bin/python /opt/gvm-siem/gvm_siem_push.py --env-file /etc/gvm-siem/gvm-siem.env --dry-run

# Send reports finished since the last successful run
sudo /opt/gvm-siem/venv/bin/python /opt/gvm-siem/gvm_siem_push.py --env-file /etc/gvm-siem/gvm-siem.env

# Resend the latest report of every task (first run, or after deleting the index)
sudo /opt/gvm-siem/venv/bin/python /opt/gvm-siem/gvm_siem_push.py --env-file /etc/gvm-siem/gvm-siem.env --full
```

Example output:

```
[INFO] Weekly Scan: report 1a2b3c4d-... (finished 2026-01-10T01:30:00+00:00)
[INFO]   75 finding(s) in this scan; compared with 9f8e7d6c-...: changed 25, fixed 1, same 50
[INFO]   Indexed 76 document(s).
[INFO] Done. 1 report(s) pushed, 3 skipped. Index: gvm-vulnerabilities
```

Tasks whose latest report was already sent show `latest report already pushed`. Tasks in Greenbone's trashcan are ignored.

## Running it with cron

Schedule the push a few hours after each scan normally finishes; a report still running at push time is sent on the next run. See [`examples/crontab.example`](examples/crontab.example).

```
# sudo crontab -e
0 3 * * 6 /opt/gvm-siem/venv/bin/python /opt/gvm-siem/gvm_siem_push.py --env-file /etc/gvm-siem/gvm-siem.env >> /var/log/gvm-siem/cron.log 2>&1
```

A simpler option is one daily run (`0 6 * * *`): a run with nothing new finishes in seconds, and cron does not need to change when scan schedules move.

## Logs

With `LOG_FILE` set, every run is written there. From cron, only warnings and errors also reach cron's output, so `cron.log` stays empty unless something went wrong. The exit code is 0 on success and 1 on any error.

```sh
sudo tail -30 /var/log/gvm-siem/push.log   # last run in detail
sudo cat /var/log/gvm-siem/cron.log        # problems only
```

## Using the data in Kibana

| Question | KQL |
| --- | --- |
| What is new since the previous scan? | `delta_status : new` |
| What was fixed since the previous scan? | `delta_status : fixed` |
| Open findings only | `not delta_status : fixed` |
| Is a CVE present on any host? | `cve : "CVE-2024-12345"` |
| Critical and High only | `severity_label : (Critical or High)` |

Main fields: `task_name`, `report_id`, `previous_report_id`, `delta_status`, `scan_end`, `host`, `hostname`, `port`, `name`, `nvt_oid`, `severity`, `severity_label`, `cvss_base`, `cve`, `qod`, `solution`, `solution_type`.

Dashboards that count open vulnerabilities should exclude `delta_status : fixed` and use only each task's latest `scan_end`, otherwise older scans are counted again.

## Troubleshooting

| Message or symptom | Fix |
| --- | --- |
| `Missing required settings: ...` | Add the setting to the env file; check `--env-file` points to it |
| `Permission denied` on the socket | Run with `sudo`, or give the user access to `gvmd.sock` |
| `Elasticsearch error: ...` | Check `ES_HOST`, credentials and `ES_CA_CERTS` |
| `Could not compare with the previous scan (timed out)` | Raise `GVM_TIMEOUT`; findings are still sent, labelled `unknown` |
| `Some documents failed to index` | Read the first error in the log; the next run retries |
| `Could not read this report from GVM` | That task is skipped and retried next run; the other tasks are still sent |
| Every task says `latest report already pushed` but data is missing | Run once with `--full` |

## Security notes

- Keep the env file readable only by the user that runs the script (`chmod 600`). Never commit it.
- Prefer `ES_CA_CERTS` over `ES_VERIFY_CERTS=false`.
- Give the Elasticsearch user write access to the target index only.

## License

[MIT](LICENSE)
