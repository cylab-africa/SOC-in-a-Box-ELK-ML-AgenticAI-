# Install the Elastic Stack

SOC-in-a-Box runs on top of an Elastic Stack 8.x: Elasticsearch, Kibana and
Fleet. If you already have one, skip to
[Add the hosts you want to monitor](#add-the-hosts-you-want-to-monitor).

There are three ways to get a stack:

| Option | Best for |
|---|---|
| [Use the install script](#option-1-use-the-install-script) | A single Ubuntu server for a small team, a lab or a training environment |
| [Install it yourself](#option-2-install-it-yourself) | Several nodes, an existing Elastic setup, or a different operating system |
| [Elastic Cloud](https://www.elastic.co/cloud) | Letting Elastic host the stack for you (paid, with a free trial) |

## Option 1: Use the install script

`install-elastic-stack.sh` sets up a complete single-server stack on Ubuntu:

- Elasticsearch 8.x and Kibana 8.x, with security and HTTPS turned on
- Fleet, with a Fleet Server policy
- Elastic Agent on the same server, acting as the Fleet Server

It does **not** add the System or Elastic Defend integrations; you add those
in Kibana afterwards (see [below](#add-the-hosts-you-want-to-monitor)). It
does not install Suricata either.

### Before you install

| You need | Notes |
|---|---|
| Ubuntu 20.04 or newer | 22.04 and 24.04 are the tested releases; the script warns on others. Check [Elastic's support matrix](https://www.elastic.co/support/matrix) |
| A fresh server | The script stops if Elasticsearch, Kibana or Elastic Agent are already installed |
| `sudo` access | |
| 8 GiB of RAM | Recommended. The script warns with less, and the stack may be slow or unstable |
| 30 GiB of free disk | Required. The script stops with less |
| An `amd64` or `arm64` CPU | |
| Internet access | To the Ubuntu and Elastic package repositories |
| `systemd` | Standard on Ubuntu. On WSL, turn it on in `/etc/wsl.conf` first |

### Install

On the server:

```bash
git clone https://github.com/cylab-africa/SOC-in-a-Box-ELK-ML-AgenticAI-.git
cd SOC-in-a-Box-ELK-ML-AgenticAI-
sudo bash install-elastic-stack.sh
```

The script asks once whether to continue (`y` or `n`), then runs the
remaining steps without further questions. It takes several minutes and
ends with a summary like this:

```
Kibana:       http://10.0.0.5:5601
Fleet Server: https://10.0.0.5:8220
Username:     elastic
Password:     sudo cat /var/tmp/elastic-soc-installer/elastic-password.txt
```

Open the Kibana address in a browser and sign in as `elastic` with that
password. Keep the password private: don't paste it into tickets, chat or
public logs.

Kibana normally starts on plain `http://`, so the password crosses the
network unencrypted. That's fine on the server itself or a trusted lab
network. Anywhere else,
[turn on HTTPS for Kibana](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/security-basic-setup-https.html#encrypt-kibana-browser).

The same details are saved in `/root/elastic-soc-deployment-summary.txt`
(`sudo cat` to read it).

### Options

Set these before the command, for example
`sudo FLEET_SERVER_HOST=10.0.0.5 bash install-elastic-stack.sh`:

| Setting | Default | What it does |
|---|---|---|
| `FLEET_SERVER_HOST` | The server's first IP address (`127.0.0.1` on WSL) | The IP or DNS name your monitored hosts use to reach Fleet Server. Give a name or IP only, with no `https://`, port or path |
| `FLEET_PORT` | `8220` | Fleet Server port |
| `SOC_HOSTNAME` | The server's hostname | Name written in the deployment summary |
| `ELASTIC_MAJOR` | `8` | Elastic major version. SOC-in-a-Box needs 8.x, so keep the default |
| `RESUME_PARTIAL` | `0` | Set to `1` to continue a failed run (see below) |

If the server has more than one network address, set `FLEET_SERVER_HOST`
to the one your other hosts can reach.

### If the install fails

The script stops at the failing step and prints the log location,
`/var/log/elastic-soc-installer.log`. Fix the cause, then continue on the
**same server** with:

```bash
sudo RESUME_PARTIAL=1 bash install-elastic-stack.sh
```

This reuses the saved password and the Fleet setup from the first run. It
is only for continuing this script's own run, not for repairing some other
Elastic installation. Don't start a second copy while the first is still
running.

### Where things are

| Path | What it is |
|---|---|
| `/var/tmp/elastic-soc-installer/elastic-password.txt` | The `elastic` user's password (root only) |
| `/root/elastic-soc-deployment-summary.txt` | Addresses, policy IDs and notes (root only) |
| `/var/log/elastic-soc-installer.log` | Everything the script printed |
| `/etc/elasticsearch/certs/http_ca.crt` | The certificate authority. `deploy.sh` offers to trust it |
| `/etc/elasticsearch/`, `/etc/kibana/` | Elasticsearch and Kibana settings |
| `/opt/Elastic/Agent/` | The Elastic Agent running Fleet Server |

## Option 2: Install it yourself

Follow Elastic's own guides, using version 8.x:

1. [Install Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/deb.html)
   (Debian/Ubuntu package; the same guide links to RPM, Windows and Docker),
   and apply the [system settings](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/system-config.html)
   Elastic recommends.
2. [Install Kibana](https://www.elastic.co/guide/en/kibana/8.19/deb.html)
   and connect it to Elasticsearch with an enrollment token.
3. [Deploy Fleet Server](https://www.elastic.co/guide/en/fleet/8.19/add-fleet-server-on-prem.html)
   on your own server.

Then continue below.

## Add the hosts you want to monitor

The detection engine learns from Elastic Agent data, so each Linux host you
want to monitor needs:

- the [Elastic Defend](https://www.elastic.co/guide/en/security/8.19/install-endpoint.html)
  integration, for process and network events
- the [System](https://www.elastic.co/docs/reference/integrations/system)
  integration, for logins and system logs

In Kibana:

1. Go to **Fleet → Agent policies → Create agent policy**, and name it, for
   example `Linux hosts`.
2. Open the policy and **Add integration**: add **Elastic Defend**, then
   **System**.
3. Go to **Fleet → Agents → Add agent**, choose the policy, and run the
   install command it shows on each host. Elastic's guide:
   [Install Fleet-managed Elastic Agents](https://www.elastic.co/guide/en/fleet/8.19/install-fleet-managed-elastic-agent.html).
4. Check that each host shows as **Healthy** under **Fleet → Agents**.

The hosts must be able to reach Fleet Server on port `8220` and
Elasticsearch on port `9200`.

Let the hosts send data for **about 7 days** before installing the
detection engine, so it has normal behaviour to learn from.

## Install SOC-in-a-Box

Run `./deploy.sh` as described in [Installation](installation.md). When it
asks:

| Question | Answer, for a stack from the install script |
|---|---|
| Elasticsearch address | `https://<server IP>:9200`, or `https://localhost:9200` on the same server |
| Elasticsearch username | `elastic`, or a dedicated user you created in Kibana |
| Elasticsearch password | The password from `elastic-password.txt` |
| Certificate | Choose **1** to trust it. The certificate is `/etc/elasticsearch/certs/http_ca.crt` |

## Check it works

```bash
sudo systemctl status elasticsearch kibana elastic-agent --no-pager
sudo /opt/Elastic/Agent/elastic-agent status
```

Check the cluster health:

```bash
PASS="$(sudo cat /var/tmp/elastic-soc-installer/elastic-password.txt)"
curl --cacert /etc/elasticsearch/certs/http_ca.crt -u "elastic:${PASS}" \
  "https://127.0.0.1:9200/_cluster/health?pretty"
unset PASS
```

`"status" : "green"` or `"yellow"` is fine for a single server: yellow just
means there is no second node to hold replica copies.

## Troubleshooting

| Problem | What to do |
|---|---|
| Stops with "already installed" | The server isn't fresh. If it's this script's own earlier run, use `RESUME_PARTIAL=1`. Otherwise use a clean server |
| Seems stuck at step 6 (Kibana) | Kibana setup can take a few minutes; the enrollment step times out after 90 seconds. In a second terminal: `sudo journalctl -u kibana --since "15 minutes ago" --no-pager` |
| Seems stuck at step 7 (Fleet) | Each Kibana request times out after 30 seconds. Check `sudo tail -100 /var/log/elastic-soc-installer.log` |
| Elasticsearch or Kibana is not active | `sudo journalctl -u elasticsearch --since "30 minutes ago" --no-pager` (or `-u kibana`). Check memory and disk with `free -h` and `df -h /` |
| Other hosts can't enroll | They can't reach Fleet Server. Check **Fleet → Settings → Fleet Server hosts** shows an address they can reach (not `127.0.0.1`), and that port `8220` is open |
| Hosts are enrolled but send no data | Check **Fleet → Settings → Outputs** shows an Elasticsearch address they can reach (`https://<server IP>:9200`, not `localhost`), and that port `9200` is open to them |
| No System or Elastic Defend data | Expected until you add them: see [Add the hosts you want to monitor](#add-the-hosts-you-want-to-monitor) |

More SOC-in-a-Box problems: [Troubleshooting](troubleshooting.md).

## Security notes

- Allow only trusted networks to reach Kibana (`5601`) and Fleet Server
  (`8220`). Open Elasticsearch (`9200`) only to the hosts and services that
  need it, and never to the internet.
- Turn on [HTTPS for Kibana](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/security-basic-setup-https.html#encrypt-kibana-browser)
  before anyone signs in over the network.
- The script uses `curl --insecure` only for its own setup calls on the
  server. Other clients should check the certificate, as `deploy.sh` does
  when you choose to trust it.
- The installer log can contain sensitive details. Review it before sharing.
- Keep Ubuntu and the Elastic packages updated.
- Some Elastic Security features need a paid subscription; check Elastic's
  licensing before turning them on.

## Limits

This is a single-server stack, not a high-availability production cluster.
WSL works for trying out the install, but Elastic Defend and other
kernel-level features may not behave as on a normal Ubuntu server, and its
address may change between restarts. For larger setups, see
[Option 2](#option-2-install-it-yourself).
