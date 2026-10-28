# Security Policy

## Reporting a vulnerability

**Do not open a public issue.** Report it privately on GitHub: the
repository's **Security** tab → **Report a vulnerability**.

Include what is affected, how to reproduce it, and the impact you expect.
Please give us reasonable time to fix it before disclosing it publicly.

In scope: the detection pipeline, the add-ons, `deploy.sh`, credential
handling, and communication with Elasticsearch, Google Chat and AI providers.

## Using SOC-in-a-Box safely

- Never commit `.env` files or credentials. They are in `.gitignore`.
- Give the Elasticsearch user only the access it needs: read the log indices,
  write `ml-anomalies-custom-*`.
- Verify the cluster's certificate (`ES_VERIFY_CERTS=true`, the default) on
  anything but a lab cluster.
- Run the services as a normal user, not root (`deploy.sh` uses the user who
  runs it).
- Keep the Alert Triage Agent on `127.0.0.1`: it has no login.
- Fill the false-positive lists in `config/local/` to match your own
  environment, and do not allowlist `root` or general tools such as `bash`.
- Update regularly: `git pull`, then `./deploy.sh`.
