# Configuration

[English](configuration.md) · [Français](configuration.fr.md)

`.env` configures Compose. Private `config/config.json` configures collectors.
Both are excluded from Git. The installer preserves existing files.

| Setting | Purpose |
| --- | --- |
| `FCP_ADMIN_USER`, `FCP_ADMIN_PASSWORD` | Initial account bootstrap only; remove password from environment after initialization |
| `FCP_FAIL2BAN_CONTAINER`, `FCP_CONTAINER` | Fail2ban and FCP container names; environment overrides JSON |
| `FCP_BIND_ADDRESS`, `FCP_PORT` | Published bind address and port; local by default |
| `TZ` / `timezone` | Installation and reporting timezone; UTC by default |
| `jails` | Jail labels; empty dictionary discovers active jails |
| `ssh_jails`, `ssh_log`, `ssh_port` | Verified SSH jails, log inside Fail2ban and public SSH port |
| `http_enabled` | Optional HTTP evidence collection; false by default |
| `web_jail`, `web_log` | Web jail and access log inside Fail2ban |
| `sftp_container`, `sftp_port` | Optional SFTP container and public port |
| `postfix` | Existing Postfix container providing sendmail |
| `sender`, `recipient` | Initial email settings; subsequently managed through FCP |
| `message_id_domain` | Message-ID domain; localhost by default |
| `output` | Internal state directory; retain `/app/automation-state` for supplied Compose |

Recreate services with `docker compose up -d` after changing `.env` or container
names. Collectors reread JSON on every run. Settings saved in the interface
are stored separately and are not overwritten by the installer.

## Logs and geolocation

Mount the chosen HTTP log directory read only at `/app/logs`. The default
filename is `access.log`; override `FCP_HTTP_LOG` if needed. Expected lines use
the NPMplus-compatible timestamp, domain, source IP, quoted request and status.
SSH logs must already be available inside Fail2ban. FCP does not automatically
read host system logs. SFTP evidence comes from timestamped Docker logs.
Missing logs never become invented evidence.

No MMDB database is bundled. The interface downloads DB-IP City Lite. Supply
an optional ASN database at `geo/asn.mmdb`. DB-IP Lite remains CC BY 4.0 with
DB-IP attribution in the interface.

## Automations

Configure real SSH/web jails, log sources, sender and Postfix container before
activation. Enable the desired email/report/AbuseIPDB settings in FCP, then
start the optional worker with `docker compose --profile automations up -d`.
Do not run this worker alongside an existing scheduler for the same tasks.

The worker checks repeat activity every five minutes and attempts the daily
report once after 08:00 in the configured timezone. After an interruption it
may attempt today's report at startup. A failed daily attempt is not retried
automatically on the same day. Preserve `state/` on upgrades: uncertain
submissions block automatic resends. Delivery to Postfix is not proof of
recipient delivery. Evidence distinguishes observations, samples and limits;
private usernames, passwords, URL parameters and arbitrary paths are filtered.

AbuseIPDB needs `config/abuseipdb.key` with mode 600 and only the key. SSH
classification depends on configured SSH filters. Web reports require known
scan-path evidence; HTTP 401/403 responses alone are insufficient.

Auxiliary SMTP and webhook tests do not change the Postfix transport used by
automatic reports. Automatic webhook event delivery is not implemented.

[Authentication, HTTPS and local HTTP testing](authentication.md)

[Fail2ban connection modes / Modes de connexion à Fail2ban](connection.md)
