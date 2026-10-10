# FCP — Fail2ban Control Panel

[English](README.md) · [Français](README.fr.md)

Web administration for Fail2ban: jails, filters, actions, persistent HTTP
history, a world IP map and abuse reports with supporting evidence.

## Install

Requires Linux, Docker Engine, Docker Compose and an existing Fail2ban
container with `fail2ban-client`, `fail2ban-regex`, Python 3 and `date`.
Persistent configuration editing targets crazymax/fail2ban paths:
`/data/{jail.d,filter.d,action.d}` and `/etc/fail2ban`. Validate other images
before editing their configuration. Native Linux Fail2ban is also supported through **Application administration →
Fail2ban connection**, with detection, connection tests and read-only access.
See [Connection modes](docs/connection.md), including running FCP without Docker.
Remote servers are not supported. FCP does not install Fail2ban or create firewall rules.

```sh
git clone https://github.com/woofix/fcp.git
cd fcp
python3 install.py
```

The installer creates a private `.env` with a random administrator password
and `config/config.json`, preserving existing settings. Set
`FCP_FAIL2BAN_CONTAINER` to your container name, then review
[Configuration](docs/configuration.md).

```sh
docker compose config --quiet
docker compose up -d --build
```

Configure an HTTPS reverse proxy before opening FCP. See [authentication setup](docs/authentication.md). The initial administrator password is in `.env`; remove it after initialization. Explicit local HTTP testing requires `FCP_ALLOW_HTTP=1`.
Use an SSH tunnel or an HTTPS reverse proxy for remote access. All application
routes require authentication; sensitive operations also require the existing
CSRF token. See [Security](SECURITY.md).

## Languages

Choose **Français** or **English** using the language selector. The preference
is stored in a browser cookie for one year and applies to the dashboard,
configuration, map, dialogs and application messages. Technical logs,
configuration files, saved report contents and operator-provided values retain
their original content. French is the default.

## Optional features

- HTTP history: mount compatible NPMplus logs at `/app/logs/access.log`.
- World map: supply `geo/city.mmdb` or use the DB-IP update in the interface.
  IPs without coordinates stay in the list. Databases are not bundled.
- Automations: optional `automations` Compose profile; disabled by default.
- Email reports: existing Postfix container and `sendmail`, with UTC evidence
  and a verifiable attachment.
- AbuseIPDB: private local API-key file, never committed.
- Auxiliary SMTP and webhook settings: manual tests. Automatic webhook event
  delivery is not implemented in this version.

Back up `data`, `state`, `config`, `geo` and `logs`; these are excluded from Git.

## Validation

```sh
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

The image uses Python 3.12. Tests cover authentication, language isolation,
configured container names, optional sources, evidence, privacy filtering
and duplicate prevention. Validate each installation with its own jails,
logs and firewall rules before enabling reports.

## License

FCP: **Apache-2.0**, see [LICENSE](LICENSE) and [NOTICE]. Dependencies and
optional datasets retain their own licenses.

[Validation record](docs/validation.md) · [GitHub publication](docs/publication.md)

[Authentication and sessions](docs/authentication.md)
