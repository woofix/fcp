# FCP — Fail2ban Control Panel

[English](README.md) · [Français](README.fr.md)

Web administration for Fail2ban: jails, filters, actions, persistent HTTP
history, a world IP map and optional AbuseIPDB reporting.

## Install

Requires Linux, Docker Engine, Docker Compose and an existing Fail2ban
container with `fail2ban-client`, `fail2ban-regex`, Python 3 and `date`.
Persistent configuration editing targets crazymax/fail2ban paths:
`/data/{jail.d,filter.d,action.d}` and `/etc/fail2ban`. Validate other images
before editing their configuration. Native Linux Fail2ban is also supported through **Settings →
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

## Navigation

The left sidebar stays visible throughout the application. Selecting a section
opens its submenu; the selected view is highlighted.

| Section | Views and settings |
| --- | --- |
| Dashboard | Service status, protection counters, recent activity |
| Bans | List, World map, History |
| Activity | Detections, HTTP requests, Fail2ban log |
| Protections | Jails, Filters and actions, Backups, Service, Expert |
| Automations | Optional AbuseIPDB reporting and daily summary |
| Settings | General, Fail2ban connection, Security |

List, World map and History share protection, country, status and search
filters when switching views. The map is inside **Bans** and has no separate
sidebar entry. Password changes, session management and the security log are
in **Settings → Security**.

See the [user guide](docs/usage.md) for daily use and safe update instructions.

## Languages

Choose **Français** or **English** in **Settings → General**. The preference
is stored in a browser cookie for one year and applies to the dashboard,
configuration, map, dialogs and application messages. Technical logs,
configuration files, saved report contents and operator-provided values retain
their original content. French is the default.

## Optional features

- HTTP history: mount compatible NPMplus logs at `/app/logs/access.log`.
- World map: supply `geo/city.mmdb` or use the DB-IP update in the interface.
  IPs without coordinates stay in the list. Databases are not bundled.
- Automations: optional `automations` Compose profile; disabled by default.
- Daily summary: delivered to your own address through an existing Postfix container.
- AbuseIPDB: private local API-key file, never committed.
- Optional webhook settings: manual tests. Automatic webhook event
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
