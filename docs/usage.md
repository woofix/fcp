# User guide

[English](usage.md) · [Français](usage.fr.md)

## Daily use

Select a section in the left sidebar to open its submenu. The dashboard
summarizes service status and protection counters; use Bans for IP details.

- **Bans → List**: search addresses, filter by protection, country or status,
  and select an IP to inspect its details and available ban/unban actions.
- **Bans → World map**: explore approximate IP locations. Addresses without
  coordinates remain in the list. An IP location is not proof of identity.
- **Bans → History**: inspect chronological Ban/Unban events from the inspected
  log, retaining the same filters. Select an IP to open its map details.
- **Activity**: detections, HTTP requests and the Fail2ban log. HTTP requests
  require compatible mounted logs; missing optional sources do not create data.
- **Protections**: manage jails, filters/actions and configuration backups;
  inspect the service or use Expert controls. Availability depends on the
  selected connector and read-only/administration access.
- **Automations**: configure the optional AbuseIPDB integration and daily
  summary. Review prerequisites in [Configuration](configuration.md).
- **Settings → General**: select French or English.
- **Settings → Fail2ban connection**: select Docker or native Linux, detect
  paths, test the connection and save it. See [Connection modes](connection.md).
- **Settings → Security**: change the password, revoke other sessions, sign out
  and inspect the security log. Changing a password closes every session.

Ban status is checked with Fail2ban. Historical data is limited to the last
5,000 inspected log lines, up to 300 historical IP records and 300 events;
this is not a complete archive. Filters are retained between the three ban
views in the current page; a reload may reset their values. The chosen main
section and ban view are remembered in browser storage.

## Updating an existing Docker installation

Back up persistent data and private settings, record the current Git revision
and image, and review local modifications before pulling. Keep `.env`,
`config/`, `data/`, `state/`, `geo/`, `logs/` and local Compose overrides.

From the existing checkout, with the same Compose project and override files:

```sh
git pull --ff-only
docker compose config --quiet
docker compose build fcp
docker compose up -d --no-deps fcp
docker compose ps fcp
```

If `git pull` reports local changes or divergence, resolve them before
continuing. Validate the login, sidebar, configured connection and existing
jails afterwards. These commands update FCP only; they do not install Fail2ban
or migrate independent report schedulers. Refresh the browser after updating.
For a native FCP deployment, use the existing virtual environment and service
procedure described in [Connection modes](connection.md).
