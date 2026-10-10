# Fail2ban connection

Use **Application administration → Fail2ban connection** to select local Docker
or a local native Linux installation. Path detection and connection tests do
not change Fail2ban. Tests check daemon response, jail visibility, configuration
permissions and validation, and log access. Saving tests again; unreachable
connections or inadequate requested permissions preserve the current settings.
Read-only access must be explicitly selected and blocks FCP write operations.
Settings are atomically persisted in `data/connection.json` with revision checks.
The saved selection overrides the initial `FCP_FAIL2BAN_CONTAINER` default.

Docker configuration editing expects the existing crazymax layout (`/data`
and `/etc/fail2ban`). Native mode invokes `fail2ban-client -c DIRECTORY -s SOCKET`
directly, without Docker or implicit sudo. Install compatible Fail2ban client
and regex tools. The FCP image includes the client package, without starting a
daemon. Typical paths are `/etc/fail2ban`, `/run/fail2ban/fail2ban.sock` and
`/var/log/fail2ban.log`. System journal access additionally requires journalctl
and appropriate permissions. File reads are bounded to 32 MiB / 100,000 lines.

When FCP runs in Docker, bind mount the native configuration, socket directory
and logs. Mounting the socket directory follows daemon socket recreation.
Configuration validation also needs log paths referenced by the jails to be
visible. Paths supplied in the UI are those inside FCP; paths sent to the daemon
must remain coherent with the host. The form does not create mounts or grant
permissions. Fail2ban socket access is powerful; read-only mode is enforced by
FCP, not by a distinct read-only Fail2ban protocol.

Native file edits stage and validate a copy, retain original content and
metadata, and roll back on reload failure. Backups are stored under
`data/fail2ban-backups/INSTALLATION/ui`. Distribution filter/action `.conf`
files cannot be deleted from FCP; prefer `.local` overrides. Starting, stopping
and restarting native Fail2ban uses systemctl only when FCP itself runs directly
on the host. From a container those operations must be performed on the host;
configuration and jail reloads remain available.

To run FCP without Docker, install its Python requirements in a virtual
environment, configure a supervised Gunicorn process using the supplied config,
set PYTHONPATH to `src`, and use writable persistent paths for
`FCP_AUTH_DATABASE`, `FCP_CONNECTION_FILE`, `FCP_AUTOMATION_FILE`, `FCP_DATABASE`,
`FCP_ABUSE_SETTINGS`, plus a private `FCP_CONFIG`. Existing authentication and
network restrictions still apply. See the [French deployment details](connection.fr.md).

External abuse schedulers and the optional reporting worker retain their own
connection settings. This form selects the web administration target, without
moving external jobs, report history or duplicate protection to another server.
Remote SSH administration is not part of this version.
