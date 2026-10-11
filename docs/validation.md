# Validation

38 automated tests pass on Linux/Python 3.12 and macOS/Python 3.9. They cover
sessions, CSRF, origin and network restrictions, password rotation, rate limits,
language selection, private evidence handling, installation idempotency,
connection persistence, concurrent updates, read-only enforcement and native
configuration rollback.

The Docker image builds and runs successfully. The Docker connector was
verified against an existing Fail2ban instance with three active jails. Native
mode was tested with an isolated real Fail2ban 1.1.0 daemon: status, inventory,
configuration validation, save/reload/restore, dashboard, and dummy ban/unban.
This test had no network or host firewall capabilities. No real email or API
report was sent by these tests. The French and English interface and consistent
form sizing were also checked in a browser.

Limitations: these are not multi-distribution or multi-architecture tests.
Native clients must be compatible with the target daemon and have access to
its configuration, socket and logs. Mounts and operating-system permissions
are not automatically provisioned. External report schedulers retain their
independent configuration; changing the web connection does not migrate them.
Remote administration, multiple administrator accounts and automatic webhook
delivery are not implemented. Verify GitHub Actions for each published commit.

Sidebar regrouping was checked in an isolated browser preview: Bans exposes List, World map and History; Activity, Protections and Settings expose their own sidebar submenus. Switching ban views preserved the search filter. The updated image was deployed on the test host and reported healthy; existing Fail2ban data remained readable. Browser checks used isolated test data, without changing live bans or credentials.
