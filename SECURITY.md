# Security

Basic authentication is replaced by revocable server-side sessions and Argon2id password hashes. Every business route is protected; login, language selection and a minimal loopback health check are the exceptions. See [authentication and its limitations](docs/authentication.md).

HTTPS is required by default. Explicit local HTTP testing does not encrypt traffic. Docker socket access grants substantial host privileges: restrict FCP to trusted administrators. Never commit local data or secrets to Git.
