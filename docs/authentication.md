# Authentication and application administration


Passwords use Argon2id. Authentication state is stored in `/app/data/auth.sqlite3`, mode 0600. Session identifiers are SHA-256 hashed in the database. Sessions expire after 30 minutes idle or 8 hours maximum. Password changes revoke every session. Passwords must contain 20–256 characters. Authentication Basic is no longer accepted.

Five failed attempts from one address cause a 15-minute block; a global limit of 30 failures also applies. Limits survive restarts. Login and account mutations require CSRF tokens and validate Origin. Existing Fail2ban API CSRF protection remains in place.


## HTTPS and explicitly allowed local HTTP

HTTP is rejected by default. Behind a trusted HTTPS proxy, bind the application to loopback, set `FCP_PUBLIC_URL=https://your-host` and enable `FCP_TRUST_PROXY=1` only when that proxy is the sole client capable of reaching the backend. The proxy must replace X-Forwarded-For and X-Forwarded-Proto. Cookies use Secure, HttpOnly and SameSite=Lax.

For local testing, `FCP_ALLOW_HTTP=1` explicitly permits HTTP with an HttpOnly, SameSite=Lax cookie without Secure. Traffic and session cookies remain unencrypted; do not expose this mode publicly. Bind to a local interface and restrict client sources using `FCP_ALLOWED_NETWORKS`.

## Bootstrap and recovery

`FCP_ADMIN_PASSWORD` is only used to initialize a missing authentication database. Remove it from `.env` and recreate the container after initialization. Do not delete the database to change a password.

Local trusted-console recovery:

```
docker exec -it fcp python /app/automation/reset-admin.py
```


Back up authentication state securely. Restoring an old authentication database may restore old sessions; use local recovery to revoke them afterwards.

Sign in using the username and password. Two-factor authentication is not available in this version.
