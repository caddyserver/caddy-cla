# Deployment

Copy `config.example.json` to `config.json`. Agreement and repository values seed
the initial database; subsequent edits are managed live through the admin UI.
Secrets are environment variables, not
JSON fields. All paths are relative to the process working directory unless
absolute. For production, set:

```json
{
  "base_url": "https://example.com",
  "base_path": "/cla",
  "listen": "127.0.0.1:8080",
  "database": "/var/lib/caddy-cla/cla.db",
  "repositories": ["caddyserver/caddy"],
  "repository_id": "29207621",
  "admin_ids": [],
  "exempt_users": ["*[bot]"],
  "exempt_public_orgs": ["github"],
  "agreement_file": "/opt/caddy-cla/agreement.md",
  "agreement_version": "fd82f5aa148dc67b743e0e8e14d33c9b9d32b6d8",
  "agreement_source": "https://gist.github.com/mholt/f2a199f495ebd529f6d9"
}
```

Set `base_url` to the public origin and `base_path` to the route prefix. Use `"/"`
(or an empty string) for a subdomain served at its root. The examples use `/cla`.
The application handles its configured prefix itself. **Preserve the prefix** when reverse
proxying; do not use `handle_path` to strip it. Cookies have `Path=/cla/`,
`HttpOnly`, `SameSite=Lax` and `Secure` in HTTPS deployments. The canonical external
URL is configured explicitly rather than trusted from incoming proxy headers.
See [Caddy example](../deploy/Caddyfile) and [systemd unit](../deploy/caddy-cla.service).

## Systemd layout

The supplied unit runs as a dedicated `caddy-cla` system user, with:

- executable and agreement in `/opt/caddy-cla/` (root owned);
- config in `/etc/caddy-cla/config.json` (readable by the service group);
- credentials in `/etc/caddy-cla/secrets.env` (root owned, mode 0600);
- GitHub App key in `/etc/caddy-cla/github-app.pem` (root owned, service group, mode 0640);
- persistent data and backups in `/var/lib/caddy-cla/` (service owned, mode 0700).

Systemd reads the environment file before switching to the service user. The
service needs read access to the PEM file, not the environment file itself.
After updating credentials, run `systemctl restart caddy-cla`. Check status with
`systemctl status caddy-cla` and logs with `journalctl -u caddy-cla`.

Without GitHub credentials, viewing agreements and the health endpoint works;
signing and GitHub automation remain unavailable. Install the GitHub App only
after the webhook and credentials are ready, and test before requiring its status.

## Operations

One process and one local persistent SQLite database. WAL mode, foreign keys and a
busy timeout are enabled. Webhook acceptance, delivery deduplication and job enqueue
are one transaction. Jobs survive restarts, retry with capped exponential backoff,
and retain failures for the admin dashboard. A generation counter prevents an
in-flight reconciliation from deleting newer work for the same PR. Successful
signing and its recheck enqueue commit atomically.

Health: `/cla/healthz` checks database availability. Logs go to stderr as structured
`slog` messages. Back up with:

```sh
./bin/caddy-cla -config config.json -backup /backups/cla-2026-10-19.db
```

This uses SQLite `VACUUM INTO` for a consistent database snapshot; destination must
not already exist. A separate process can run this while the service is live.
Encrypt/restrict backup access. Test restore by pointing an isolated local config
at a backup and checking history; keep production bot credentials out of the
restore test. Copying only the main DB while WAL writes are active is not a backup.

Build and verify:

```sh
go test -race ./...
go vet ./...
go build -trimpath -o bin/caddy-cla ./cmd/caddy-cla
```

Integration tests use a local mock GitHub server and temporary SQLite databases;
they do not authenticate against GitHub or sign a real agreement.
