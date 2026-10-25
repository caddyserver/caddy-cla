# Caddy CLA

A Go and SQLite service for Caddy contributor agreements. Supports GitHub sign-in,
live per-repository agreements, PR status checks, signer history and web imports. Supports root or subpath hosting.

## Run locally

Requires Go 1.26 or newer.

```sh
cp config.example.json config.json
go run ./cmd/caddy-cla -config config.json
```

The example uses `base_url: "http://localhost:8080"` and `base_path: "/cla"`.
Set `base_path` to `"/"` to serve at the origin root.

Open http://localhost:8080/cla/. Viewing the agreement works without credentials;
signing and PR updates require [GitHub setup](docs/github.md).

## Development

```sh
go test -race ./...
go vet ./...
go build -o bin/caddy-cla ./cmd/caddy-cla
```

- `cmd/caddy-cla/` — command entry point
- `internal/app/` — HTTP handlers, GitHub integration and background workers
- `internal/config/` — configuration loading and validation
- `internal/storage/` — SQLite schema, signatures and imports
- `data/` — local databases (ignored by Git)

## Documentation

- [GitHub applications and permissions](docs/github.md)
- [Deployment and backups](docs/deployment.md)
- [Signature migration](docs/migration.md)
- [Behavior and compatibility limits](docs/behavior.md)
- [Tests and browser fixture](docs/testing.md)
