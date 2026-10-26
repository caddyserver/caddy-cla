# Testing

Run the automated suite:

```sh
go test -race ./...
go vet ./...
```

Tests use temporary SQLite databases and local mock GitHub servers. Merge-queue
coverage includes signed webhook deduplication, retries, comparison pagination,
multiple PR authors, ignored co-author trailers, signature revocation, agreement changes and
concurrent requeues. Incomplete attribution never produces a successful status.

## Interactive browser fixture

```sh
CLA_BROWSER_TEST=1 go test ./internal/app -run '^TestBrowserHarness$' -v -count=1 -timeout=30m
```

Open `http://127.0.0.1:8098/cla/`. Visit `/__test/login` for the synthetic
administrator, or `/__test/login?id=44` for a reader. Set
`CLA_BROWSER_BASE_PATH=root` to test hosting at `/` instead. Stop with Ctrl+C.
The database is temporary, all GitHub calls are mocked, and the agreement is
explicitly nonbinding test text. Fixture login exists only in `_test.go` and is
never compiled into the application binary.

Browser verification covered required acceptance, signing, history, revocation,
repository isolation, manual Gist refresh, JSON file import, recheck submission,
reader permission denial, private user history and logout under `/cla`. Signing
and administration were also verified at `/`. These checks found and fixed an
Origin/referrer-policy conflict that prevented browser form submissions.

Real GitHub OAuth and installed-App behavior remain unverified until credentials
and a disposable live repository are available. No live repository was changed.
