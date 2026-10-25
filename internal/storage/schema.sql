PRAGMA journal_mode=WAL;

PRAGMA busy_timeout=5000;

PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS legacy_signatures(
    key TEXT PRIMARY KEY,
    login TEXT NOT NULL,
    version TEXT NOT NULL REFERENCES agreements(version),
    signed_at TEXT NOT NULL,
    raw TEXT NOT NULL,
    resolved_id INTEGER NOT NULL DEFAULT 0,
    resolved_by INTEGER NOT NULL DEFAULT 0,
    resolved_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agreements(
    version TEXT PRIMARY KEY,
    body TEXT NOT NULL,
    digest TEXT NOT NULL,
    source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signatures(
    id INTEGER PRIMARY KEY,
    github_id INTEGER NOT NULL,
    login TEXT NOT NULL,
    version TEXT NOT NULL REFERENCES agreements(version),
    signed_at TEXT NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT '',
    end_at TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL,
    raw TEXT NOT NULL,
    UNIQUE(github_id,version,signed_at)
);

CREATE INDEX IF NOT EXISTS signer_version ON signatures(github_id,version);

CREATE TABLE IF NOT EXISTS sessions(
    token TEXT PRIMARY KEY,
    github_id INTEGER NOT NULL,
    login TEXT NOT NULL,
    csrf TEXT NOT NULL,
    expires INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_states(
    token TEXT PRIMARY KEY,
    verifier TEXT NOT NULL,
    expires INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS prs(
    repo TEXT NOT NULL,
    number INTEGER NOT NULL,
    installation INTEGER NOT NULL,
    PRIMARY KEY(repo,number)
);

CREATE TABLE IF NOT EXISTS deliveries(
    id TEXT PRIMARY KEY,
    received INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs(
    id INTEGER PRIMARY KEY,
    repo TEXT NOT NULL,
    number INTEGER NOT NULL,
    installation INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    generation INTEGER NOT NULL DEFAULT 0,
    UNIQUE(repo,number)
);

CREATE TABLE IF NOT EXISTS repositories (
    name TEXT PRIMARY KEY,
    github_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    version TEXT NOT NULL REFERENCES agreements(version),
    gist_url TEXT NOT NULL DEFAULT '',
    gist_file TEXT NOT NULL DEFAULT '',
    -- Retained for compatibility with existing databases; Gists refresh manually.
    auto_update INTEGER NOT NULL DEFAULT 0,
    policy TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1,
    updated_by INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signature_repositories (
    signature_id INTEGER NOT NULL REFERENCES signatures(id),
    repo TEXT NOT NULL REFERENCES repositories(name),
    revoked_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(signature_id, repo)
);

CREATE TABLE IF NOT EXISTS legacy_repositories (
    signature_key TEXT NOT NULL REFERENCES legacy_signatures(key),
    repo TEXT NOT NULL REFERENCES repositories(name),
    PRIMARY KEY(signature_key, repo)
);

CREATE TABLE IF NOT EXISTS history_events (
    id INTEGER PRIMARY KEY,
    github_id INTEGER NOT NULL,
    actor_id INTEGER NOT NULL,
    repo TEXT NOT NULL,
    version TEXT NOT NULL,
    kind TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS user_history ON history_events(github_id, occurred_at);

CREATE TABLE IF NOT EXISTS oauth_return_paths (
    token TEXT PRIMARY KEY,
    return_path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manual_rechecks (
    repo TEXT NOT NULL,
    number INTEGER NOT NULL,
    requested_at INTEGER NOT NULL,
    PRIMARY KEY(repo, number)
);

-- Merge-group checks persist independently of individual pull-request jobs.
CREATE TABLE IF NOT EXISTS merge_groups (
    repo TEXT NOT NULL REFERENCES repositories(name),
    head_sha TEXT NOT NULL,
    base_sha TEXT NOT NULL,
    installation INTEGER NOT NULL,
    pending INTEGER NOT NULL DEFAULT 1,
    generation INTEGER NOT NULL DEFAULT 1,
    attempts INTEGER NOT NULL DEFAULT 0,
    next INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    received INTEGER NOT NULL,
    PRIMARY KEY(repo, head_sha)
);
