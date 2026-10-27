// Package storage persists agreements, signatures, sessions and reconciliation jobs in SQLite.
package storage

import (
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store owns a SQLite connection pool configured for serialized writes and durable jobs.
type Store struct {
	*sql.DB
}

// Signature records acceptance of an immutable agreement by a numeric GitHub identity.
type Signature struct {
	// RecordID identifies the stored acceptance for history and revocation.
	RecordID int64 `json:"record_id,omitempty"`
	// Repository is the scope in which this acceptance is recognized.
	Repository string `json:"repository,omitempty"`
	// ID is the stable numeric GitHub identity, independent of username changes.
	ID int64 `json:"github_id"`
	// Login is the GitHub username recorded with the acceptance.
	Login string `json:"login"`
	// Version identifies the immutable agreement text.
	Version string `json:"version"`
	// SignedAt is the original RFC 3339 acceptance timestamp.
	SignedAt string `json:"signed_at"`
	// RevokedAt is the revocation timestamp, or empty when not revoked.
	RevokedAt string `json:"revoked_at,omitempty"`
	// EndAt is the expiration timestamp, or empty for an indefinite acceptance.
	EndAt string `json:"end_at,omitempty"`
	// Origin identifies how this record entered the service.
	Origin string `json:"origin"`
	// Raw retains the original imported evidence without transforming its fields.
	Raw json.RawMessage `json:"raw"`
}

// Open creates the database directory, restricts file permissions and initializes the SQLite schema.
func Open(file string) (*Store, error) {
	if file != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(file, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err = f.Chmod(0600); err != nil {
			f.Close()
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", file)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(schemaSQL)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db}, nil
}

// Agreement stores a versioned document and rejects text changes to an existing version.
func (s *Store) Agreement(version, body, source string) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = agreementTx(tx, version, body, source); err != nil {
		return err
	}
	return tx.Commit()
}

// agreementTx preserves immutable document content within a larger state change.
func agreementTx(tx *sql.Tx, version, body, source string) error {
	digest := recordHash(body)
	var old string
	err := tx.QueryRow("SELECT digest FROM agreements WHERE version=?", version).Scan(&old)
	if err == nil && old != digest {
		return fmt.Errorf("agreement text changed under existing version %s; choose a new version", version)
	}
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	_, err = tx.Exec("INSERT OR IGNORE INTO agreements VALUES(?,?,?,?)", version, body, digest, source)
	return err
}

// Signed checks the latest acceptance for id and version, including revocation and expiration.
func (s *Store) Signed(id int64, version string) (bool, error) {
	var revoked, end string
	err := s.QueryRow("SELECT revoked_at,end_at FROM signatures WHERE github_id=? AND version=? ORDER BY julianday(signed_at) DESC,id DESC LIMIT 1", id, version).Scan(&revoked, &end)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if revoked != "" {
		return false, nil
	}
	if end != "" {
		t, err := time.Parse(time.RFC3339Nano, end)
		if err != nil {
			return false, err
		}
		if !t.After(time.Now()) {
			return false, nil
		}
	}
	return true, nil
}

// Signatures returns signature history, newest first, including original imported evidence.
func (s *Store) Signatures() ([]Signature, error) {
	rows, err := s.Query("SELECT github_id,login,version,signed_at,revoked_at,end_at,origin,raw FROM signatures ORDER BY signed_at DESC,id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Signature{}
	for rows.Next() {
		var x Signature
		var raw string
		if err = rows.Scan(&x.ID, &x.Login, &x.Version, &x.SignedAt, &x.RevokedAt, &x.EndAt, &x.Origin, &raw); err != nil {
			return nil, err
		}
		x.Raw = json.RawMessage(raw)
		result = append(result, x)
	}
	return result, rows.Err()
}

// InsertSignature adds a record within the caller's transaction without duplicating an existing acceptance.
func InsertSignature(tx *sql.Tx, x Signature) error {
	_, err := tx.Exec("INSERT OR IGNORE INTO signatures(github_id,login,version,signed_at,revoked_at,end_at,origin,raw) VALUES(?,?,?,?,?,?,?,?)", x.ID, x.Login, x.Version, x.SignedAt, x.RevokedAt, x.EndAt, x.Origin, string(x.Raw))
	return err
}

// Sign records acceptance and queues tracked pull requests for reevaluation in one transaction.
func (s *Store) Sign(id int64, login, version string) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	x := Signature{
		ID:       id,
		Login:    login,
		Version:  version,
		SignedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Origin:   "web",
		Raw:      json.RawMessage(`{}`),
	}
	if err = InsertSignature(tx, x); err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO jobs(repo,number,installation) SELECT repo,number,installation FROM prs WHERE true ON CONFLICT(repo,number) DO UPDATE SET next=0,attempts=0,error='',generation=jobs.generation+1 ")
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ImportFile atomically imports raw CLA Assistant records, retaining unresolved identities separately.
// Optional repoIDs identify the same repository under historical owner or repository names.
func (s *Store) ImportFile(file, version, repo, source string, repoIDs ...string) (int, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}
	return s.ImportJSON(b, version, repo, source, repoIDs...)
}

// ImportJSON atomically imports uploaded records with explicit repository and agreement scope.
func (s *Store) ImportJSON(b []byte, version, repo, source string, repoIDs ...string) (int, error) {
	var err error
	var records []json.RawMessage
	var rejectedLegacy []LegacySignature
	if err = json.Unmarshal(b, &records); err != nil {
		var wrapper struct {
			Repository string            `json:"repository"`
			Version    string            `json:"gistVersion"`
			Signatures []json.RawMessage `json:"signatures"`
			Legacy     []LegacySignature `json:"legacy_signatures"`
		}
		if err = json.Unmarshal(b, &wrapper); err != nil {
			return 0, err
		}
		if wrapper.Repository != "" && wrapper.Repository != repo {
			return 0, fmt.Errorf("repository mismatch")
		}
		if wrapper.Version != "" && wrapper.Version != version {
			return 0, fmt.Errorf("agreement version mismatch")
		}
		records = wrapper.Signatures
		for _, legacy := range wrapper.Legacy {
			if legacy.RevokedAt != "" {
				rejectedLegacy = append(rejectedLegacy, legacy)
			}
			if len(legacy.Raw) == 0 || !json.Valid(legacy.Raw) {
				return 0, fmt.Errorf("invalid legacy evidence")
			}
			records = append(records, legacy.Raw)
		}
	}
	if len(records) == 0 {
		return 0, fmt.Errorf("no signatures found")
	}
	tx, err := s.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for i, raw := range records {
		var m map[string]json.RawMessage
		if err = json.Unmarshal(raw, &m); err != nil {
			return 0, err
		}
		str := func(keys ...string) string {
			for _, k := range keys {
				if v, ok := m[k]; ok && string(v) != "null" {
					var a string
					if json.Unmarshal(v, &a) == nil {
						return a
					}
					var d map[string]string
					if json.Unmarshal(v, &d) == nil && d["$date"] != "" {
						return d["$date"]
					}
					return string(v)
				}
			}
			return ""
		}
		id, err := strconv.ParseInt(str("userId", "github_id"), 10, 64)
		if str("userId", "github_id") != "" && (err != nil || id <= 0) {
			return 0, fmt.Errorf("record %d: invalid numeric GitHub user ID", i+1)
		}
		v := str("gist_version", "version")
		if v == "" {
			v = version
		}
		if v != version {
			return 0, fmt.Errorf("record %d: agreement version mismatch", i+1)
		}
		if r := str("repo"); r != "" {
			owner := str("owner")
			if owner != "" && owner+"/"+r != repo && !(len(repoIDs) > 0 && repoIDs[0] != "" && str("repoId") == repoIDs[0]) {
				return 0, fmt.Errorf("record %d: repository mismatch", i+1)
			}
		}
		if g := str("gist_url"); g != "" && g != source {
			return 0, fmt.Errorf("record %d: Gist mismatch", i+1)
		}
		x := Signature{
			ID:        id,
			Login:     str("user", "login", "user_name"),
			Version:   v,
			SignedAt:  str("created_at", "signed_at"),
			RevokedAt: str("revoked_at"),
			EndAt:     str("end_at"),
			Origin:    "cla-assistant-import",
			Raw:       raw,
		}
		if x.Login == "" {
			return 0, fmt.Errorf("record %d: missing login", i+1)
		}
		for _, d := range []string{x.SignedAt, x.RevokedAt, x.EndAt} {
			if d == "" {
				continue
			}
			if _, err = time.Parse(time.RFC3339Nano, d); err != nil {
				return 0, fmt.Errorf("record %d: invalid date %q", i+1, d)
			}
		}
		if x.SignedAt == "" {
			return 0, fmt.Errorf("record %d: missing signing date", i+1)
		}
		var revoked bool
		_ = json.Unmarshal(m["revoked"], &revoked)
		if revoked && x.RevokedAt == "" {
			x.RevokedAt = x.SignedAt
		}
		if id <= 0 {
			key := recordHash(string(raw))
			var existing string
			lookupErr := tx.QueryRow("SELECT key FROM legacy_signatures WHERE json(raw)=json(?) LIMIT 1", string(raw)).Scan(&existing)
			if lookupErr == nil {
				key = existing
			} else if lookupErr != sql.ErrNoRows {
				return 0, lookupErr
			}
			_, err = tx.Exec("INSERT OR IGNORE INTO legacy_signatures(key,login,version,signed_at,raw) VALUES(?,?,?,?,?)", key, x.Login, x.Version, x.SignedAt, string(raw))
			if err != nil {
				return 0, err
			}
			if err = associateLegacy(tx, key, repo); err != nil {
				return 0, err
			}
			continue
		}
		if err = InsertSignature(tx, x); err != nil {
			return 0, err
		}
		if err = associateSignature(tx, x, repo); err != nil {
			return 0, err
		}
	}
	for _, legacy := range rejectedLegacy {
		if _, err = time.Parse(time.RFC3339Nano, legacy.RevokedAt); err != nil {
			return 0, fmt.Errorf("invalid legacy revocation date")
		}
		if strings.TrimSpace(legacy.RevocationReason) == "" || len(legacy.RevocationReason) > 1000 {
			return 0, fmt.Errorf("invalid legacy revocation reason")
		}
		var key string
		if err = tx.QueryRow("SELECT l.key FROM legacy_signatures l JOIN legacy_repositories r ON r.signature_key=l.key WHERE json(l.raw)=json(?) AND r.repo=?", string(legacy.Raw), repo).Scan(&key); err != nil {
			return 0, err
		}
		if _, err = tx.Exec("INSERT OR IGNORE INTO legacy_revocations(key,repo,revoked_at,revoked_by,reason) VALUES(?,?,?,?,?)", key, repo, legacy.RevokedAt, legacy.RevokedBy, legacy.RevocationReason); err != nil {
			return 0, err
		}
	}
	if err = queueRepository(tx, repo); err != nil {
		return 0, err
	}
	if err = eventTx(tx, HistoryEvent{Repo: repo, Version: version, Kind: "signatures-imported", Details: fmt.Sprintf("%d records", len(records))}); err != nil {
		return 0, err
	}
	return len(records), tx.Commit()
}

// recordHash derives a stable key for the exact bytes of an imported legacy record.
func recordHash(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

// schemaSQL defines the durable data model and SQLite connection settings.
//
//go:embed schema.sql
var schemaSQL string
