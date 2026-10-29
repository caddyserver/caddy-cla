package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// associateSignature recognizes an acceptance only within the selected repository.
func associateSignature(tx *sql.Tx, x Signature, repo string) error {
	var exists int
	if err := tx.QueryRow("SELECT count(*) FROM repositories WHERE name=?", repo).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	} // Initial migration can bootstrap scope after legacy CLI imports.
	_, err := tx.Exec(`INSERT OR IGNORE INTO signature_repositories(signature_id,repo) SELECT id,? FROM signatures WHERE github_id=? AND version=? AND signed_at=?`, repo, x.ID, x.Version, x.SignedAt)
	return err
}

// associateLegacy retains repository scope for historical evidence without granting account approval.
func associateLegacy(tx *sql.Tx, key, repo string) error {
	var exists int
	if err := tx.QueryRow("SELECT count(*) FROM repositories WHERE name=?", repo).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	_, err := tx.Exec("INSERT OR IGNORE INTO legacy_repositories VALUES(?,?)", key, repo)
	return err
}

// RepositorySigned checks the latest scoped acceptance, including repository-specific revocations.
func (s *Store) RepositorySigned(id int64, repo, version string) (bool, error) {
	var revoked, end string
	err := s.QueryRow(`SELECT CASE WHEN sr.revoked_at<>'' THEN sr.revoked_at ELSE s.revoked_at END,s.end_at FROM signatures s JOIN signature_repositories sr ON sr.signature_id=s.id WHERE s.github_id=? AND sr.repo=? AND s.version=? ORDER BY julianday(s.signed_at) DESC,s.id DESC LIMIT 1`, id, repo, version).Scan(&revoked, &end)
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
		expiry, err := time.Parse(time.RFC3339Nano, end)
		if err != nil {
			return false, err
		}
		if !expiry.After(time.Now()) {
			return false, nil
		}
	}
	return true, nil
}

// SignRepository records explicit acceptance and queues that repository's PR checks atomically.
func (s *Store) SignRepository(id int64, login, repo, version string) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = currentAgreement(tx, repo, version); err != nil {
		return err
	}
	x := Signature{ID: id, Login: login, Version: version, SignedAt: time.Now().UTC().Format(time.RFC3339Nano), Origin: "web", Raw: json.RawMessage(`{}`)}
	if err = InsertSignature(tx, x); err != nil {
		return err
	}
	if err = associateSignature(tx, x, repo); err != nil {
		return err
	}
	if err = queueRepository(tx, repo); err != nil {
		return err
	}
	if err = eventTx(tx, HistoryEvent{GitHubID: id, ActorID: id, Repo: repo, Version: version, Kind: "signed"}); err != nil {
		return err
	}
	return tx.Commit()
}

// ScopedSignatures lists records for a repository, a user, or both without exposing unrelated evidence.
// A zero user ID is appropriate only after repository administration is authorized.
func (s *Store) ScopedSignatures(repo string, id int64) ([]Signature, error) {
	rows, err := s.Query(`SELECT s.id,s.github_id,s.login,s.version,s.signed_at,CASE WHEN sr.revoked_at<>'' THEN sr.revoked_at ELSE s.revoked_at END,s.end_at,s.origin,s.raw,sr.repo FROM signatures s JOIN signature_repositories sr ON sr.signature_id=s.id WHERE (?='' OR sr.repo=?) AND (?=0 OR s.github_id=?) ORDER BY julianday(s.signed_at) DESC,s.id DESC,sr.repo`, repo, repo, id, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Signature{}
	for rows.Next() {
		var x Signature
		var raw string
		if err = rows.Scan(&x.RecordID, &x.ID, &x.Login, &x.Version, &x.SignedAt, &x.RevokedAt, &x.EndAt, &x.Origin, &raw, &x.Repository); err != nil {
			return nil, err
		}
		x.Raw = json.RawMessage(raw)
		result = append(result, x)
	}
	return result, rows.Err()
}

// RevokeSignature allows a signer to revoke only their own acceptance in the specified repository.
func (s *Store) RevokeSignature(recordID, userID int64, repo string) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version string
	err = tx.QueryRow("SELECT s.version FROM signatures s JOIN signature_repositories sr ON s.id=sr.signature_id WHERE s.id=? AND s.github_id=? AND sr.repo=?", recordID, userID, repo).Scan(&version)
	if err != nil {
		return fmt.Errorf("signature not found for this account")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.Exec("UPDATE signature_repositories SET revoked_at=? WHERE signature_id=? AND repo=? AND revoked_at=''", now, recordID, repo)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return tx.Commit()
	}
	if err = queueRepository(tx, repo); err != nil {
		return err
	}
	if err = eventTx(tx, HistoryEvent{GitHubID: userID, ActorID: userID, Repo: repo, Version: version, Kind: "revoked", OccurredAt: now}); err != nil {
		return err
	}
	return tx.Commit()
}

// ScopedLegacy lists imported historical identities attached to the authorized repository.
func (s *Store) ScopedLegacy(repo string) ([]LegacySignature, error) {
	rows, err := s.Query(`SELECT l.key,l.login,l.version,l.signed_at,l.raw,CASE WHEN EXISTS(SELECT 1 FROM signatures s JOIN signature_repositories sr ON s.id=sr.signature_id WHERE sr.repo=lr.repo AND s.github_id=l.resolved_id AND s.version=l.version AND s.signed_at=l.signed_at) THEN l.resolved_id ELSE 0 END,l.resolved_by,l.resolved_at,COALESCE(v.revoked_at,''),COALESCE(v.revoked_by,0),COALESCE(v.reason,'') FROM legacy_signatures l JOIN legacy_repositories lr ON l.key=lr.signature_key LEFT JOIN legacy_revocations v ON v.key=l.key AND v.repo=lr.repo WHERE lr.repo=? ORDER BY (v.revoked_at IS NOT NULL),l.resolved_id<>0,l.login`, repo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LegacySignature{}
	for rows.Next() {
		var x LegacySignature
		var raw string
		if err = rows.Scan(&x.Key, &x.Login, &x.Version, &x.SignedAt, &raw, &x.ResolvedID, &x.ResolvedBy, &x.ResolvedAt, &x.RevokedAt, &x.RevokedBy, &x.RevocationReason); err != nil {
			return nil, err
		}
		x.Raw = json.RawMessage(raw)
		out = append(out, x)
	}
	return out, rows.Err()
}

// LinkLegacy verifies scope, attaches the historical acceptance and records who resolved its identity.
func (s *Store) LinkLegacy(key, repo string, userID int64, login string, actor int64) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version, date, raw string
	var resolved int64
	err = tx.QueryRow(`SELECT l.version,l.signed_at,l.raw,l.resolved_id FROM legacy_signatures l JOIN legacy_repositories lr ON l.key=lr.signature_key WHERE l.key=? AND lr.repo=?`, key, repo).Scan(&version, &date, &raw, &resolved)
	if err != nil {
		return fmt.Errorf("legacy signature not found in this repository")
	}
	var rejected bool
	if err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM legacy_revocations WHERE key=? AND repo=?)", key, repo).Scan(&rejected); err != nil {
		return err
	}
	if rejected {
		return fmt.Errorf("historical evidence was revoked; contributor must sign again")
	}
	if resolved != 0 && resolved != userID {
		return fmt.Errorf("legacy signature is already linked to a different identity")
	}
	var m map[string]json.RawMessage
	if err = json.Unmarshal([]byte(raw), &m); err != nil {
		return err
	}
	var revoked bool
	_ = json.Unmarshal(m["revoked"], &revoked)
	if revoked {
		return fmt.Errorf("cannot activate a revoked legacy signature")
	}
	var revokedAt, endAt string
	_ = json.Unmarshal(m["revoked_at"], &revokedAt)
	_ = json.Unmarshal(m["end_at"], &endAt)
	x := Signature{ID: userID, Login: login, Version: version, SignedAt: date, RevokedAt: revokedAt, EndAt: endAt, Origin: "legacy-admin-link", Raw: json.RawMessage(raw)}
	if err = InsertSignature(tx, x); err != nil {
		return err
	}
	if err = associateSignature(tx, x, repo); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.Exec("UPDATE legacy_signatures SET resolved_id=?,resolved_by=?,resolved_at=? WHERE key=?", userID, actor, now, key); err != nil {
		return err
	}
	if err = queueRepository(tx, repo); err != nil {
		return err
	}
	if err = eventTx(tx, HistoryEvent{GitHubID: userID, ActorID: actor, Repo: repo, Version: version, Kind: "historical-identity-linked"}); err != nil {
		return err
	}
	return tx.Commit()
}

// ErrRecheckLimited indicates that this PR was checked within the shared cooldown.
var ErrRecheckLimited = errors.New("a recheck was just requested; retry in 30 seconds")

// ReserveManualRecheck atomically enforces the per-PR cooldown without enqueueing any work.
func (s *Store) ReserveManualRecheck(repo string, number int) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous int64
	err = tx.QueryRow("SELECT requested_at FROM manual_rechecks WHERE repo=? AND number=?", repo, number).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	now := time.Now().Unix()
	if previous > now-30 {
		return ErrRecheckLimited
	}
	if _, err = tx.Exec("INSERT INTO manual_rechecks VALUES(?,?,?) ON CONFLICT(repo,number) DO UPDATE SET requested_at=excluded.requested_at", repo, number, now); err != nil {
		return err
	}
	return tx.Commit()
}
