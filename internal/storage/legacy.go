package storage

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LegacySignature preserves historical evidence that lacks a verified numeric GitHub identity.
type LegacySignature struct {
	// Key identifies the exact original legacy record.
	Key string `json:"key"`
	// Login is the GitHub username recorded with the acceptance.
	Login string `json:"login"`
	// Version identifies the immutable agreement text.
	Version string `json:"version"`
	// SignedAt is the original RFC 3339 acceptance timestamp.
	SignedAt string `json:"signed_at"`
	// Raw retains the original imported evidence without transforming its fields.
	Raw json.RawMessage `json:"raw"`
	// RevokedAt records when an administrator rejected this evidence in its repository scope.
	RevokedAt string `json:"legacy_revoked_at,omitempty"`
	// RevokedBy is the administrator who rejected the historical evidence.
	RevokedBy int64 `json:"legacy_revoked_by,omitempty"`
	// RevocationReason explains why the evidence cannot be linked.
	RevocationReason string `json:"legacy_revocation_reason,omitempty"`
	// ResolvedID is the verified GitHub identity, or zero while unresolved.
	ResolvedID int64 `json:"resolved_id,omitempty"`
	// ResolvedBy is the GitHub ID of the administrator who linked the identity.
	ResolvedBy int64 `json:"resolved_by,omitempty"`
	// ResolvedAt records when the identity was verified and linked.
	ResolvedAt string `json:"resolved_at,omitempty"`
}

// Legacy returns historical records and their administrator identity-resolution audit trail.
func (s *Store) Legacy() ([]LegacySignature, error) {
	rows, err := s.Query("SELECT key,login,version,signed_at,raw,resolved_id,resolved_by,resolved_at FROM legacy_signatures ORDER BY login")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LegacySignature{}
	for rows.Next() {
		var x LegacySignature
		var raw string
		if err = rows.Scan(&x.Key, &x.Login, &x.Version, &x.SignedAt, &raw, &x.ResolvedID, &x.ResolvedBy, &x.ResolvedAt); err != nil {
			return nil, err
		}
		x.Raw = json.RawMessage(raw)
		out = append(out, x)
	}
	return out, rows.Err()
}

// RevokeLegacy prevents unresolved historical evidence from being linked in one repository.
// It preserves the original record and does not revoke any verified account's acceptance.
func (s *Store) RevokeLegacy(key, repo string, actor int64, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 1000 {
		return fmt.Errorf("a reason of at most 1000 bytes is required")
	}
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var login, version string
	var resolved int64
	if err = tx.QueryRow("SELECT l.login,l.version,l.resolved_id FROM legacy_signatures l JOIN legacy_repositories r ON r.signature_key=l.key WHERE l.key=? AND r.repo=?", key, repo).Scan(&login, &version, &resolved); err != nil {
		return fmt.Errorf("legacy record not found in this repository")
	}
	if resolved != 0 {
		return fmt.Errorf("linked signatures must be revoked from signer history")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.Exec("INSERT OR IGNORE INTO legacy_revocations(key,repo,revoked_at,revoked_by,reason) VALUES(?,?,?,?,?)", key, repo, now, actor, reason)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	details, _ := json.Marshal(map[string]string{"legacy_key": key, "login": login, "reason": reason})
	if err = eventTx(tx, HistoryEvent{ActorID: actor, Repo: repo, Version: version, Kind: "historical-evidence-revoked", Details: string(details)}); err != nil {
		return err
	}
	return tx.Commit()
}
