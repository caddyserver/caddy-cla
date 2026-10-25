package storage

import "encoding/json"

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
