package storage

import (
	"database/sql"
	"encoding/json"
)

// Policy defines username patterns and public organization memberships exempt from signing.
type Policy struct {
	// Users contains username patterns exempt from signing.
	Users []string `json:"users"`
	// PublicOrgs contains organizations whose public members are exempt.
	PublicOrgs []string `json:"public_orgs"`
}

// Policy returns persisted exemption rules, falling back to deployment defaults.
func (s *Store) Policy(defaults Policy) (Policy, error) {
	p := defaults
	var raw string
	err := s.QueryRow("SELECT value FROM settings WHERE key='policy'").Scan(&raw)
	if err == sql.ErrNoRows {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal([]byte(raw), &p)
	return p, err
}
