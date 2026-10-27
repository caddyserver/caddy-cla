package storage

import (
	"encoding/json"
	"testing"
)

// TestLegacyRevocationPreservesEvidence verifies rejection is scoped, durable across imports and cannot affect linked signers.
func TestLegacyRevocationPreservesEvidence(t *testing.T) {
	s := testStore(t)
	raw := []byte(`[{"user":"old-name","created_at":"2016-01-01T00:00:00Z"}]`)
	if _, err := s.ImportJSON(raw, "v1", "owner/one", ""); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ScopedLegacy("owner/one")
	key := rows[0].Key
	if err := s.RevokeLegacy(key, "owner/other", 7, "unverified"); err == nil {
		t.Fatal("wrong repository revoked")
	}
	if err := s.RevokeLegacy(key, "owner/one", 7, ""); err == nil {
		t.Fatal("reason missing")
	}
	for range 2 {
		if err := s.RevokeLegacy(key, "owner/one", 7, "Username reassigned"); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ = s.ScopedLegacy("owner/one")
	if rows[0].RevokedAt == "" || rows[0].RevokedBy != 7 || rows[0].RevocationReason != "Username reassigned" {
		t.Fatalf("missing audit metadata: %+v", rows[0])
	}
	if err := s.LinkLegacy(key, "owner/one", 42, "old-name", 7); err == nil {
		t.Fatal("revoked evidence linked")
	}
	if _, err := s.ImportJSON(raw, "v1", "owner/one", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkLegacy(key, "owner/one", 42, "old-name", 7); err == nil {
		t.Fatal("reimport revived evidence")
	}
	var count int
	if err := s.QueryRow("SELECT count(*) FROM history_events WHERE kind='historical-evidence-revoked'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate audit events: %d %v", count, err)
	}
	exported, err := json.Marshal(map[string]any{"legacy_signatures": rows})
	if err != nil {
		t.Fatal(err)
	}
	restored := testStore(t)
	if _, err = restored.ImportJSON(exported, "v1", "owner/one", ""); err != nil {
		t.Fatal(err)
	}
	back, _ := restored.ScopedLegacy("owner/one")
	if len(back) != 1 || back[0].RevokedAt != rows[0].RevokedAt || string(back[0].Raw) != string(rows[0].Raw) {
		t.Fatal("export/import lost rejection or original evidence")
	}
	if err = restored.LinkLegacy(back[0].Key, "owner/one", 42, "old-name", 7); err == nil {
		t.Fatal("restored rejection ignored")
	}
	if err = s.SignRepository(42, "old-name", "owner/one", "v1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.RepositorySigned(42, "owner/one", "v1"); !ok {
		t.Fatal("new signature blocked by rejected legacy record")
	}
	clean := testStore(t)
	if _, err = clean.ImportJSON(raw, "v1", "owner/one", ""); err != nil {
		t.Fatal(err)
	}
	records, _ := clean.ScopedLegacy("owner/one")
	if err = clean.LinkLegacy(records[0].Key, "owner/one", 42, "old-name", 7); err != nil {
		t.Fatal(err)
	}
	if err = clean.RevokeLegacy(records[0].Key, "owner/one", 7, "unverified"); err == nil {
		t.Fatal("linked record revoked via unresolved-evidence flow")
	}
}
