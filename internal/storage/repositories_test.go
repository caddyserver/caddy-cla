package storage

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// testStore creates the original single-agreement data model and migrates its repository scope.
func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "cla.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.Agreement("v1", "Original agreement", "https://gist.github.com/owner/abc"); err != nil {
		t.Fatal(err)
	}
	if err = s.BootstrapRepositories([]string{"owner/one"}, "1", "v1", "https://gist.github.com/owner/abc", Policy{}); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestRepositoryIsolation keeps identical document revisions from sharing acceptance across repositories.
func TestRepositoryIsolation(t *testing.T) {
	s := testStore(t)
	first, _ := s.Repository("owner/one")
	second := first
	second.Name = "owner/two"
	second.Generation = 0
	if err := s.SaveRepository(second, 7); err != nil {
		t.Fatal(err)
	}
	if err := s.SignRepository(42, "alice", first.Name, "v1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.RepositorySigned(42, second.Name, "v1"); ok {
		t.Fatal("acceptance leaked into another repository")
	}
	if err := s.SignRepository(42, "alice", second.Name, "v1"); err != nil {
		t.Fatal(err)
	}
	records, err := s.ScopedSignatures(first.Name, 42)
	if err != nil || len(records) != 1 {
		t.Fatalf("history: %v %v", records, err)
	}
	if err = s.RevokeSignature(records[0].RecordID, 99, first.Name); err == nil {
		t.Fatal("another user revoked acceptance")
	}
	if err = s.RevokeSignature(records[0].RecordID, 42, first.Name); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.RepositorySigned(42, first.Name, "v1"); ok {
		t.Fatal("revoked acceptance passed")
	}
	if ok, _ := s.RepositorySigned(42, second.Name, "v1"); !ok {
		t.Fatal("revocation leaked across repository scopes")
	}
	events, err := s.UserHistory(42)
	if err != nil || len(events) != 3 {
		t.Fatalf("history events: %v %v", events, err)
	}
}

// TestLiveAgreementPersists verifies immutable snapshots, stale edit rejection and restart-safe live settings.
func TestLiveAgreementPersists(t *testing.T) {
	s := testStore(t)
	cfg, _ := s.Repository("owner/one")
	stale := cfg
	cfg.Body = "Updated agreement"
	cfg.Version = "v2"
	if err := s.SaveRepository(cfg, 7); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRepository(stale, 7); err != ErrConflict {
		t.Fatalf("stale edit: %v", err)
	}
	if err := s.SignRepository(42, "alice", cfg.Name, "v1"); err == nil {
		t.Fatal("accepted a form for the old version")
	}
	if err := s.BootstrapRepositories([]string{"owner/one"}, "1", "v1", "", Policy{}); err != nil {
		t.Fatal(err)
	}
	current, _ := s.Repository(cfg.Name)
	if current.Version != "v2" || current.Body != "Updated agreement" {
		t.Fatal("bootstrap overwrote live configuration")
	}
	current.Body = "Silently changed"
	if err := s.SaveRepository(current, 7); err == nil {
		t.Fatal("immutable snapshot changed")
	}
	var original string
	if err := s.QueryRow("SELECT body FROM agreements WHERE version='v1'").Scan(&original); err != nil || original != "Original agreement" {
		t.Fatal("original agreement lost")
	}
}

// TestScopedImportIsAtomic preserves unidentified records without giving them approval or leaking scope.
func TestScopedImportIsAtomic(t *testing.T) {
	s := testStore(t)
	data := []byte(`[{"userId":"42","user":"alice","created_at":"2020-01-01T00:00:00Z"},{"user":"historical","created_at":"2015-01-01T00:00:00Z"}]`)
	if count, err := s.ImportJSON(data, "v1", "owner/one", "https://gist.github.com/owner/abc"); err != nil || count != 2 {
		t.Fatalf("import: %d %v", count, err)
	}
	known, _ := s.ScopedSignatures("owner/one", 0)
	legacy, _ := s.ScopedLegacy("owner/one")
	if len(known) != 1 || len(legacy) != 1 {
		t.Fatal("imported scope or unresolved record missing")
	}
	invalid := []byte(`[{"userId":"43","user":"bob","created_at":"2020-01-01T00:00:00Z"},{"userId":"invalid","user":"bad"}]`)
	if _, err := s.ImportJSON(invalid, "v1", "owner/one", ""); err == nil {
		t.Fatal("malformed import succeeded")
	}
	known, _ = s.ScopedSignatures("owner/one", 0)
	if len(known) != 1 {
		t.Fatal("partial import committed")
	}
	if err := s.LinkLegacy(legacy[0].Key, "owner/other", 99, "someone", 7); err == nil {
		t.Fatal("unrelated repository linked legacy evidence")
	}
	if err := s.LinkLegacy(legacy[0].Key, "owner/one", 99, "historical", 7); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.RepositorySigned(99, "owner/one", "v1"); !ok {
		t.Fatal("verified historical identity not recognized")
	}
	raw, _ := json.Marshal(known)
	if len(raw) == 0 {
		t.Fatal("missing export")
	}
}

// TestBootstrapMigratesOldEvidence scopes existing records once without changing their original bytes.
func TestBootstrapMigratesOldEvidence(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Agreement("v1", "Original", ""); err != nil {
		t.Fatal(err)
	}
	data := []byte(`[{"userId":"42","user":"alice","created_at":"2020-01-01T00:00:00Z"},{"user":"historical","created_at":"2015-01-01T00:00:00Z"}]`)
	if _, err = s.ImportJSON(data, "v1", "owner/one", ""); err != nil {
		t.Fatal(err)
	}
	if err = s.BootstrapRepositories([]string{"owner/one"}, "1", "v1", "", Policy{}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.RepositorySigned(42, "owner/one", "v1"); !ok {
		t.Fatal("existing signature not recognized after migration")
	}
	legacy, _ := s.ScopedLegacy("owner/one")
	if len(legacy) != 1 {
		t.Fatal("existing historical evidence lost during migration")
	}
	cfg, _ := s.Repository("owner/one")
	cfg.Name = "owner/two"
	cfg.Generation = 0
	if err = s.SaveRepository(cfg, 7); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.RepositorySigned(42, "owner/two", "v1"); ok {
		t.Fatal("new repository inherited old evidence implicitly")
	}
}
