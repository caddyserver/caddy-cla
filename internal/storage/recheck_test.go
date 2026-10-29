package storage

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// TestManualRecheckCooldown shares one atomic reservation across all callers without queuing work.
func TestManualRecheckCooldown(t *testing.T) {
	s := testStore(t)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.ReserveManualRecheck("owner/one", 10)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrRecheckLimited) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted concurrent rechecks: %d", accepted.Load())
	}
	var jobs int
	s.QueryRow("SELECT count(*) FROM jobs").Scan(&jobs)
	if jobs != 0 {
		t.Fatal("cooldown queued work")
	}
	if _, err := s.Exec("UPDATE manual_rechecks SET requested_at=requested_at-31"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveManualRecheck("owner/one", 10); err != nil {
		t.Fatal(err)
	}
}
