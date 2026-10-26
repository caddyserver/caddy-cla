package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestAutomationDisabledBlocksAllBotWork verifies credentials and queued jobs cannot activate writes.
func TestAutomationDisabledBlocksAllBotWork(t *testing.T) {
	a := fixture(t)
	appKey(t, a)
	a.c.AutomationEnabled = false
	a.c.WebhookSecret = "secret"
	cookie := loginFixture(t, a, 7)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected bot request", 500)
	}))
	defer server.Close()
	a.gh.api = server.URL
	if err := a.enqueue("caddyserver/caddy", 10, 12); err != nil {
		t.Fatal(err)
	}
	if _, err := a.s.Exec("INSERT INTO merge_groups(repo,head_sha,base_sha,installation,received) VALUES(?,?,?,?,?)", "caddyserver/caddy", strings.Repeat("a", 40), strings.Repeat("b", 40), 12, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	a.runJob(t.Context())
	a.runMergeJob(t.Context())
	if requests.Load() != 0 {
		t.Fatal("disabled worker contacted GitHub")
	}
	var jobs int
	if err := a.s.QueryRow("SELECT count(*) FROM jobs").Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal("disabled worker changed queued work")
	}
	response := mergeDelivery(t, a, "disabled-event", "checks_requested", strings.Repeat("c", 40))
	if response.Code != 204 {
		t.Fatal("disabled webhook not acknowledged")
	}
	if err := a.s.QueryRow("SELECT count(*) FROM merge_groups").Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal("disabled webhook queued new work")
	}
	for _, path := range []string{"/cla/admin/recheck", "/cla/recheck"} {
		response = postForm(t, a, cookie, path, url.Values{"csrf": {"csrf-test"}, "repo": {"caddyserver/caddy"}, "pr": {"10"}, "confirm_all": {"yes"}})
		if response.Code != 503 {
			t.Fatalf("disabled recheck %s: %d", path, response.Code)
		}
	}
	if err := a.s.SignRepository(7, "maintainer", "caddyserver/caddy", "v1"); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("signing or recheck contacted GitHub while disabled")
	}
}

// TestBulkRecheckRequiresExplicitConfirmation prevents a routine form POST from scanning old PRs.
func TestBulkRecheckRequiresExplicitConfirmation(t *testing.T) {
	a := fixture(t)
	cookie := loginFixture(t, a, 7)
	response := postForm(t, a, cookie, "/cla/admin/recheck", url.Values{"csrf": {"csrf-test"}, "repo": {"caddyserver/caddy"}})
	if response.Code != 400 {
		t.Fatalf("unconfirmed bulk recheck: %d %s", response.Code, response.Body)
	}
}
