package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSynchronousRecheck redirects only after publishing the status and resolving the existing reminder.
func TestSynchronousRecheck(t *testing.T) {
	a := fixture(t)
	appKey(t, a)
	if _, err := a.s.Exec("INSERT INTO prs VALUES('caddyserver/caddy',10,12)"); err != nil {
		t.Fatal(err)
	}
	if err := a.s.SignRepository(42, "alice", "caddyserver/caddy", "v1"); err != nil {
		t.Fatal(err)
	}
	// Signing already queued work; a direct recheck must not add or drain background jobs.
	before := 0
	a.s.QueryRow("SELECT count(*) FROM jobs").Scan(&before)
	requests, statuses, updates := 0, 0, 0
	body := ""
	showReminder := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/app/installations/12/access_tokens":
			fmt.Fprint(w, `{"token":"test"}`)
		case "/repos/caddyserver/caddy/pulls/10":
			fmt.Fprint(w, `{"state":"open","commits":1,"user":{"id":42,"login":"alice"},"head":{"sha":"head"}}`)
		case "/repos/caddyserver/caddy/pulls/10/commits":
			fmt.Fprint(w, `[{"author":{"id":42,"login":"alice"}}]`)
		case "/repos/caddyserver/caddy/statuses/head":
			statuses++
			fmt.Fprint(w, `{}`)
		case "/repos/caddyserver/caddy/issues/10/comments":
			if r.Method != "GET" {
				t.Error("manual recheck created comment")
			}
			if showReminder {
				fmt.Fprint(w, `[{"id":99,"body":"<!-- caddy-cla --> old reminder","performed_via_github_app":{"id":123}}]`)
			} else {
				fmt.Fprint(w, `[]`)
			}
		case "/repos/caddyserver/caddy/issues/comments/99":
			updates++
			var input map[string]string
			json.NewDecoder(r.Body).Decode(&input)
			body = input["body"]
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected API call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	a.gh.api = server.URL
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	path := "/cla/recheck?repo=caddyserver%2Fcaddy&pr=10"
	w := get(path)
	if w.Code != 303 || w.Header().Get("Location") != "https://github.com/caddyserver/caddy/pull/10" || statuses != 1 || updates != 1 {
		t.Fatalf("redirect before completion: %d status=%d updates=%d body=%s", w.Code, statuses, updates, w.Body)
	}
	if strings.Contains(body, "Recheck this PR") || !strings.Contains(body, "✅") {
		t.Fatalf("resolved reminder: %s", body)
	}
	firstRequests := requests
	w = get(path)
	if w.Code != 303 || w.Header().Get("Retry-After") != "30" || requests != firstRequests {
		t.Fatal("cooldown made API calls or failed to return to PR")
	}
	w = get("/cla/recheck?repo=caddyserver%2Fcaddy&pr=11")
	if w.Code != 404 || requests != firstRequests {
		t.Fatal("untracked PR reached GitHub")
	}
	w = get("/cla/recheck?repo=other%2Frepo&pr=10")
	if w.Code != 400 || requests != firstRequests {
		t.Fatal("unconfigured repository reached GitHub")
	}
	after := 0
	a.s.QueryRow("SELECT count(*) FROM jobs").Scan(&after)
	if before != after {
		t.Fatal("manual check changed background jobs")
	}
	// Even an unsigned PR with initial-open permission cannot get a new comment from a public link.
	showReminder = false
	if _, err := a.s.Exec("UPDATE signatures SET revoked_at='2026-01-01T00:00:00Z'"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.s.Exec("UPDATE manual_rechecks SET requested_at=0"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.s.Exec("INSERT INTO initial_pr_checks(repo,number) VALUES('caddyserver/caddy',10)"); err != nil {
		t.Fatal(err)
	}
	w = get(path)
	if w.Code != 303 || statuses != 2 || updates != 1 {
		t.Fatal("unsigned manual check did not stay silent")
	}
	firstRequests = requests
	a.c.AutomationEnabled = false
	w = get(path)
	if w.Code != 503 || requests != firstRequests {
		t.Fatal("disabled manual check contacted GitHub")
	}
}
