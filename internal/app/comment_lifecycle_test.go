package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCommentLifecycle creates one actionable reminder and reuses it across every later state.
func TestCommentLifecycle(t *testing.T) {
	a := fixture(t)
	appKey(t, a)
	var created, updated, statuses int
	body := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/12/access_tokens":
			fmt.Fprint(w, `{"token":"test-token"}`)
		case "/repos/caddyserver/caddy/pulls/10":
			fmt.Fprint(w, `{"state":"open","commits":1,"user":{"id":42,"login":"alice"},"head":{"sha":"head"}}`)
		case "/repos/caddyserver/caddy/pulls/10/commits":
			fmt.Fprint(w, `[{"sha":"head","author":{"id":42,"login":"alice"},"commit":{"message":"test"}}]`)
		case "/repos/caddyserver/caddy/statuses/head":
			statuses++
			fmt.Fprint(w, `{}`)
		case "/repos/caddyserver/caddy/issues/10/comments":
			if r.Method == "GET" {
				if body == "" {
					fmt.Fprint(w, `[]`)
				} else {
					json.NewEncoder(w).Encode([]map[string]any{{"id": 99, "body": body, "performed_via_github_app": map[string]int{"id": 123}}})
				}
			} else if r.Method == "POST" {
				created++
				var input map[string]string
				json.NewDecoder(r.Body).Decode(&input)
				body = input["body"]
				fmt.Fprint(w, `{"id":99}`)
			} else {
				t.Errorf("unexpected comment method %s", r.Method)
				http.Error(w, "unexpected method", 500)
			}
		case "/repos/caddyserver/caddy/issues/comments/99":
			if r.Method != "PATCH" {
				t.Errorf("unexpected update method %s", r.Method)
			}
			updated++
			var input map[string]string
			json.NewDecoder(r.Body).Decode(&input)
			body = input["body"]
			fmt.Fprint(w, `{"id":99}`)
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	a.gh.api = server.URL
	check := func() {
		t.Helper()
		if err := a.gh.reconcile(t.Context(), a.s, "caddyserver/caddy", 10, 12); err != nil {
			t.Fatal(err)
		}
	}
	sign := func() {
		t.Helper()
		if err := a.s.SignRepository(42, "alice", "caddyserver/caddy", "v1"); err != nil {
			t.Fatal(err)
		}
	}
	revoke := func() {
		t.Helper()
		records, err := a.s.ScopedSignatures("caddyserver/caddy", 42)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if record.RevokedAt == "" {
				if err = a.s.RevokeSignature(record.RecordID, 42, "caddyserver/caddy"); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if _, err := a.s.Exec("INSERT INTO initial_pr_checks(repo,number) VALUES('caddyserver/caddy',10)"); err != nil {
		t.Fatal(err)
	}
	sign()
	check()
	check()
	if created != 0 || updated != 0 || statuses != 2 {
		t.Fatalf("satisfied PR was commented on: create=%d update=%d statuses=%d", created, updated, statuses)
	}
	revoke()
	check()
	if created != 0 || updated != 0 {
		t.Fatal("existing unsigned PR must remain silent")
	}
	// Simulate a newly opened, not-yet-verified PR.
	if _, err := a.s.Exec("UPDATE initial_pr_checks SET checked=0 WHERE repo='caddyserver/caddy' AND number=10"); err != nil {
		t.Fatal(err)
	}
	check()
	check()
	if created != 1 || updated != 0 {
		t.Fatalf("reminder duplicated: create=%d update=%d", created, updated)
	}
	if !strings.Contains(body, "⚠️ **") || !strings.Contains(body, "[Recheck this PR](") || strings.Contains(body, "also comment") {
		t.Fatal("reminder must advertise the link flow only")
	}
	sign()
	check()
	check()
	if created != 1 || updated != 1 {
		t.Fatalf("resolution created or repeatedly edited comments: create=%d update=%d", created, updated)
	}
	if !strings.Contains(body, "✅ **") || !strings.Contains(body, "All identified contributors have signed the CLA. Thank you!") || strings.Contains(body, "or are exempt") || strings.Contains(body, "[Recheck this PR]") {
		t.Fatal("unexpected resolved wording")
	}
	revoke()
	check()
	if created != 1 || updated != 2 {
		t.Fatalf("later changes must reuse the reminder: create=%d update=%d", created, updated)
	}
}

// TestInitialReminderEligibility excludes backfills, updates and reopened PRs.
func TestInitialReminderEligibility(t *testing.T) {
	for _, tc := range []struct {
		action  string
		tracked bool
		want    int
	}{
		{"opened", false, 1},
		{"opened", true, 0},
		{"synchronize", false, 0},
		{"reopened", false, 0},
	} {
		t.Run(fmt.Sprintf("%s/tracked=%t", tc.action, tc.tracked), func(t *testing.T) {
			a := fixture(t)
			a.c.WebhookSecret = "secret"
			if tc.tracked {
				if err := a.enqueue("caddyserver/caddy", 10, 12); err != nil {
					t.Fatal(err)
				}
			}
			payload := fmt.Sprintf(`{"action":%q,"number":10,"repository":{"full_name":"caddyserver/caddy"},"installation":{"id":12}}`, tc.action)
			mac := hmac.New(sha256.New, []byte("secret"))
			mac.Write([]byte(payload))
			r := httptest.NewRequest("POST", "/cla/webhooks/github", strings.NewReader(payload))
			r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
			r.Header.Set("X-GitHub-Delivery", "initial-delivery")
			r.Header.Set("X-GitHub-Event", "pull_request")
			w := httptest.NewRecorder()
			a.routes().ServeHTTP(w, r)
			if w.Code != 202 {
				t.Fatalf("webhook: %d %s", w.Code, w.Body)
			}
			var count int
			if err := a.s.QueryRow("SELECT count(*) FROM initial_pr_checks WHERE checked=0").Scan(&count); err != nil || count != tc.want {
				t.Fatalf("eligible=%d want=%d err=%v", count, tc.want, err)
			}
		})
	}
}
