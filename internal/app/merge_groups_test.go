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

// mergeDelivery sends a correctly signed synthetic GitHub merge-group delivery through the router.
func mergeDelivery(t *testing.T, a *App, delivery, action, head string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"action":%q,"repository":{"full_name":"caddyserver/caddy"},"installation":{"id":12},"merge_group":{"base_sha":%q,"head_sha":%q}}`, action, strings.Repeat("a", 40), head)
	mac := hmac.New(sha256.New, []byte(a.c.WebhookSecret))
	mac.Write([]byte(body))
	req := httptest.NewRequest("POST", "/cla/webhooks/github", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", "merge_group")
	req.Header.Set("X-GitHub-Delivery", delivery)
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	res := httptest.NewRecorder()
	a.routes().ServeHTTP(res, req)
	return res
}

// TestMergeGroupWorkflow covers durable delivery, pagination, unsigned authors, signing and revocation.
func TestMergeGroupWorkflow(t *testing.T) {
	a := fixture(t)
	appKey(t, a)
	a.c.WebhookSecret = "merge-secret"
	head := strings.Repeat("b", 40)
	for range 2 {
		if res := mergeDelivery(t, a, "delivery", "checks_requested", head); res.Code != 202 {
			t.Fatalf("delivery: %d %s", res.Code, res.Body)
		}
	}
	var generation int
	if err := a.s.QueryRow("SELECT generation FROM merge_groups").Scan(&generation); err != nil || generation != 1 {
		t.Fatalf("duplicate delivery changed generation: %d %v", generation, err)
	}
	if res := mergeDelivery(t, a, "invalid", "checks_requested", "bad-sha"); res.Code != 400 {
		t.Fatal("invalid SHA accepted")
	}
	if res := mergeDelivery(t, a, "other", "unknown_action", head); res.Code != 204 {
		t.Fatal("unexpected action accepted")
	}
	linked := true
	state := ""
	comparisonPages := 0
	requeueDuringStatus := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations/12/access_tokens":
			fmt.Fprint(w, `{"token":"test-installation"}`)
		case strings.Contains(r.URL.Path, "/compare/"):
			if r.Header.Get("Authorization") != "" {
				t.Error("public comparison requested expanded app access")
			}
			comparisonPages++
			start, end := 0, 100
			if r.URL.Query().Get("page") == "2" {
				start, end = 100, 101
			}
			commits := []map[string]any{}
			for i := start; i < end; i++ {
				var author any = map[string]any{"id": 42, "login": "alice"}
				if !linked {
					author = nil
				}
				commits = append(commits, map[string]any{"sha": fmt.Sprintf("%040x", i+1), "author": author, "commit": map[string]any{"message": "test"}})
			}
			json.NewEncoder(w).Encode(map[string]any{"total_commits": 101, "commits": commits})
		case strings.HasSuffix(r.URL.Path, "/pulls"):
			fmt.Fprint(w, `[]`)
		case r.URL.Path == "/repos/caddyserver/caddy/statuses/"+head:
			var payload map[string]string
			json.NewDecoder(r.Body).Decode(&payload)
			state = payload["state"]
			if payload["context"] != "license/cla" {
				t.Error("wrong required context")
			}
			if state != "pending" && requeueDuringStatus {
				requeueDuringStatus = false
				if _, err := a.s.Exec("UPDATE merge_groups SET pending=1,generation=generation+1,next=0"); err != nil {
					t.Error(err)
				}
			}
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected request: %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	a.gh.api = server.URL
	a.runMergeJob(t.Context())
	if state != "failure" || comparisonPages != 2 {
		t.Fatalf("unsigned group: state=%s pages=%d", state, comparisonPages)
	}
	if err := a.s.SignRepository(42, "alice", "caddyserver/caddy", "v1"); err != nil {
		t.Fatal(err)
	}
	requeueDuringStatus = true
	a.runMergeJob(t.Context())
	var pending int
	a.s.QueryRow("SELECT pending FROM merge_groups").Scan(&pending)
	if state != "success" || pending != 1 {
		t.Fatalf("signing/concurrent requeue: %s pending=%d", state, pending)
	}
	a.runMergeJob(t.Context())
	a.s.QueryRow("SELECT pending FROM merge_groups").Scan(&pending)
	if pending != 0 {
		t.Fatal("successful job still pending")
	}
	records, err := a.s.ScopedSignatures("caddyserver/caddy", 42)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.s.RevokeSignature(records[0].RecordID, 42, "caddyserver/caddy"); err != nil {
		t.Fatal(err)
	}
	a.runMergeJob(t.Context())
	if state != "failure" {
		t.Fatal("revoked author passed merge check")
	}
	if err = a.s.SignRepository(42, "alice", "caddyserver/caddy", "v1"); err != nil {
		t.Fatal(err)
	}
	linked = false
	a.runMergeJob(t.Context())
	if state != "failure" {
		t.Fatal("unlinked author passed merge check")
	}
	// Agreement changes must invalidate previous acceptances in pending merge groups too.
	cfg, err := a.s.Repository("caddyserver/caddy")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Version = "v2"
	cfg.Body = "new agreement"
	if err = a.s.SaveRepository(cfg, 7); err != nil {
		t.Fatal(err)
	}
	linked = true
	a.runMergeJob(t.Context())
	if state != "failure" {
		t.Fatal("old agreement passed")
	}
}

// TestMergeGroupFailureRetainsJob ensures API errors leave a durable pending check for retry.
func TestMergeGroupFailureRetainsJob(t *testing.T) {
	a := fixture(t)
	appKey(t, a)
	a.c.WebhookSecret = "secret"
	head := strings.Repeat("b", 40)
	if res := mergeDelivery(t, a, "retry", "checks_requested", head); res.Code != 202 {
		t.Fatal(res.Code)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "temporarily unavailable", 503) }))
	defer server.Close()
	a.gh.api = server.URL
	a.runMergeJob(t.Context())
	var pending, attempts int
	var message string
	var next int64
	if err := a.s.QueryRow("SELECT pending,attempts,error,next FROM merge_groups").Scan(&pending, &attempts, &message, &next); err != nil {
		t.Fatal(err)
	}
	if pending != 1 || attempts != 1 || message == "" || next == 0 {
		t.Fatalf("retry lost: %d %d %s %d", pending, attempts, message, next)
	}
}

// TestMergeGroupAttribution requires all grouped PR authors and co-authors, never an old status alone.
func TestMergeGroupAttribution(t *testing.T) {
	a := fixture(t)
	appKey(t, a)
	head := strings.Repeat("c", 40)
	base := strings.Repeat("a", 40)
	state := ""
	message := "test"
	total := 2
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			fmt.Fprint(w, `{"token":"test-token"}`)
		case strings.Contains(r.URL.Path, "/compare/"):
			fmt.Fprintf(w, `{"total_commits":%d,"commits":[{"sha":"first","author":{"id":42,"login":"alice"},"commit":{"message":%q}},{"sha":"second","author":{"id":43,"login":"bob"},"commit":{"message":"test"}}]}`, total, message)
		case strings.HasSuffix(r.URL.Path, "/pulls"):
			fmt.Fprint(w, `[{"state":"open","user":{"id":44,"login":"opener"},"head":{"sha":"second"},"base":{"repo":{"full_name":"caddyserver/caddy"}}}]`)
		case strings.Contains(r.URL.Path, "/statuses/"):
			var p map[string]string
			json.NewDecoder(r.Body).Decode(&p)
			state = p["state"]
			fmt.Fprint(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	a.gh.api = server.URL
	check := func(want string) {
		t.Helper()
		if err := a.gh.reconcileMergeGroup(t.Context(), a.s, "caddyserver/caddy", base, head, 12); err != nil {
			t.Fatal(err)
		}
		if state != want {
			t.Fatalf("got %s want %s", state, want)
		}
	}
	sign := func(id int64) {
		t.Helper()
		if err := a.s.SignRepository(id, fmt.Sprint(id), "caddyserver/caddy", "v1"); err != nil {
			t.Fatal(err)
		}
	}
	sign(42)
	check("failure")
	sign(43)
	check("failure") // A PR opener need not be a commit author.
	sign(44)
	check("success")
	message = "test\n\nCo-authored-by: Unknown <unknown@example.test>"
	check("failure")
	total = 3
	if err := a.gh.reconcileMergeGroup(t.Context(), a.s, "caddyserver/caddy", base, head, 12); err == nil {
		t.Fatal("incomplete comparison approved")
	}
	if state != "pending" {
		t.Fatalf("incomplete evidence produced a final status: %s", state)
	}
}
