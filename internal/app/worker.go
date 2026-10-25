package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// enqueue tracks a pull request and refreshes its durable reconciliation job atomically.
func (a *App) enqueue(repo string, number int, installation int64) error {
	tx, err := a.s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("INSERT INTO prs VALUES(?,?,?) ON CONFLICT(repo,number) DO UPDATE SET installation=excluded.installation", repo, number, installation); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO jobs(repo,number,installation) VALUES(?,?,?) ON CONFLICT(repo,number) DO UPDATE SET installation=excluded.installation,next=0,attempts=0,error='',generation=jobs.generation+1", repo, number, installation); err != nil {
		return err
	}
	return tx.Commit()
}

// webhook verifies the delivery HMAC and durably deduplicates supported GitHub events.
func (a *App) webhook(w http.ResponseWriter, r *http.Request) {
	if a.c.WebhookSecret == "" {
		http.Error(w, "Webhook not configured", 503)
		return
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid payload", 400)
		return
	}
	mac := hmac.New(sha256.New, []byte(a.c.WebhookSecret))
	mac.Write(b)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-Hub-Signature-256"))) {
		http.Error(w, "Invalid signature", 401)
		return
	}
	delivery := r.Header.Get("X-GitHub-Delivery")
	if delivery == "" {
		http.Error(w, "Missing delivery ID", 400)
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	if event == "ping" {
		w.WriteHeader(200)
		return
	}
	if event != "pull_request" && event != "issue_comment" && event != "merge_group" {
		w.WriteHeader(204)
		return
	}
	if event == "merge_group" {
		a.mergeWebhook(w, r, b, delivery)
		return
	}
	var p struct {
		Action     string `json:"action"`
		Number     int    `json:"number"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
		Issue struct {
			Number      int              `json:"number"`
			PullRequest *json.RawMessage `json:"pull_request"`
			User        User             `json:"user"`
		} `json:"issue"`
		Comment struct {
			Body string `json:"body"`
			User User   `json:"user"`
		} `json:"comment"`
	}
	if json.Unmarshal(b, &p) != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}
	repo := p.Repository.FullName
	if _, err := a.s.Repository(repo); err != nil {
		http.Error(w, "Repository not configured", 403)
		return
	}
	if p.Installation.ID <= 0 {
		http.Error(w, "Missing installation", 400)
		return
	}
	number := p.Number
	if event == "pull_request" {
		switch p.Action {
		case "opened", "reopened", "synchronize", "closed", "ready_for_review", "edited":
		default:
			w.WriteHeader(204)
			return
		}
	} else {
		if p.Action != "created" || p.Issue.PullRequest == nil {
			w.WriteHeader(204)
			return
		}
		command := strings.TrimSpace(p.Comment.Body)
		if command != "recheck" && command != "@cla-bot check" {
			w.WriteHeader(204)
			return
		}
		number = p.Issue.Number
		u := p.Comment.User
		if u.ID != p.Issue.User.ID && !a.gh.canAdminRepo(r.Context(), u, repo) {
			http.Error(w, "Only PR author or repository writers can recheck", 403)
			return
		}
	}
	if number <= 0 {
		http.Error(w, "Invalid PR number", 400)
		return
	}
	tx, err := a.s.Begin()
	if err != nil {
		a.fail(w, err)
		return
	}
	defer tx.Rollback()
	res, err := tx.Exec("INSERT OR IGNORE INTO deliveries VALUES(?,?)", delivery, time.Now().Unix())
	if err != nil {
		a.fail(w, err)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		w.WriteHeader(202)
		return
	}
	_, err = tx.Exec("INSERT INTO prs VALUES(?,?,?) ON CONFLICT(repo,number) DO UPDATE SET installation=excluded.installation", repo, number, p.Installation.ID)
	if err == nil {
		_, err = tx.Exec("INSERT INTO jobs(repo,number,installation) VALUES(?,?,?) ON CONFLICT(repo,number) DO UPDATE SET installation=excluded.installation,next=0,attempts=0,error='',generation=jobs.generation+1", repo, number, p.Installation.ID)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(202)
}

// discover enumerates configured repositories' open pull requests and queues each for evaluation.
func (a *App) discover(ctx context.Context) error {
	names, err := a.s.Repositories()
	if err != nil {
		return err
	}
	for _, repo := range names {
		if err = a.discoverRepository(ctx, repo); err != nil {
			return err
		}
	}
	return nil
}

// discoverRepository refreshes one repository without touching another administrator's repositories.
func (a *App) discoverRepository(ctx context.Context, repo string) error {

	id, err := a.gh.installation(ctx, repo)
	if err != nil {
		return err
	}
	token, err := a.gh.token(ctx, id)
	if err != nil {
		return err
	}
	for page := 1; ; page++ {
		var prs []struct {
			Number int `json:"number"`
		}
		if err = a.gh.request(ctx, "GET", fmt.Sprintf("/repos/%s/pulls?state=open&per_page=100&page=%d", repo, page), token, nil, &prs); err != nil {
			return err
		}
		for _, p := range prs {
			if err = a.enqueue(repo, p.Number, id); err != nil {
				return err
			}
		}
		if len(prs) < 100 {
			break
		}
	}
	return nil
}

// work processes durable GitHub updates until the service context is canceled.
func (a *App) work(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runJob(ctx)
			a.runMergeJob(ctx)
		}
	}
}

// runJob executes one due job, retrying failures with capped exponential backoff.
// Generation checks prevent completion from removing work queued while this job was running.
func (a *App) runJob(ctx context.Context) {
	var id, installation int64
	var repo string
	var number, attempts int
	var next, generation int64
	err := a.s.QueryRow("SELECT id,repo,number,installation,attempts,next,generation FROM jobs WHERE next<=? ORDER BY next,id LIMIT 1", time.Now().Unix()).Scan(&id, &repo, &number, &installation, &attempts, &next, &generation)
	if err == sql.ErrNoRows {
		return
	}
	if err != nil {
		slog.Error("read job", "error", err)
		return
	}
	jobctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	err = a.gh.reconcile(jobctx, a.s, repo, number, installation)
	if err == nil {
		_, err = a.s.Exec("DELETE FROM jobs WHERE id=? AND attempts=? AND next=? AND generation=?", id, attempts, next, generation)
	} else {
		slog.Error("GitHub update failed", "repo", repo, "pr", number, "error", err)
		delay := time.Duration(1<<min(attempts, 10)) * 10 * time.Second
		_, err = a.s.Exec("UPDATE jobs SET attempts=attempts+1,next=?,error=? WHERE id=? AND attempts=? AND next=? AND generation=?", time.Now().Add(delay).Unix(), err.Error(), id, attempts, next, generation)
	}
	if err != nil {
		slog.Error("complete job", "error", err)
	}
}

// maintenance periodically repairs missed PR updates and expires authentication state.
func (a *App) maintenance(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.c.AppID != "" {
				if err := a.discover(ctx); err != nil {
					slog.Error("reconcile open PRs", "error", err)
				}
			}
			_, _ = a.s.Exec("DELETE FROM oauth_return_paths WHERE token NOT IN (SELECT token FROM oauth_states)")
			now := time.Now().Unix()
			_, _ = a.s.Exec("DELETE FROM merge_groups WHERE received<?", now-7*24*60*60)
			for _, table := range []string{"sessions", "oauth_states"} {
				if _, err := a.s.Exec("DELETE FROM "+table+" WHERE expires<?", now); err != nil {
					slog.Error("expire auth data", "error", err)
				}
			}
		}
	}
}
