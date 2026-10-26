package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"caddy-cla/internal/storage"
)

var commitSHA = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

// mergeWebhook durably accepts authenticated merge-queue deliveries without doing network work.
// The caller has already verified the GitHub delivery signature.
func (a *App) mergeWebhook(w http.ResponseWriter, r *http.Request, body []byte, delivery string) {
	var event struct {
		Action     string `json:"action"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		Group struct {
			Head string `json:"head_sha"`
			Base string `json:"base_sha"`
		} `json:"merge_group"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}
	if event.Action != "checks_requested" {
		w.WriteHeader(204)
		return
	}
	repo := event.Repository.FullName
	if _, err := a.s.Repository(repo); err != nil {
		http.Error(w, "Repository not configured", 403)
		return
	}
	if event.Installation.ID <= 0 || !commitSHA.MatchString(event.Group.Head) || !commitSHA.MatchString(event.Group.Base) {
		http.Error(w, "Invalid merge group", 400)
		return
	}
	tx, err := a.s.Begin()
	if err != nil {
		a.fail(w, err)
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec("INSERT OR IGNORE INTO deliveries VALUES(?,?)", delivery, time.Now().Unix())
	if err != nil {
		a.fail(w, err)
		return
	}
	count, err := result.RowsAffected()
	if err != nil {
		a.fail(w, err)
		return
	}
	if count > 0 {
		_, err = tx.Exec(`INSERT INTO merge_groups(repo,head_sha,base_sha,installation,received) VALUES(?,?,?,?,?) ON CONFLICT(repo,head_sha) DO UPDATE SET base_sha=excluded.base_sha,installation=excluded.installation,pending=1,generation=merge_groups.generation+1,next=0,attempts=0,error='',received=excluded.received`, repo, event.Group.Head, event.Group.Base, event.Installation.ID, time.Now().Unix())
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

// runMergeJob retries one durable merge-group check without losing concurrent signature changes.
func (a *App) runMergeJob(ctx context.Context) {
	if !a.c.AutomationEnabled {
		return
	}
	var repo, head, base string
	var installation, generation int64
	var attempts int
	err := a.s.QueryRow("SELECT repo,head_sha,base_sha,installation,generation,attempts FROM merge_groups WHERE pending=1 AND next<=? ORDER BY next,received LIMIT 1", time.Now().Unix()).Scan(&repo, &head, &base, &installation, &generation, &attempts)
	if err == sql.ErrNoRows {
		return
	}
	if err != nil {
		slog.Error("read merge-group job", "error", err)
		return
	}
	jobctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	err = a.gh.reconcileMergeGroup(jobctx, a.s, repo, base, head, installation)
	if err == nil {
		_, err = a.s.Exec("UPDATE merge_groups SET pending=0,error='' WHERE repo=? AND head_sha=? AND generation=?", repo, head, generation)
	} else {
		slog.Error("merge-group check failed", "repo", repo, "head", head, "error", err)
		delay := time.Duration(1<<min(attempts, 10)) * 10 * time.Second
		_, err = a.s.Exec("UPDATE merge_groups SET attempts=attempts+1,next=?,error=? WHERE repo=? AND head_sha=? AND generation=?", time.Now().Add(delay).Unix(), err.Error(), repo, head, generation)
	}
	if err != nil {
		slog.Error("complete merge-group job", "error", err)
	}
}

// reconcileMergeGroup checks the exact immutable base/head comparison requested by GitHub.
// Public comparison reads avoid adding repository Contents access to the GitHub App.
func (g *GitHub) reconcileMergeGroup(ctx context.Context, s *storage.Store, repo, base, head string, installation int64) error {
	cfg, err := s.Repository(repo)
	if err != nil {
		return err
	}
	token, err := g.token(ctx, installation)
	if err != nil {
		return err
	}
	if err = g.mergeStatus(ctx, repo, head, token, "pending", "Checking merge-group contributors"); err != nil {
		return err
	}
	var commits []commit
	total := -1
	for page := 1; ; page++ {
		var comparison struct {
			Total   int      `json:"total_commits"`
			Commits []commit `json:"commits"`
		}
		path := fmt.Sprintf("/repos/%s/compare/%s...%s?per_page=100&page=%d", repo, base, head, page)
		if err = g.request(ctx, "GET", path, "", nil, &comparison); err != nil {
			return err
		}
		if total < 0 {
			total = comparison.Total
		}
		if comparison.Total != total || total <= 0 {
			return fmt.Errorf("invalid merge-group comparison")
		}
		commits = append(commits, comparison.Commits...)
		if len(commits) == total {
			break
		}
		if len(comparison.Commits) == 0 || len(commits) > total {
			return fmt.Errorf("incomplete merge-group comparison")
		}
	}
	// A commit shared by multiple PRs must be checked only once.
	seen := map[string]bool{}
	for _, c := range commits {
		if c.SHA == "" || seen[c.SHA] {
			return fmt.Errorf("invalid or repeated merge-group commit")
		}
		seen[c.SHA] = true
	}
	users := map[int64]User{}
	// Include PR openers when the PR's exact head is part of this comparison.
	// This preserves the ordinary PR policy without pulling in unrelated PRs sharing an older commit.
	for _, c := range commits {
		for page := 1; ; page++ {
			var associated []struct {
				User  User   `json:"user"`
				State string `json:"state"`
				Head  struct {
					SHA string `json:"sha"`
				} `json:"head"`
				Base struct {
					Repo struct {
						FullName string `json:"full_name"`
					} `json:"repo"`
				} `json:"base"`
			}
			path := fmt.Sprintf("/repos/%s/commits/%s/pulls?per_page=100&page=%d", repo, c.SHA, page)
			if err = g.request(ctx, "GET", path, token, nil, &associated); err != nil {
				return err
			}
			for _, pr := range associated {
				if pr.State == "open" && seen[pr.Head.SHA] && pr.Base.Repo.FullName == repo {
					users[pr.User.ID] = pr.User
				}
			}
			if len(associated) < 100 {
				break
			}
		}
	}
	missing, _, unresolved, err := g.contributors(ctx, s, cfg, token, users, commits)
	if err != nil {
		return err
	}
	latest, err := s.Repository(repo)
	if err != nil {
		return err
	}
	if latest.Generation != cfg.Generation {
		return storage.ErrConflict
	}
	state, description := "success", "All merge-group contributors have signed the CLA"
	if unresolved {
		state, description = "failure", "Merge-group author identities could not be verified"
	} else if len(missing) > 0 {
		state, description = "failure", "Merge-group contributors must sign the CLA"
	}
	return g.mergeStatus(ctx, repo, head, token, state, description)
}

// mergeStatus publishes the same required context on the queue's synthetic head commit.
func (g *GitHub) mergeStatus(ctx context.Context, repo, head, token, state, description string) error {
	return g.request(ctx, "POST", "/repos/"+repo+"/statuses/"+head, token, map[string]string{"state": state, "context": "license/cla", "description": description, "target_url": g.c.PublicURL() + "/?" + url.Values{"repo": {repo}}.Encode()}, nil)
}

// mergeJobView exposes pending queue work to the repository's authorized administrators.
type mergeJobView struct {
	Head     string
	Attempts int
	Error    string
}

// pendingMergeGroups lists bounded operational details for one repository's pending checks.
func (a *App) pendingMergeGroups(repo string) ([]mergeJobView, error) {
	rows, err := a.s.Query("SELECT head_sha,attempts,error FROM merge_groups WHERE repo=? AND pending=1 ORDER BY received LIMIT 30", repo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []mergeJobView{}
	for rows.Next() {
		var job mergeJobView
		if err = rows.Scan(&job.Head, &job.Attempts, &job.Error); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}
