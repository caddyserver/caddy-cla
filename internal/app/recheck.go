package app

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"caddy-cla/internal/storage"
)

// recheckPage synchronously refreshes one tracked public PR and returns to GitHub.
// It needs no login and never authorizes a new reminder comment.
func (a *App) recheckPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if !a.c.AutomationEnabled {
		http.Error(w, "GitHub automation is disabled", 503)
		return
	}
	repo, err := a.repository(r)
	number, parseErr := strconv.Atoi(r.FormValue("pr"))
	if err != nil || parseErr != nil || number <= 0 {
		http.Error(w, "Invalid repository or PR", 400)
		return
	}
	var installation int64
	if err = a.s.QueryRow("SELECT installation FROM prs WHERE repo=? AND number=?", repo.Name, number).Scan(&installation); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Pull request is not tracked", 404)
		} else {
			a.fail(w, err)
		}
		return
	}
	target := "https://github.com/" + repo.Name + "/pull/" + strconv.Itoa(number)
	if err = a.s.ReserveManualRecheck(repo.Name, number); err != nil {
		if errors.Is(err, storage.ErrRecheckLimited) {
			w.Header().Set("Retry-After", "30")
			http.Redirect(w, r, target, 303)
		} else {
			a.fail(w, err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err = a.gh.reconcilePR(ctx, a.s, repo.Name, number, installation, false); err != nil {
		a.fail(w, err)
		return
	}
	http.Redirect(w, r, target, 303)
}

// recheckPR retains compatibility with previously rendered CSRF-protected forms.
func (a *App) recheckPR(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.csrf(w, r); !ok {
		return
	}
	a.recheckPage(w, r)
}
