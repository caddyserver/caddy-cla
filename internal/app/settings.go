package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"caddy-cla/internal/storage"
)

// settings saves administrator-edited exemption rules and schedules affected PR checks.
func (a *App) settings(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.csrf(w, r); !ok {
		return
	}
	if _, ok := a.authorized(w, r); !ok {
		return
	}
	split := func(s string) []string {
		out := []string{}
		for _, v := range strings.Split(s, ",") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	p := storage.Policy{
		Users:      split(r.FormValue("users")),
		PublicOrgs: split(r.FormValue("orgs")),
	}
	for _, org := range p.PublicOrgs {
		if strings.ContainsAny(org, "/ ?#%*") {
			http.Error(w, "Invalid organization", 400)
			return
		}
	}
	cfg, err := a.repository(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	user, _ := a.session(r)
	if err = a.s.SaveRepositoryPolicy(cfg.Name, p, user.ID); err != nil {
		a.fail(w, err)
		return
	}

	http.Redirect(w, r, a.repoURL("/admin", cfg.Name), 303)
}

// history filters signature records by username or numeric GitHub ID.
func (a *App) history(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorized(w, r)
	if !ok {
		return
	}
	cfg, err := a.repository(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	xs, err := a.s.ScopedSignatures(cfg.Name, 0)
	if err != nil {
		a.fail(w, err)
		return
	}
	q := strings.ToLower(r.URL.Query().Get("q"))
	filtered := []storage.Signature{}
	for _, x := range xs {
		if q == "" || strings.Contains(strings.ToLower(x.Login), q) || fmt.Sprint(x.ID) == q {
			filtered = append(filtered, x)
		}
	}
	a.render(w, "history", map[string]any{"Base": a.c.BasePath, "Session": s, "Records": filtered, "Query": q, "Repo": cfg.Name})
}

// initialReconcile discovers open pull requests after startup so missed deliveries are repaired.
func (a *App) initialReconcile(ctx context.Context) {
	if a.c.AppID == "" {
		return
	}
	if err := a.discover(ctx); err != nil {
		slog.Error("initial PR reconciliation failed; periodic retry scheduled", "error", err)
	}
}
