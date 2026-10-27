package app

import (
	"net/http"
	"net/url"
	"strings"
)

// legacyPage displays historical signatures awaiting explicit identity verification.
func (a *App) legacyPage(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorized(w, r)
	if !ok {
		return
	}
	cfg, err := a.repository(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	xs, err := a.s.ScopedLegacy(cfg.Name)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.render(w, "legacy", map[string]any{"Base": a.c.BasePath, "Session": s, "Records": xs, "Repo": cfg.Name})
}

// linkLegacy binds a historical acceptance to a verified account and records the administrator audit trail.
func (a *App) linkLegacy(w http.ResponseWriter, r *http.Request) {
	s, ok := a.csrf(w, r)
	if !ok {
		return
	}
	if _, ok = a.authorized(w, r); !ok {
		return
	}
	if r.FormValue("verified") != "yes" {
		http.Error(w, "Explicit identity verification required", 400)
		return
	}
	login := strings.TrimSpace(r.FormValue("github_account"))
	if login == "" || strings.ContainsAny(login, "/?#% ") {
		http.Error(w, "Invalid GitHub login", 400)
		return
	}
	var u User
	if err := a.gh.request(r.Context(), "GET", "/users/"+url.PathEscape(login), "", nil, &u); err != nil || u.ID <= 0 {
		http.Error(w, "Could not verify current GitHub account", 502)
		return
	}
	cfg, err := a.repository(r)
	if err != nil {
		http.Error(w, "Repository not found", 404)
		return
	}
	if err = a.s.LinkLegacy(r.FormValue("key"), cfg.Name, u.ID, u.Login, s.ID); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	http.Redirect(w, r, a.repoURL("/admin/legacy", cfg.Name), 303)
}

// revokeLegacy rejects unresolved evidence after explicit administrator confirmation.
func (a *App) revokeLegacy(w http.ResponseWriter, r *http.Request) {
	s, ok := a.csrf(w, r)
	if !ok {
		return
	}
	if _, ok = a.authorized(w, r); !ok {
		return
	}
	if r.FormValue("confirm") != "yes" {
		http.Error(w, "Explicit revocation confirmation required", 400)
		return
	}
	cfg, err := a.repository(r)
	if err != nil {
		http.Error(w, "Repository not found", 404)
		return
	}
	if err = a.s.RevokeLegacy(r.FormValue("key"), cfg.Name, s.ID, r.FormValue("reason")); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	http.Redirect(w, r, a.repoURL("/admin/legacy", cfg.Name), 303)
}
