package app

import (
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// requireLogin sends a visitor through OAuth and returns them to the same application-relative page.
func (a *App) requireLogin(w http.ResponseWriter, r *http.Request) (session, bool) {
	user, ok := a.session(r)
	if !ok {
		http.Redirect(w, r, a.c.Path("/auth/github")+"?"+url.Values{"next": {r.URL.RequestURI()}}.Encode(), 303)
	}
	return user, ok
}

// userHistory shows only the authenticated account's acceptances, original agreement links and audit events.
func (a *App) userHistory(w http.ResponseWriter, r *http.Request) {
	user, ok := a.requireLogin(w, r)
	if !ok {
		return
	}
	records, err := a.s.ScopedSignatures("", user.ID)
	if err != nil {
		a.fail(w, err)
		return
	}
	events, err := a.s.UserHistory(user.ID)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.render(w, "user-history", map[string]any{"Base": a.c.BasePath, "Session": user, "Logged": true, "Records": records, "Events": events})
}

// revokeOwn invalidates a scoped signature only after its owner explicitly confirms the request.
func (a *App) revokeOwn(w http.ResponseWriter, r *http.Request) {
	user, ok := a.csrf(w, r)
	if !ok {
		return
	}
	if r.FormValue("confirm") != "yes" {
		http.Error(w, "Confirm revocation", 400)
		return
	}
	id, err := strconv.ParseInt(r.FormValue("record_id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid signature", 400)
		return
	}
	if err = a.s.RevokeSignature(id, user.ID, r.FormValue("repo")); err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	http.Redirect(w, r, a.c.Path("/history"), 303)
}

// agreementHistory displays an immutable document version associated with a repository.
func (a *App) agreementHistory(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	version := r.URL.Query().Get("version")
	var body, source string
	err := a.s.QueryRow(`SELECT a.body,a.source FROM agreements a WHERE a.version=? AND (EXISTS(SELECT 1 FROM repositories WHERE name=? AND version=a.version) OR EXISTS(SELECT 1 FROM signatures s JOIN signature_repositories sr ON s.id=sr.signature_id WHERE sr.repo=? AND s.version=a.version))`, version, repo, repo).Scan(&body, &source)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	a.render(w, "agreement-history", map[string]any{"Base": a.c.BasePath, "Repo": repo, "Version": version, "Body": body, "Source": source})
}

// safeReturnURL rejects external origins and routes outside this application's base path.
func (a *App) safeReturnURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\\\r\n") || !strings.HasPrefix(path.Clean(parsed.Path)+"/", a.c.Path("/")) || strings.ContainsAny(parsed.Path, "\\\r\n") {
		return a.c.Path("/")
	}
	return parsed.RequestURI()
}
