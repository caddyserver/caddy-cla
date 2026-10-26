package app

import (
	"net/http"
	"strconv"
)

// recheckPage presents an authenticated confirmation rather than changing GitHub state on a GET.
func (a *App) recheckPage(w http.ResponseWriter, r *http.Request) {
	user, ok := a.requireLogin(w, r)
	if !ok {
		return
	}
	repo, err := a.repository(r)
	number, parseErr := strconv.Atoi(r.URL.Query().Get("pr"))
	if err != nil || parseErr != nil || number <= 0 {
		http.Error(w, "Invalid repository or PR", 400)
		return
	}
	a.render(w, "recheck", map[string]any{"Base": a.c.BasePath, "Session": user, "Logged": true, "Repo": repo.Name, "Number": number})
}

// recheckPR allows the PR author, a covered contributor or repository writer to request a fresh check.
func (a *App) recheckPR(w http.ResponseWriter, r *http.Request) {
	user, ok := a.csrf(w, r)
	if !ok {
		return
	}
	if !a.c.AutomationEnabled {
		http.Error(w, "GitHub automation is disabled", http.StatusServiceUnavailable)
		return
	}
	repo, err := a.repository(r)
	number, parseErr := strconv.Atoi(r.FormValue("pr"))
	if err != nil || parseErr != nil || number <= 0 {
		http.Error(w, "Invalid repository or PR", 400)
		return
	}
	installation, err := a.gh.installation(r.Context(), repo.Name)
	if err != nil {
		a.fail(w, err)
		return
	}
	token, err := a.gh.token(r.Context(), installation)
	if err != nil {
		a.fail(w, err)
		return
	}
	var pr pull
	if err = a.gh.request(r.Context(), "GET", "/repos/"+repo.Name+"/pulls/"+strconv.Itoa(number), token, nil, &pr); err != nil {
		http.Error(w, "Pull request not found", 404)
		return
	}
	covered, err := a.s.RepositorySigned(user.ID, repo.Name, repo.Version)
	if err != nil {
		a.fail(w, err)
		return
	}
	if pr.User.ID != user.ID && !covered && !a.gh.canAdminRepo(r.Context(), user.User, repo.Name) {
		http.Error(w, "Only the PR author, a covered contributor or a repository writer can recheck", 403)
		return
	}
	if pr.State != "open" {
		http.Error(w, "Pull request is not open", 409)
		return
	}
	if err = a.s.QueueManualRecheck(repo.Name, number, installation); err != nil {
		http.Error(w, err.Error(), 429)
		return
	}
	a.render(w, "recheck", map[string]any{"Base": a.c.BasePath, "Session": user, "Logged": true, "Repo": repo.Name, "Number": number, "Queued": true})
}
