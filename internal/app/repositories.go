package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"caddy-cla/internal/storage"
)

var repositoryName = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// repository selects a configured repository without interpreting arbitrary redirect targets.
func (a *App) repository(r *http.Request) (storage.Repository, error) {
	name := r.FormValue("repo")
	if name == "" {
		names, err := a.s.Repositories()
		if err != nil {
			return storage.Repository{}, err
		}
		if len(names) == 0 {
			return storage.Repository{}, fmt.Errorf("no repositories configured")
		}
		name = names[0]
	}
	return a.s.Repository(name)
}

// repoURL binds links and forms to the same repository throughout authentication and administration.
func (a *App) repoURL(path, repo string) string {
	return a.c.Path(path) + "?" + url.Values{"repo": {repo}}.Encode()
}

// canAdminRepo checks one repository's write permission without requiring unrelated repository access.
func (g *GitHub) canAdminRepo(ctx context.Context, u User, repo string) bool {
	if g.c.Admin(u.ID) {
		return true
	}
	if u.ID <= 0 || !repositoryName.MatchString(repo) {
		return false
	}
	installation, err := g.installation(ctx, repo)
	if err != nil {
		return false
	}
	token, err := g.token(ctx, installation)
	if err != nil {
		return false
	}
	var permission struct {
		Permission string `json:"permission"`
		User       struct {
			ID          int64 `json:"id"`
			Permissions struct {
				Push bool `json:"push"`
			} `json:"permissions"`
		} `json:"user"`
	}
	if err = g.request(ctx, "GET", "/repos/"+repo+"/collaborators/"+url.PathEscape(u.Login)+"/permission", token, nil, &permission); err != nil || permission.User.ID != u.ID {
		return false
	}
	return permission.User.Permissions.Push || permission.Permission == "write" || permission.Permission == "maintain" || permission.Permission == "admin"
}

// managedRepositories returns only repositories the signed-in administrator may configure.
func (a *App) managedRepositories(ctx context.Context, u User) ([]string, error) {
	names, err := a.s.Repositories()
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, name := range names {
		if a.gh.canAdminRepo(ctx, u, name) {
			out = append(out, name)
		}
	}
	return out, nil
}

// configureRepository publishes either an explicit text snapshot or a validated public Gist revision.
func (a *App) configureRepository(w http.ResponseWriter, r *http.Request) {
	user, ok := a.csrf(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("repo"))
	if !repositoryName.MatchString(name) || !a.gh.canAdminRepo(r.Context(), user.User, name) {
		http.Error(w, "Repository write permission required", 403)
		return
	}
	generation, err := strconv.ParseInt(r.FormValue("generation"), 10, 64)
	if err != nil || generation < 0 {
		http.Error(w, "Invalid configuration generation", 400)
		return
	}
	current, loadErr := a.s.Repository(name)
	if loadErr == nil && current.Generation != generation {
		http.Error(w, storage.ErrConflict.Error(), 409)
		return
	}
	cfg := storage.Repository{Name: name, GitHubID: current.GitHubID, Title: strings.TrimSpace(r.FormValue("title")), Generation: generation, Policy: current.Policy}
	if len(cfg.Title) > 200 {
		http.Error(w, "Agreement title must be at most 200 bytes", 400)
		return
	}
	if cfg.Title == "" {
		cfg.Title = "Contributor License Agreement"
	}
	if loadErr != nil {
		cfg.Policy = storage.Policy{Users: a.c.ExemptUsers, PublicOrgs: a.c.ExemptPublicOrgs}
		if generation != 0 {
			http.Error(w, "Repository not found", 404)
			return
		}
		id, err := a.gh.installation(r.Context(), name)
		if err != nil {
			http.Error(w, "Install the GitHub App on this repository first", 400)
			return
		}
		token, err := a.gh.token(r.Context(), id)
		if err != nil {
			a.fail(w, err)
			return
		}
		var repo struct {
			ID int64 `json:"id"`
		}
		if err = a.gh.request(r.Context(), "GET", "/repos/"+name, token, nil, &repo); err != nil {
			a.fail(w, err)
			return
		}
		cfg.GitHubID = strconv.FormatInt(repo.ID, 10)
	}
	if r.FormValue("mode") == "gist" {
		cfg.GistURL = strings.TrimSpace(r.FormValue("gist_url"))
		cfg.GistFile = strings.TrimSpace(r.FormValue("gist_file"))
		if err = a.gh.fetchAgreement(r.Context(), &cfg); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	} else {
		cfg.Body = strings.ReplaceAll(r.FormValue("body"), "\r\n", "\n")
		if strings.TrimSpace(cfg.Body) == "" {
			http.Error(w, "Agreement text is required", 400)
			return
		}
		digest := sha256.Sum256([]byte(cfg.Body))
		cfg.Version = "text-" + hex.EncodeToString(digest[:])
		cfg.Source = ""
	}
	if cfg.Version != current.Version && r.FormValue("confirm_change") != "yes" {
		http.Error(w, "Confirm that contributors must accept the new agreement version", 400)
		return
	}
	if err = a.s.SaveRepository(cfg, user.ID); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	http.Redirect(w, r, a.repoURL("/admin", name), 303)
}

// fetchAgreement reads only public GitHub Gists and never follows user-supplied raw download URLs.
func (g *GitHub) fetchAgreement(ctx context.Context, cfg *storage.Repository) error {
	u, err := url.Parse(cfg.GistURL)
	if err != nil || u.Scheme != "https" || u.Host != "gist.github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("use an https://gist.github.com/owner/id URL")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || len(parts) > 3 {
		return fmt.Errorf("invalid Gist URL")
	}
	valid := regexp.MustCompile(`^[a-fA-F0-9]+$`)
	id := parts[1]
	if !valid.MatchString(id) {
		return fmt.Errorf("invalid Gist ID")
	}
	path := "/gists/" + id
	if len(parts) == 3 {
		if !valid.MatchString(parts[2]) {
			return fmt.Errorf("invalid Gist revision")
		}
		path += "/" + parts[2]
	}
	var gist struct {
		Public  bool `json:"public"`
		History []struct {
			Version string `json:"version"`
		} `json:"history"`
		Files map[string]struct {
			Content   string `json:"content"`
			Truncated bool   `json:"truncated"`
		} `json:"files"`
	}
	if err = g.request(ctx, "GET", path, "", nil, &gist); err != nil {
		return fmt.Errorf("could not read public Gist: %w", err)
	}
	if !gist.Public || len(gist.History) == 0 {
		return fmt.Errorf("a public Gist with revision history is required")
	}
	if cfg.GistFile == "" {
		for name := range gist.Files {
			if name == "metadata" {
				continue
			}
			if cfg.GistFile != "" {
				return fmt.Errorf("Gist contains multiple documents; specify a filename")
			}
			cfg.GistFile = name
		}
	}
	file, ok := gist.Files[cfg.GistFile]
	if !ok || file.Truncated || strings.TrimSpace(file.Content) == "" {
		return fmt.Errorf("selected Gist file is missing, empty or truncated")
	}
	// Keep historical single-document Gist revisions compatible with existing imported signatures.
	cfg.Body = file.Content
	cfg.Version = gist.History[0].Version
	documents := 0
	for name := range gist.Files {
		if name != "metadata" {
			documents++
		}
	}
	if documents > 1 {
		digest := sha256.Sum256([]byte(cfg.GistFile))
		cfg.Version = "gist:" + id + ":" + cfg.Version + ":" + hex.EncodeToString(digest[:8])
	}
	cfg.Source = cfg.GistURL
	return nil
}
