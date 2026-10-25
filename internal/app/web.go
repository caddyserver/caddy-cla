package app

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"caddy-cla/internal/config"
	"caddy-cla/internal/storage"

	"github.com/yuin/goldmark"
)

// App coordinates the HTTP interface, agreement storage and GitHub automation.
type App struct {
	c  config.Config
	s  *storage.Store
	gh *GitHub
}

// session contains the authenticated identity and the token required for form submissions.
type session struct {
	User
	CSRF string
}

// random generates an opaque token from 32 cryptographically random bytes.
func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hash produces the database lookup digest for a browser token without storing the token itself.
func hash(s string) string {
	digest := sha256.Sum256([]byte(s))
	return hex.EncodeToString(digest[:])
}

// newApp connects the HTTP service to live repository storage and GitHub.
func newApp(c config.Config, s *storage.Store) *App { return &App{c: c, s: s, gh: newGitHub(c)} }

// routes mounts handlers beneath the public subpath and applies response security headers.
func (a *App) routes() http.Handler {
	m := http.NewServeMux()
	p := a.c.Path
	m.HandleFunc("GET "+p("/"), a.home)
	if a.c.BasePath != "" {
		m.HandleFunc("GET "+a.c.BasePath, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, p("/"), http.StatusSeeOther) })
	}
	m.HandleFunc("GET "+p("/auth/github"), a.login)
	m.HandleFunc("GET "+p("/auth/github/callback"), a.callback)
	m.HandleFunc("POST "+p("/sign"), a.sign)
	m.HandleFunc("POST "+p("/logout"), a.logout)
	m.HandleFunc("GET "+p("/admin"), a.admin)
	m.HandleFunc("POST "+p("/admin/repository"), a.configureRepository)
	m.HandleFunc("POST "+p("/admin/import"), a.webImport)
	m.HandleFunc("GET "+p("/history"), a.userHistory)
	m.HandleFunc("POST "+p("/history/revoke"), a.revokeOwn)
	m.HandleFunc("GET "+p("/recheck"), a.recheckPage)
	m.HandleFunc("POST "+p("/recheck"), a.recheckPR)
	m.HandleFunc("GET "+p("/admin/history"), a.history)
	m.HandleFunc("GET "+p("/admin/legacy"), a.legacyPage)
	m.HandleFunc("POST "+p("/admin/legacy/link"), a.linkLegacy)
	m.HandleFunc("POST "+p("/admin/settings"), a.settings)
	m.HandleFunc("GET "+p("/admin/export"), a.export)
	m.HandleFunc("POST "+p("/admin/recheck"), a.recheck)
	m.HandleFunc("POST "+p("/webhooks/github"), a.webhook)
	m.HandleFunc("GET "+p("/agreement"), a.agreementHistory)
	m.HandleFunc("GET "+p("/healthz"), func(w http.ResponseWriter, r *http.Request) {
		if err := a.s.PingContext(r.Context()); err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		io.WriteString(w, "ok\n")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' https://avatars.githubusercontent.com; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		m.ServeHTTP(w, r)
	})
}

// cookie writes a browser cookie restricted to the application path and configured transport.
func (a *App) cookie(w http.ResponseWriter, name, value string, seconds int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     a.c.Path("/"),
		Secure:   a.c.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   seconds,
	})
}

// session resolves an unexpired browser session from its hashed database token.
func (a *App) session(r *http.Request) (session, bool) {
	var s session
	c, err := r.Cookie("cla_session")
	if err != nil {
		return s, false
	}
	err = a.s.QueryRowContext(r.Context(), "SELECT github_id,login,csrf FROM sessions WHERE token=? AND expires>?", hash(c.Value), time.Now().Unix()).Scan(&s.ID, &s.Login, &s.CSRF)
	return s, err == nil
}

// csrf authenticates a session and validates its form token and optional Origin header.
func (a *App) csrf(w http.ResponseWriter, r *http.Request) (session, bool) {
	s, ok := a.session(r)
	if !ok {
		http.Error(w, "Sign in first", 401)
		return s, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", 400)
		return s, false
	}
	origin := r.Header.Get("Origin")
	u, _ := url.Parse(a.c.BaseURL)
	if origin != "" && origin != u.Scheme+"://"+u.Host {
		http.Error(w, "Invalid origin", 403)
		return s, false
	}
	if !hmac.Equal([]byte(s.CSRF), []byte(r.FormValue("csrf"))) {
		http.Error(w, "Invalid CSRF token", 403)
		return s, false
	}
	return s, true
}

// login starts scope-free GitHub OAuth using browser-bound state and an S256 PKCE challenge.
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if a.c.OAuthClientID == "" || a.c.OAuthSecret == "" {
		http.Error(w, "GitHub login is not configured yet", 503)
		return
	}
	state, verifier := random(), random()
	next := a.safeReturnURL(r.URL.Query().Get("next"))
	tx, err := a.s.Begin()
	if err != nil {
		a.fail(w, err)
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec("INSERT INTO oauth_states VALUES(?,?,?)", hash(state), verifier, time.Now().Add(10*time.Minute).Unix())
	if err == nil {
		_, err = tx.Exec("INSERT INTO oauth_return_paths VALUES(?,?)", hash(state), next)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	a.cookie(w, "cla_oauth", state, 600)
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id":             {a.c.OAuthClientID},
		"redirect_uri":          {a.c.PublicURL() + "/auth/github/callback"},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+q.Encode(), 302)
}

// callback consumes OAuth state, verifies GitHub identity and creates a local session.
// The GitHub access token is used only during this request and is not persisted.
func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("cla_oauth")
	if err != nil || state == "" || !hmac.Equal([]byte(cookie.Value), []byte(state)) {
		http.Error(w, "Invalid OAuth state", 400)
		return
	}
	var verifier string
	err = a.s.QueryRow("DELETE FROM oauth_states WHERE token=? AND expires>? RETURNING verifier", hash(state), time.Now().Unix()).Scan(&verifier)
	a.cookie(w, "cla_oauth", "", -1)
	if err != nil || r.URL.Query().Get("code") == "" {
		http.Error(w, "OAuth login expired or denied", 400)
		return
	}
	values := url.Values{
		"client_id":     {a.c.OAuthClientID},
		"client_secret": {a.c.OAuthSecret},
		"code":          {r.URL.Query().Get("code")},
		"redirect_uri":  {a.c.PublicURL() + "/auth/github/callback"},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(r.Context(), "POST", "https://github.com/login/oauth/access_token", strings.NewReader(values.Encode()))
	if err != nil {
		a.fail(w, err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := a.gh.client.Do(req)
	if err != nil {
		a.fail(w, err)
		return
	}
	defer res.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&token) != nil || token.AccessToken == "" {
		http.Error(w, "GitHub login failed", 502)
		return
	}
	var u User
	if err = a.gh.request(r.Context(), "GET", "/user", token.AccessToken, nil, &u); err != nil || u.ID <= 0 {
		a.fail(w, fmt.Errorf("could not verify GitHub identity"))
		return
	}
	id, csrf := random(), random()
	_, err = a.s.Exec("INSERT INTO sessions VALUES(?,?,?,?,?)", hash(id), u.ID, u.Login, csrf, time.Now().Add(12*time.Hour).Unix())
	if err != nil {
		a.fail(w, err)
		return
	}
	a.cookie(w, "cla_session", id, 43200)
	next := a.c.Path("/")
	_ = a.s.QueryRow("DELETE FROM oauth_return_paths WHERE token=? RETURNING return_path", hash(state)).Scan(&next)
	http.Redirect(w, r, a.safeReturnURL(next), 303)
}

// home displays the agreement and the current user's acceptance state.
func (a *App) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != a.c.Path("/") {
		http.NotFound(w, r)
		return
	}
	cfg, err := a.repository(r)
	if err != nil {
		http.Error(w, "Repository not found", 404)
		return
	}
	user, logged := a.session(r)
	signed := false
	if logged {
		signed, err = a.s.RepositorySigned(user.ID, cfg.Name, cfg.Version)
		if err != nil {
			a.fail(w, err)
			return
		}
	}
	var rendered bytes.Buffer
	if err = goldmark.Convert([]byte(cfg.Body), &rendered); err != nil {
		a.fail(w, err)
		return
	}
	a.render(w, "home", map[string]any{"Base": a.c.BasePath, "Body": template.HTML(rendered.String()), "Version": cfg.Version, "Source": cfg.Source, "Title": cfg.Title, "Repo": cfg.Name, "Session": user, "Logged": logged, "Signed": signed, "Admin": logged, "LoginURL": a.c.Path("/auth/github") + "?" + url.Values{"next": {a.repoURL("/", cfg.Name)}}.Encode()})
}

// sign records explicit acceptance only within the repository and version shown to the signer.
func (a *App) sign(w http.ResponseWriter, r *http.Request) {
	user, ok := a.csrf(w, r)
	if !ok {
		return
	}
	cfg, err := a.repository(r)
	if err != nil {
		http.Error(w, "Repository not found", 404)
		return
	}
	if r.FormValue("version") != cfg.Version || r.FormValue("accept") != "yes" {
		http.Error(w, "Review and accept the current agreement", 400)
		return
	}
	signed, err := a.s.RepositorySigned(user.ID, cfg.Name, cfg.Version)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !signed {
		if err = a.s.SignRepository(user.ID, user.Login, cfg.Name, cfg.Version); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
	}
	http.Redirect(w, r, a.repoURL("/", cfg.Name), 303)
}

// logout invalidates the stored session and removes its browser cookie.
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.csrf(w, r); !ok {
		return
	}
	c, _ := r.Cookie("cla_session")
	_, err := a.s.Exec("DELETE FROM sessions WHERE token=?", hash(c.Value))
	if err != nil {
		a.fail(w, err)
		return
	}
	a.cookie(w, "cla_session", "", -1)
	http.Redirect(w, r, a.c.Path("/"), 303)
}

// authorized grants shared administration only to configured operators or repository writers.
func (a *App) authorized(w http.ResponseWriter, r *http.Request) (session, bool) {
	user, ok := a.requireLogin(w, r)
	if !ok {
		return user, false
	}
	cfg, err := a.repository(r)
	if r.FormValue("repo") == "" {
		names, listErr := a.managedRepositories(r.Context(), user.User)
		if listErr == nil && len(names) > 0 {
			r.Form.Set("repo", names[0])
			cfg, err = a.s.Repository(names[0])
		}
	}
	if err != nil || !a.gh.canAdminRepo(r.Context(), user.User, cfg.Name) {
		http.Error(w, "Repository write permission required", 403)
		return user, false
	}
	return user, true
}

// admin displays configuration, signature totals and pending GitHub updates.
func (a *App) admin(w http.ResponseWriter, r *http.Request) {
	s, ok := a.authorized(w, r)
	if !ok {
		return
	}
	cfg, err := a.repository(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	names, err := a.managedRepositories(r.Context(), s.User)
	if err != nil {
		a.fail(w, err)
		return
	}
	var count, pending int
	if err := a.s.QueryRow("SELECT count(*) FROM signature_repositories WHERE repo=?", cfg.Name).Scan(&count); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.s.QueryRow("SELECT (SELECT count(*) FROM jobs WHERE repo=?)+(SELECT count(*) FROM merge_groups WHERE repo=? AND pending=1)", cfg.Name, cfg.Name).Scan(&pending); err != nil {
		a.fail(w, err)
		return
	}
	rows, err := a.s.Query("SELECT repo,number,attempts,error FROM jobs WHERE repo=? ORDER BY id LIMIT 30", cfg.Name)
	if err != nil {
		a.fail(w, err)
		return
	}
	type jobView struct {
		Repo             string
		Number, Attempts int
		Error            string
	}
	jobs := []jobView{}
	for rows.Next() {
		var j jobView
		if err = rows.Scan(&j.Repo, &j.Number, &j.Attempts, &j.Error); err != nil {
			rows.Close()
			a.fail(w, err)
			return
		}
		jobs = append(jobs, j)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		a.fail(w, err)
		return
	}
	mergeJobs, err := a.pendingMergeGroups(cfg.Name)
	if err != nil {
		a.fail(w, err)
		return
	}
	policy := cfg.Policy
	importCount, importErr := strconv.Atoi(r.URL.Query().Get("imported"))
	a.render(w, "admin", map[string]any{
		"ImportDone": importErr == nil && importCount >= 0, "ImportCount": importCount,
		"PolicyUsers": strings.Join(policy.Users, ", "),
		"PolicyOrgs":  strings.Join(policy.PublicOrgs, ", "),
		"Base":        a.c.BasePath,
		"Session":     s,
		"Count":       count,
		"Pending":     pending,
		"Jobs":        jobs,
		"MergeJobs":   mergeJobs,
		"Config":      a.c, "Repo": cfg.Name, "Repository": cfg, "Repositories": names,
	})
}

// export downloads JSON evidence or a spreadsheet-safe CSV of signature history.
func (a *App) export(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.authorized(w, r); !ok {
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
	w.Header().Set("Content-Disposition", `attachment; filename="cla-signatures.json"`)
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Disposition", `attachment; filename="cla-signatures.csv"`)
		w.Header().Set("Content-Type", "text/csv")
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{
			"GitHub ID",
			"Username",
			"Agreement version",
			"Signed at",
			"Revoked at",
			"Ends at",
			"Origin",
		})
		safe := func(s string) string {
			if strings.HasPrefix(s, "=") || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "@") || strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\r") {
				return "'" + s
			}
			return s
		}
		for _, x := range xs {
			_ = cw.Write([]string{
				strconv.FormatInt(x.ID, 10),
				safe(x.Login),
				safe(x.Version),
				x.SignedAt,
				x.RevokedAt,
				x.EndAt,
				safe(x.Origin),
			})
		}
		cw.Flush()
		return
	}
	legacy, err := a.s.ScopedLegacy(cfg.Name)
	if err != nil {
		a.fail(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"signatures": xs, "legacy_signatures": legacy})
}

// recheck discovers and queues open pull requests after validating administrator access.
func (a *App) recheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.csrf(w, r); !ok {
		return
	}
	if _, ok := a.authorized(w, r); !ok {
		return
	}
	cfg, err := a.repository(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := a.discoverRepository(r.Context(), cfg.Name); err != nil {
		a.fail(w, err)
		return
	}
	http.Redirect(w, r, a.repoURL("/admin", cfg.Name), 303)
}

// fail logs an internal error without exposing its details in the HTTP response.
func (a *App) fail(w http.ResponseWriter, err error) {
	slog.Error("request failed", "error", err)
	http.Error(w, "The request failed. Please retry; details are in the server log.", 500)
}

// render buffers a named page before committing the HTML response.
func (a *App) render(w http.ResponseWriter, name string, data any) {
	if m, ok := data.(map[string]any); ok {
		if _, present := m["Logged"]; !present {
			if s, ok := m["Session"].(session); ok && s.ID > 0 {
				m["Logged"] = true
				m["Admin"] = true
			}
		}
	}

	var b bytes.Buffer
	if err := pages.ExecuteTemplate(&b, name, data); err != nil {
		a.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b.Bytes())
}

//go:embed templates/*.html
var pageFiles embed.FS

var pages = template.Must(template.New("pages").ParseFS(pageFiles, "templates/*.html"))
