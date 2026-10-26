package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"caddy-cla/internal/config"
	"caddy-cla/internal/storage"
)

// GitHub handles bounded API requests and credentials for the installed repository application.
type GitHub struct {
	c      config.Config
	client *http.Client
	api    string
}

// User is the stable identity returned by GitHub authentication or contributor lookup.
type User struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}

// newGitHub creates an API client with bounded request duration.
func newGitHub(c config.Config) *GitHub {
	return &GitHub{c, &http.Client{Timeout: 25 * time.Second}, "https://api.github.com"}
}

// request performs an authenticated GitHub API call and optionally decodes its JSON response.
func (g *GitHub) request(ctx context.Context, method, path, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.api+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "caddy-cla")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("GitHub %s %s: HTTP %d", method, path, res.StatusCode)
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(output)
	}
	return nil
}

// appJWT signs a short-lived application JWT using the configured RSA private key.
func (g *GitHub) appJWT() (string, error) {
	b, err := os.ReadFile(g.c.PrivateKey)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", fmt.Errorf("invalid PEM private key")
	}
	var key *rsa.PrivateKey
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("RSA key required")
		}
	}
	enc := base64.RawURLEncoding.EncodeToString
	claims, _ := json.Marshal(map[string]any{
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(8 * time.Minute).Unix(),
		"iss": g.c.AppID,
	})
	msg := enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc(claims)
	h := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	return msg + "." + enc(sig), err
}

// token exchanges an application JWT for a short-lived installation access token.
func (g *GitHub) token(ctx context.Context, installation int64) (string, error) {
	jwt, err := g.appJWT()
	if err != nil {
		return "", err
	}
	var v struct {
		Token string `json:"token"`
	}
	err = g.request(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", installation), jwt, map[string]any{}, &v)
	return v.Token, err
}

// installation resolves the application installation that can access repo.
func (g *GitHub) installation(ctx context.Context, repo string) (int64, error) {
	jwt, err := g.appJWT()
	if err != nil {
		return 0, err
	}
	var v struct{ ID int64 }
	err = g.request(ctx, "GET", "/repos/"+repo+"/installation", jwt, nil, &v)
	return v.ID, err
}

// wildcard matches case-insensitive username patterns with only * treated specially.
// Brackets remain literal, so *[bot] matches GitHub's bot suffix rather than a character class.
func wildcard(pattern, value string) bool {
	parts := strings.Split(strings.ToLower(pattern), "*")
	value = strings.ToLower(value)
	if len(parts) == 1 {
		return value == parts[0]
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	for i, p := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(value, p)
		}
		at := strings.Index(value, p)
		if at < 0 {
			return false
		}
		value = value[at+len(p):]
	}
	return true
}

// exempt checks username rules and public organization membership without private-org scopes.
func (g *GitHub) exempt(ctx context.Context, u User, token string, policy storage.Policy) bool {
	for _, p := range policy.Users {
		if wildcard(p, u.Login) {
			return true
		}
	}
	for _, org := range policy.PublicOrgs {
		if g.request(ctx, "GET", "/orgs/"+url.PathEscape(org)+"/public_members/"+url.PathEscape(u.Login), token, nil, nil) == nil {
			return true
		}
	}
	return false
}

// pull contains the pull-request state needed to determine which commit receives a status.
type pull struct {
	Locked bool   `json:"locked"`
	State  string `json:"state"`
	User   User   `json:"user"`
	Head   struct {
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"base"`
}

// reconcile evaluates contributors and updates the current head status and app-owned comment.
// Incomplete commit lists and unresolved author identities prevent approval.
func (g *GitHub) reconcile(ctx context.Context, s *storage.Store, repo string, number int, installation int64) error {
	var allowNewComment bool
	if err := s.QueryRow("SELECT EXISTS(SELECT 1 FROM initial_pr_checks WHERE repo=? AND number=? AND checked=0)", repo, number).Scan(&allowNewComment); err != nil {
		return err
	}
	if err := g.reconcilePR(ctx, s, repo, number, installation, allowNewComment); err != nil {
		return err
	}
	_, err := s.Exec("UPDATE initial_pr_checks SET checked=1 WHERE repo=? AND number=?", repo, number)
	return err
}

// reconcilePR publishes a status and updates a reminder; only an initial opened check may create one.
func (g *GitHub) reconcilePR(ctx context.Context, s *storage.Store, repo string, number int, installation int64, allowNewComment bool) error {
	cfg, err := s.Repository(repo)
	if err != nil {
		return err
	}

	token, err := g.token(ctx, installation)
	if err != nil {
		return err
	}
	root := fmt.Sprintf("/repos/%s/pulls/%d", repo, number)
	var pr pull
	if err = g.request(ctx, "GET", root, token, nil, &pr); err != nil {
		return err
	}
	if pr.State != "open" {
		_, err = s.Exec("DELETE FROM prs WHERE repo=? AND number=?", repo, number)
		return err
	}
	var commits []commit
	for page := 1; ; page++ {
		var batch []commit
		if err = g.request(ctx, "GET", fmt.Sprintf("%s/commits?per_page=100&page=%d", root, page), token, nil, &batch); err != nil {
			return err
		}
		commits = append(commits, batch...)
		if len(batch) < 100 || page >= 3 {
			break
		}
	}
	// GitHub caps this endpoint at 250 commits. Never silently approve incomplete results.
	var details struct {
		Commits int `json:"commits"`
	}
	if err = g.request(ctx, "GET", root, token, nil, &details); err != nil {
		return err
	}
	missing, unlinkedCommits, unresolved, err := g.contributors(ctx, s, cfg, token, map[int64]User{pr.User.ID: pr.User}, commits)
	if err != nil {
		return err
	}
	incomplete := details.Commits > 250 || details.Commits > len(commits)
	if incomplete {
		unresolved = true
	}
	sort.Strings(missing)
	latest, err := s.Repository(repo)
	if err != nil {
		return err
	}
	if latest.Generation != cfg.Generation {
		return storage.ErrConflict
	}
	signURL := g.c.PublicURL() + "/?" + url.Values{"repo": {repo}}.Encode()
	recheckURL := g.c.PublicURL() + "/recheck?" + url.Values{"repo": {repo}, "pr": {strconv.Itoa(number)}}.Encode()
	state, description := "success", "All contributors have signed the CLA"
	if len(missing) > 0 || unresolved {
		state = "failure"
		description = "Contributor License Agreement required"
	}
	if err = g.request(ctx, "POST", "/repos/"+repo+"/statuses/"+pr.Head.SHA, token, map[string]string{
		"state":       state,
		"context":     "license/cla",
		"description": description,
		"target_url":  signURL,
	}, nil); err != nil {
		return err
	}
	// GitHub disallows comments on locked conversations; the required status still applies.
	if pr.Locked {
		return nil
	}
	body := "<!-- caddy-cla -->\n**" + cfg.Title + "**\n\n"
	if state == "success" {
		body += "All identified contributors have signed the CLA. Thank you!"
	} else {
		if len(missing) > 0 {
			body += strings.Join(missing, ", ") + ": please [read and sign the CLA](" + signURL + ").\n\n"
		}
		if incomplete {
			body += "The complete commit list could not be verified. GitHub’s PR commits API returns at most 250 commits; split larger PRs before requesting another check.\n\n"
		}
		if unresolved && !incomplete {
			body += "Some commit authors or co-authors could not be verified automatically. A maintainer must resolve author identities before this check can pass.\n\n"
		}
		if len(unlinkedCommits) > 0 {
			body += "**Commit email is not linked to a GitHub account.**\n\n"
			for _, sha := range unlinkedCommits {
				label := sha
				if len(label) > 12 {
					label = label[:12]
				}
				body += "- [Commit `" + label + "`](https://github.com/" + repo + "/commit/" + sha + ") has no linked GitHub author.\n"
			}
			body += "\nIf you authored these commits, [add their author email to your GitHub account](https://github.com/settings/emails), or amend them to use a linked or GitHub noreply address and push the corrected commits. Signing the CLA alone cannot fix unlinked commit attribution.\n\n"
		}
		body += "The check updates automatically after signing or pushing commits."
	}
	body += "\n\n[Recheck this PR](" + recheckURL + ")"
	var commentID int64
	var previous string
	for page := 1; ; page++ {
		var comments []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
			User User   `json:"user"`
			App  *struct {
				ID int64 `json:"id"`
			} `json:"performed_via_github_app"`
		}
		if err = g.request(ctx, "GET", fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100&page=%d", repo, number, page), token, nil, &comments); err != nil {
			return err
		}
		for _, c := range comments {
			if c.App != nil && fmt.Sprint(c.App.ID) == g.c.AppID && strings.HasPrefix(c.Body, "<!-- caddy-cla -->") {
				commentID = c.ID
				previous = c.Body
				break
			}
		}
		if commentID > 0 || len(comments) < 100 {
			break
		}
	}
	// Existing PRs and already verified initial checks cannot create a new reminder.
	if commentID == 0 && (state == "success" || !allowNewComment) {
		return nil
	}
	if previous == body {
		return nil
	}
	path := fmt.Sprintf("/repos/%s/issues/%d/comments", repo, number)
	method := "POST"
	if commentID > 0 {
		path = fmt.Sprintf("/repos/%s/issues/comments/%d", repo, commentID)
		method = "PATCH"
	}
	return g.request(ctx, method, path, token, map[string]string{"body": body}, nil)
}

// commit contains GitHub attribution and the message trailers needed for CLA checks.
type commit struct {
	SHA       string `json:"sha"`
	Author    *User  `json:"author"`
	Committer *User  `json:"committer"`
	Commit    struct {
		Message string `json:"message"`
		Author  struct {
			Email string `json:"email"`
		} `json:"author"`
	} `json:"commit"`
}

// contributors verifies commit attribution, co-authors and repository-scoped signatures.
func (g *GitHub) contributors(ctx context.Context, s *storage.Store, cfg storage.Repository, token string, users map[int64]User, commits []commit) ([]string, []string, bool, error) {
	unresolved := false
	unlinkedCommits := []string{}
	authorEmails := map[string]User{}
	coauthors := []string{}
	for _, c := range commits {
		if c.Author == nil || c.Author.ID == 0 {
			unresolved = true
			if c.SHA != "" {
				unlinkedCommits = append(unlinkedCommits, c.SHA)
			}
		} else {
			users[c.Author.ID] = *c.Author
			authorEmails[strings.ToLower(c.Commit.Author.Email)] = *c.Author
		}
		if (c.Author == nil || c.Author.ID == 0) && c.Committer != nil && c.Committer.ID > 0 {
			users[c.Committer.ID] = *c.Committer
		}
		for _, line := range strings.Split(c.Commit.Message, "\n") {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "co-authored-by:") {
				coauthors = append(coauthors, strings.TrimSpace(strings.SplitN(line, ":", 2)[1]))
			}
		}
	}
	for _, trailer := range coauthors {
		address, err := mail.ParseAddress(trailer)
		if err != nil {
			unresolved = true
			continue
		}
		email := strings.ToLower(address.Address)
		if u, ok := authorEmails[email]; ok && u.ID > 0 {
			users[u.ID] = u
			continue
		}
		parts := strings.Split(email, "@")
		if len(parts) != 2 || parts[1] != "users.noreply.github.com" {
			unresolved = true
			continue
		}
		login := parts[0]
		var expected int64
		if pieces := strings.SplitN(login, "+", 2); len(pieces) == 2 {
			expected, err = strconv.ParseInt(pieces[0], 10, 64)
			if err != nil {
				unresolved = true
				continue
			}
			login = pieces[1]
		}
		var u User
		if err = g.request(ctx, "GET", "/users/"+url.PathEscape(login), token, nil, &u); err != nil || u.ID <= 0 || (expected != 0 && expected != u.ID) {
			unresolved = true
			continue
		}
		users[u.ID] = u
	}
	policy := cfg.Policy
	missing := []string{}
	for id, u := range users {
		if id == 0 {
			unresolved = true
			continue
		}
		if g.exempt(ctx, u, token, policy) {
			continue
		}
		ok, err := s.RepositorySigned(id, cfg.Name, cfg.Version)
		if err != nil {
			return nil, nil, false, err
		}
		if !ok {
			missing = append(missing, "@"+u.Login)
		}
	}

	return missing, unlinkedCommits, unresolved, nil
}
