// Package config loads and validates deployment settings without requesting GitHub access.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Config describes the deployment, agreement and GitHub application credentials.
type Config struct {
	// AutomationEnabled explicitly permits GitHub webhook processing and queued bot writes.
	// It defaults to false; credentials alone never activate the bot.
	AutomationEnabled bool `json:"automation_enabled"`
	// RepositoryID is the stable GitHub repository ID used to recognize historical names during import.
	RepositoryID string `json:"repository_id"`
	// BaseURL is the canonical public origin, without a route prefix.
	BaseURL string `json:"base_url"`
	// Listen is the local HTTP listen address.
	Listen string `json:"listen"`
	// Database is the path to the SQLite file; its parent directory is created on startup.
	Database string `json:"database"`
	// Repositories lists the explicit owner/repository names whose PRs this deployment manages.
	Repositories []string `json:"repositories"`
	// AdminIDs lists optional GitHub user IDs that bypass repository permission lookup.
	AdminIDs []int64 `json:"admin_ids"`
	// ExemptUsers contains default username exemption patterns; only * is a wildcard.
	ExemptUsers []string `json:"exempt_users"`
	// ExemptPublicOrgs lists default organizations whose publicly listed members are exempt.
	ExemptPublicOrgs []string `json:"exempt_public_orgs"`
	// AgreementFile is the local file containing the exact agreement text.
	AgreementFile string `json:"agreement_file"`
	// AgreementVersion is the immutable version associated with the configured agreement text.
	AgreementVersion string `json:"agreement_version"`
	// AgreementSource is the original public agreement URL retained for provenance.
	AgreementSource string `json:"agreement_source"`
	// OAuthClientID is the contributor login application ID, loaded from the environment.
	OAuthClientID string `json:"-"`
	// OAuthSecret is the contributor login application secret, loaded from the environment.
	OAuthSecret string `json:"-"`
	// AppID is the repository automation application ID, loaded from the environment.
	AppID string `json:"-"`
	// PrivateKey is the path to the repository application RSA key, loaded from the environment.
	PrivateKey string `json:"-"`
	// WebhookSecret is the shared secret used to verify GitHub delivery signatures.
	WebhookSecret string `json:"-"`
	// BasePath is the route prefix, normalized without a trailing slash; empty means root.
	BasePath string `json:"base_path"`
	// Secure reports whether browser cookies require HTTPS.
	Secure bool `json:"-"`
}

// Load reads deployment settings and environment secrets, then validates the public URL and repositories.
func Load(file string) (Config, error) {
	c := Config{
		Listen:           "127.0.0.1:8080",
		Database:         "data/cla.db",
		BaseURL:          "http://localhost:8080",
		ExemptUsers:      []string{"*[bot]"},
		ExemptPublicOrgs: []string{"github"},
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return c, fmt.Errorf("invalid base_url")
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return c, fmt.Errorf("HTTP only allowed on localhost")
	}
	if u.Path != "" && u.Path != "/" {
		return c, fmt.Errorf("base_url must be an origin; configure the route prefix with base_path")
	}
	if u.User != nil {
		return c, fmt.Errorf("base_url must not contain credentials")
	}
	prefix := strings.TrimRight(c.BasePath, "/")
	if prefix != "" {
		if !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "?#%\\ \t\n\r") || strings.Contains(prefix, "//") {
			return c, fmt.Errorf("invalid base_path")
		}
		for _, segment := range strings.Split(prefix, "/") {
			if segment == "." || segment == ".." {
				return c, fmt.Errorf("invalid base_path")
			}
		}
	}
	c.BasePath = prefix
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	c.Secure = u.Scheme == "https"
	c.OAuthClientID = os.Getenv("GITHUB_OAUTH_CLIENT_ID")
	c.OAuthSecret = os.Getenv("GITHUB_OAUTH_CLIENT_SECRET")
	c.AppID = os.Getenv("GITHUB_APP_ID")
	c.PrivateKey = os.Getenv("GITHUB_APP_PRIVATE_KEY_FILE")
	c.WebhookSecret = os.Getenv("GITHUB_WEBHOOK_SECRET")
	if c.AgreementFile == "" || c.AgreementVersion == "" || len(c.Repositories) == 0 {
		return c, fmt.Errorf("agreement_file, agreement_version and repositories required")
	}
	for _, r := range c.Repositories {
		p := strings.Split(r, "/")
		if len(p) != 2 || p[0] == "" || p[1] == "" || strings.ContainsAny(r, "?#% ") {
			return c, fmt.Errorf("invalid repository %q", r)
		}
	}
	return c, nil
}

// Allows reports whether repo is one of the deployment's configured repositories.
func (c Config) Allows(repo string) bool {
	for _, r := range c.Repositories {
		if strings.EqualFold(repo, r) {
			return true
		}
	}
	return false
}

// Admin reports whether id has an explicit operator override; repository rights are checked separately.
func (c Config) Admin(id int64) bool {
	for _, x := range c.AdminIDs {
		if x == id {
			return true
		}
	}
	return false
}

// Path prefixes an application-relative route with the configured public subpath.
func (c Config) Path(p string) string { return c.BasePath + p }

// PublicURL returns the canonical external URL including the configured route prefix.
func (c Config) PublicURL() string { return strings.TrimRight(c.BaseURL, "/") + c.BasePath }
