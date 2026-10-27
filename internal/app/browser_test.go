package app

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"caddy-cla/internal/storage"
)

// TestBrowserHarness serves the real handlers over loopback with isolated data and mocked GitHub.
// It runs only when explicitly enabled; fixture login routes are never compiled into the application.
func TestBrowserHarness(t *testing.T) {
	if os.Getenv("CLA_BROWSER_TEST") != "1" {
		t.Skip("set CLA_BROWSER_TEST=1 for an interactive browser fixture on 127.0.0.1:8098")
	}
	a := fixture(t)
	a.c.BaseURL = "http://127.0.0.1:8098"
	if os.Getenv("CLA_BROWSER_BASE_PATH") == "root" {
		a.c.BasePath = ""
	}
	a.gh.c.BaseURL = a.c.BaseURL
	appKey(t, a)
	cfg, err := a.s.Repository("caddyserver/caddy")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Version = "browser-test-v1"
	cfg.Body = "# Browser test agreement\n\nSynthetic test data only. This is not a legal agreement."
	cfg.Title = "Browser test agreement"
	if err = a.s.SaveRepository(cfg, 7); err != nil {
		t.Fatal(err)
	}
	other := storage.Repository{Name: "caddyserver/other", Title: "Other test agreement", Version: cfg.Version, Body: cfg.Body, Policy: cfg.Policy}
	if err = a.s.SaveRepository(other, 7); err != nil {
		t.Fatal(err)
	}
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations/12/access_tokens":
			fmt.Fprint(w, `{"token":"fixture-token"}`)
		case strings.HasSuffix(r.URL.Path, "/installation"):
			fmt.Fprint(w, `{"id":12}`)
		case strings.Contains(r.URL.Path, "/collaborators/"):
			fmt.Fprint(w, `{"permission":"read","user":{"id":44}}`)
		case r.URL.Path == "/gists/abc123":
			fmt.Fprint(w, `{"public":true,"history":[{"version":"browser-gist-v2"}],"files":{"CLA.md":{"content":"# Refreshed browser agreement\n\nSynthetic test data only. This is not a legal agreement.","truncated":false}}}`)
		case strings.HasSuffix(r.URL.Path, "/pulls/10"):
			fmt.Fprint(w, `{"state":"open","commits":1,"user":{"id":7,"login":"maintainer"},"head":{"sha":"test-head"}}`)
		case strings.HasSuffix(r.URL.Path, "/commits"):
			fmt.Fprint(w, `[{"author":{"id":7,"login":"maintainer"},"commit":{"message":"test"}}]`)
		case strings.HasSuffix(r.URL.Path, "/pulls"):
			fmt.Fprint(w, `[{"number":10}]`)
		case strings.HasSuffix(r.URL.Path, "/comments") && r.Method == "GET":
			fmt.Fprint(w, `[]`)
		case r.Method == "POST" || r.Method == "PATCH":
			fmt.Fprint(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer github.Close()
	a.gh.api = github.URL
	if _, err = a.s.ImportJSON([]byte(`[{"user":"historical-example","created_at":"2016-01-01T00:00:00Z"}]`), cfg.Version, cfg.Name, ""); err != nil {
		t.Fatal(err)
	}
	routes := a.routes()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__test/login" {
			id := int64(7)
			if r.URL.Query().Get("id") == "44" {
				id = 44
			}
			token := "browser-fixture-" + strconv.FormatInt(id, 10)
			_, err := a.s.Exec("INSERT OR REPLACE INTO sessions VALUES(?,?,?,?,?)", hash(token), id, "browser-fixture-"+strconv.FormatInt(id, 10), "fixture-csrf", time.Now().Add(time.Hour).Unix())
			if err != nil {
				t.Error(err)
				http.Error(w, "fixture error", 500)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "cla_session", Value: token, Path: a.c.Path("/"), HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, a.c.Path("/"), 303)
			return
		}
		routes.ServeHTTP(w, r)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8098")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	go server.Serve(listener)
	t.Logf("Isolated browser fixture: %s%s; synthetic login: /__test/login; reader: /__test/login?id=44", a.c.BaseURL, a.c.Path("/"))
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopped)
	<-stopped
}
