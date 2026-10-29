package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"caddy-cla/internal/storage"
)

// postForm submits an authenticated form through the real router using synthetic test identity only.
func postForm(t *testing.T, a *App, cookie *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	res := httptest.NewRecorder()
	a.routes().ServeHTTP(res, req)
	return res
}

// TestLiveRepositoryEditor retains snapshots and immediately changes contributor signing requirements.
func TestLiveRepositoryEditor(t *testing.T) {
	a := fixture(t)
	cookie := loginFixture(t, a, 7)
	cfg, _ := a.s.Repository("caddyserver/caddy")
	form := url.Values{"csrf": {"csrf-test"}, "repo": {cfg.Name}, "generation": {strconv.FormatInt(cfg.Generation, 10)}, "mode": {"text"}, "title": {"Caddy agreement"}, "body": {"A newly published agreement"}, "confirm_change": {"yes"}}
	res := postForm(t, a, cookie, "/cla/admin/repository", form)
	if res.Code != 303 {
		t.Fatalf("publish: %d %s", res.Code, res.Body)
	}
	current, _ := a.s.Repository(cfg.Name)
	if current.Version == "v1" || current.Body != "A newly published agreement" {
		t.Fatal("live edit was not saved")
	}
	res = postForm(t, a, cookie, "/cla/sign", url.Values{"csrf": {"csrf-test"}, "repo": {cfg.Name}, "version": {"v1"}, "accept": {"yes"}})
	if res.Code != 400 {
		t.Fatal("stale signing form accepted")
	}
	res = postForm(t, a, cookie, "/cla/admin/repository", form)
	if res.Code != 409 {
		t.Fatal("stale admin edit was accepted")
	}
}

// TestGistPublication uses a public GitHub Gist revision and refuses ambiguous or untrusted URLs.
func TestGistPublication(t *testing.T) {
	a := fixture(t)
	cookie := loginFixture(t, a, 7)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gists/abc123" {
			t.Errorf("unexpected Gist request %s", r.URL)
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"public":true,"history":[{"version":"gist-revision-2"}],"files":{"CLA.md":{"content":"Agreement from Gist","truncated":false}}}`)
	}))
	defer server.Close()
	a.gh.api = server.URL
	cfg, _ := a.s.Repository("caddyserver/caddy")
	form := url.Values{"csrf": {"csrf-test"}, "repo": {cfg.Name}, "generation": {strconv.FormatInt(cfg.Generation, 10)}, "mode": {"gist"}, "gist_url": {"https://gist.github.com/owner/abc123"}, "confirm_change": {"yes"}}
	res := postForm(t, a, cookie, "/cla/admin/repository", form)
	if res.Code != 303 {
		t.Fatalf("Gist publish: %d %s", res.Code, res.Body)
	}
	current, _ := a.s.Repository(cfg.Name)
	if current.Version != "gist-revision-2" || current.GistFile != "CLA.md" {
		t.Fatalf("Gist selection: %+v", current)
	}
	current.GistURL = "http://localhost/private"
	if err := a.gh.fetchAgreement(t.Context(), &current); err == nil {
		t.Fatal("untrusted Gist origin accepted")
	}
}

// TestWebImport retains original records, quarantines CSV identities and rolls back malformed uploads.
func TestWebImport(t *testing.T) {
	a := fixture(t)
	cookie := loginFixture(t, a, 7)
	upload := func(filename, data string) *httptest.ResponseRecorder {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		for k, v := range map[string]string{"csrf": "csrf-test", "repo": "caddyserver/caddy", "version": "v1"} {
			if err := writer.WriteField(k, v); err != nil {
				t.Fatal(err)
			}
		}
		file, err := writer.CreateFormFile("signatures", filename)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/cla/admin/import", &body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.AddCookie(cookie)
		res := httptest.NewRecorder()
		a.routes().ServeHTTP(res, req)
		return res
	}
	res := upload("signatures.json", `[{"userId":"42","user":"alice","created_at":"2020-01-01T00:00:00Z"}]`)
	if res.Code != 303 {
		t.Fatalf("JSON upload: %d %s", res.Code, res.Body)
	}
	res = upload("signatures.csv", "User Name;Gist Version;Signed At\nhistorical;v1;2015-01-01T00:00:00Z\n")
	if res.Code != 303 {
		t.Fatalf("CSV upload: %d %s", res.Code, res.Body)
	}
	known, _ := a.s.ScopedSignatures("caddyserver/caddy", 0)
	legacy, _ := a.s.ScopedLegacy("caddyserver/caddy")
	if len(known) != 1 || len(legacy) != 1 {
		t.Fatal("upload did not retain identity scope")
	}
	res = upload("bad.json", `[{"userId":"43","user":"bob","created_at":"2020-01-01T00:00:00Z"},{"userId":"broken"}]`)
	if res.Code != 400 {
		t.Fatal("bad upload accepted")
	}
	known, _ = a.s.ScopedSignatures("caddyserver/caddy", 0)
	if len(known) != 1 {
		t.Fatal("bad upload partially committed")
	}
}

// TestUserHistoryAndRevocation protects other accounts' records and records the owner's explicit action.
func TestUserHistoryAndRevocation(t *testing.T) {
	a := fixture(t)
	cookie := loginFixture(t, a, 42)
	if err := a.s.SignRepository(42, "alice", "caddyserver/caddy", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := a.s.SignRepository(99, "other-private-user", "caddyserver/caddy", "v1"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/cla/history", nil)
	req.AddCookie(cookie)
	res := httptest.NewRecorder()
	a.routes().ServeHTTP(res, req)
	if res.Code != 200 || strings.Contains(res.Body.String(), "other-private-user") {
		t.Fatalf("history privacy: %d %s", res.Code, res.Body)
	}
	xs, _ := a.s.ScopedSignatures("caddyserver/caddy", 42)
	res = postForm(t, a, cookie, "/cla/history/revoke", url.Values{"csrf": {"csrf-test"}, "repo": {"caddyserver/caddy"}, "record_id": {strconv.FormatInt(xs[0].RecordID, 10)}, "confirm": {"yes"}})
	if res.Code != 303 {
		t.Fatalf("revoke: %d %s", res.Code, res.Body)
	}
	if ok, _ := a.s.RepositorySigned(42, "caddyserver/caddy", "v1"); ok {
		t.Fatal("revoked identity still passed")
	}
}

// TestRepositoryExportsDoNotLeak keeps identical agreement versions isolated in the administrator API.
func TestRepositoryExportsDoNotLeak(t *testing.T) {
	a := fixture(t)
	cookie := loginFixture(t, a, 7)
	cfg, _ := a.s.Repository("caddyserver/caddy")
	cfg.Name = "other/project"
	cfg.Generation = 0
	if err := a.s.SaveRepository(cfg, 7); err != nil {
		t.Fatal(err)
	}
	if err := a.s.SignRepository(99, "unrelated-user", cfg.Name, cfg.Version); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/cla/admin/export?repo=caddyserver%2Fcaddy", nil)
	req.AddCookie(cookie)
	res := httptest.NewRecorder()
	a.routes().ServeHTTP(res, req)
	if res.Code != 200 || strings.Contains(res.Body.String(), "unrelated-user") {
		t.Fatal("export leaked another repository")
	}
	var exported struct {
		Signatures []storage.Signature `json:"signatures"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
}

// TestNativeExportImportKeepsLegacyEvidence verifies uploads of the application's own JSON export preserve unresolved records.
func TestNativeExportImportKeepsLegacyEvidence(t *testing.T) {
	a := fixture(t)
	raw := json.RawMessage(`{"user":"historical","created_at":"2015-01-01T00:00:00Z"}`)
	export, err := json.Marshal(map[string]any{"signatures": []any{}, "legacy_signatures": []storage.LegacySignature{{Login: "historical", Version: "v1", Raw: raw}}})
	if err != nil {
		t.Fatal(err)
	}
	if count, err := a.s.ImportJSON(export, "v1", "caddyserver/caddy", ""); err != nil || count != 1 {
		t.Fatalf("native import: %d %v", count, err)
	}
	legacy, _ := a.s.ScopedLegacy("caddyserver/caddy")
	if len(legacy) != 1 || string(legacy[0].Raw) != string(raw) {
		t.Fatal("native import lost legacy evidence")
	}
}

// roundTripFunc provides an in-memory HTTP exchange without contacting GitHub during OAuth tests.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip delegates a synthetic HTTP request to the test exchange.
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestOAuthReturnsToPR verifies the complete login callback retains PR context and consumes state once.
func TestOAuthReturnsToPR(t *testing.T) {
	a := fixture(t)
	a.c.OAuthClientID = "test-client"
	a.c.OAuthSecret = "test-secret"
	exchanges := 0
	a.gh.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := ""
		switch r.URL.String() {
		case "https://github.com/login/oauth/access_token":
			exchanges++
			if err := r.ParseForm(); err != nil {
				return nil, err
			}
			if r.FormValue("code_verifier") == "" {
				t.Error("PKCE verifier missing")
			}
			body = `{"access_token":"test-oauth-token"}`
		case "https://api.github.com/user":
			if r.Header.Get("Authorization") != "Bearer test-oauth-token" {
				t.Error("identity request not authenticated")
			}
			body = `{"id":42,"login":"alice"}`
		default:
			return nil, fmt.Errorf("unexpected OAuth request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	next := "/cla/recheck?repo=caddyserver%2Fcaddy&pr=10"
	req := httptest.NewRequest("GET", "/cla/auth/github?"+url.Values{"next": {next}}.Encode(), nil)
	res := httptest.NewRecorder()
	a.routes().ServeHTTP(res, req)
	redirect, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cookie := res.Result().Cookies()[0]
	callback := "/cla/auth/github/callback?" + url.Values{"state": {redirect.Query().Get("state")}, "code": {"test-code"}}.Encode()
	req = httptest.NewRequest("GET", callback, nil)
	req.AddCookie(cookie)
	res = httptest.NewRecorder()
	a.routes().ServeHTTP(res, req)
	if res.Code != 303 || res.Header().Get("Location") != next {
		t.Fatalf("lost return target: %d %q", res.Code, res.Header().Get("Location"))
	}
	req = httptest.NewRequest("GET", callback, nil)
	req.AddCookie(cookie)
	res = httptest.NewRecorder()
	a.routes().ServeHTTP(res, req)
	if res.Code != 400 || exchanges != 1 {
		t.Fatal("OAuth state was replayable")
	}
}

// TestRepositoryWriterCannotEditOtherRepository checks live GitHub permissions at the selected repository boundary.
func TestRepositoryWriterCannotEditOtherRepository(t *testing.T) {
	a := fixture(t)
	appKey(t, a)
	cookie := loginFixture(t, a, 42)
	cfg, _ := a.s.Repository("caddyserver/caddy")
	cfg.Name = "other/project"
	cfg.Generation = 0
	if err := a.s.SaveRepository(cfg, 7); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			fmt.Fprint(w, `{"id":12}`)
		case r.URL.Path == "/app/installations/12/access_tokens":
			fmt.Fprint(w, `{"token":"test"}`)
		case strings.HasSuffix(r.URL.Path, "/collaborators/maintainer/permission"):
			permission := "read"
			if strings.Contains(r.URL.Path, "caddyserver/caddy") {
				permission = "write"
			}
			fmt.Fprintf(w, `{"permission":%q,"user":{"id":42}}`, permission)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	a.gh.api = server.URL
	req := httptest.NewRequest("GET", "/cla/admin/export?repo=other%2Fproject", nil)
	req.AddCookie(cookie)
	res := httptest.NewRecorder()
	a.routes().ServeHTTP(res, req)
	if res.Code != 403 {
		t.Fatalf("writer accessed unrelated repository: %d", res.Code)
	}
	req = httptest.NewRequest("GET", "/cla/admin?repo=caddyserver%2Fcaddy", nil)
	req.AddCookie(cookie)
	res = httptest.NewRecorder()
	a.routes().ServeHTTP(res, req)
	if res.Code != 200 {
		t.Fatalf("writer could not administer own repository: %d %s", res.Code, res.Body)
	}
}

// TestUnsafeOAuthReturnURLs rejects redirects outside the deployment's route prefix.
func TestUnsafeOAuthReturnURLs(t *testing.T) {
	a := fixture(t)
	for _, next := range []string{"https://evil.test", "//evil.test", "/outside", "/cla/\\evil", "/cla/../outside", "/cla/%2e%2e/outside"} {
		if a.safeReturnURL(next) != "/cla/" {
			t.Errorf("unsafe return accepted: %q", next)
		}
	}
}
