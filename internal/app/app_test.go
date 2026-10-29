package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"caddy-cla/internal/config"
	"caddy-cla/internal/storage"
)

// fixture creates an isolated application with a temporary SQLite database and test agreement.
func fixture(t *testing.T) *App {
	t.Helper()
	c := config.Config{
		AutomationEnabled: true,
		BaseURL:           "http://localhost:8080",
		BasePath:          "/cla",
		Repositories:      []string{"caddyserver/caddy"},
		AgreementVersion:  "v1",
		AgreementSource:   "https://gist.github.com/test",
		AdminIDs:          []int64{7},
		ExemptUsers:       []string{"*[bot]"},
	}
	s, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.Agreement("v1", "# Test agreement", "https://gist.github.com/test"); err != nil {
		t.Fatal(err)
	}
	if err = s.BootstrapRepositories(c.Repositories, c.RepositoryID, c.AgreementVersion, c.AgreementSource, storage.Policy{Users: c.ExemptUsers, PublicOrgs: c.ExemptPublicOrgs}); err != nil {
		t.Fatal(err)
	}
	return newApp(c, s)
}

// loginFixture stores a synthetic test session and returns its browser cookie.
func loginFixture(t *testing.T, a *App, id int64) *http.Cookie {
	t.Helper()
	token := "test-session"
	_, err := a.s.Exec("INSERT INTO sessions VALUES(?,?,?,?,?)", hash(token), id, "maintainer", "csrf-test", time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "cla_session", Value: token}
}

// TestSigningAndSubpath verifies signing and subpath.
func TestSigningAndSubpath(t *testing.T) {
	a := fixture(t)
	cookie := loginFixture(t, a, 7)
	h := a.routes()
	r := httptest.NewRequest("GET", "/cla/", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `action="/cla/sign"`) {
		t.Fatalf("home: %d %s", w.Code, w.Body)
	}
	for _, test := range []struct {
		csrf, version, accept string
		want                  int
	}{{"wrong", "v1", "yes", 403}, {"csrf-test", "old", "yes", 400}, {"csrf-test", "v1", "", 400}, {"csrf-test", "v1", "yes", 303}} {
		form := url.Values{"csrf": {test.csrf}, "version": {test.version}, "accept": {test.accept}}
		r = httptest.NewRequest("POST", "/cla/sign", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookie)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != test.want {
			t.Fatalf("sign: want %d got %d: %s", test.want, w.Code, w.Body)
		}
	}
	ok, err := a.s.Signed(7, "v1")
	if err != nil || !ok {
		t.Fatalf("signature not persisted: %v", err)
	}
	ok, err = a.s.Signed(7, "v2")
	if err != nil || ok {
		t.Fatal("signature leaked across agreement versions")
	}
	r = httptest.NewRequest("GET", "/other/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("path escaped: %d", w.Code)
	}
}

// TestImmutableAgreementAndAtomicImport verifies immutable agreement and atomic import.
func TestImmutableAgreementAndAtomicImport(t *testing.T) {
	a := fixture(t)
	if err := a.s.Agreement("v1", "Changed text", ""); err == nil {
		t.Fatal("accepted changed text under same version")
	}
	path := filepath.Join(t.TempDir(), "import.json")
	raw := `{"repository":"caddyserver/caddy","gistVersion":"v1","signatures":[{"userId":"42","user":"alice","created_at":"2020-01-01T00:00:00Z","gist_version":"v1","custom_fields":"original evidence"},{"userId":"43","user":"bob","created_at":"2020-01-01T00:00:00Z","revoked_at":"2021-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		n, err := a.s.ImportFile(path, "v1", "caddyserver/caddy", a.c.AgreementSource)
		if err != nil || n != 2 {
			t.Fatalf("import: %d %v", n, err)
		}
	}
	xs, err := a.s.Signatures()
	if err != nil || len(xs) != 2 {
		t.Fatalf("idempotency: %d %v", len(xs), err)
	}
	if ok, err := a.s.Signed(42, "v1"); err != nil || !ok {
		t.Fatal("import not recognized")
	}
	if ok, err := a.s.Signed(43, "v1"); err != nil || ok {
		t.Fatal("revoked import was accepted")
	}
	found := false
	for _, x := range xs {
		if strings.Contains(string(x.Raw), "original evidence") {
			found = true
		}
	}
	if !found {
		t.Fatal("lost raw evidence")
	}
	bad := `[{"userId":99,"user":"valid","created_at":"2020-01-01T00:00:00Z"},{"user":"no-id"}]`
	_ = os.WriteFile(path, []byte(bad), 0600)
	if _, err = a.s.ImportFile(path, "v1", "caddyserver/caddy", a.c.AgreementSource); err == nil {
		t.Fatal("accepted invalid import")
	}
	xs, _ = a.s.Signatures()
	if len(xs) != 2 {
		t.Fatal("partial import committed")
	}
}

// TestWildcardBotLiteral verifies wildcard bot literal.
func TestWildcardBotLiteral(t *testing.T) {
	for _, x := range []struct {
		user string
		want bool
	}{{"dependabot[bot]", true}, {"renovate[bot]", true}, {"robot", false}, {"bot", false}, {"somebodyb", false}} {
		if got := wildcard("*[bot]", x.user); got != x.want {
			t.Errorf("%s: got %v", x.user, got)
		}
	}
}

// TestSignedWebhookIsDurableAndDeduplicated verifies signed webhook is durable and deduplicated.
func TestSignedWebhookIsDurableAndDeduplicated(t *testing.T) {
	a := fixture(t)
	a.c.WebhookSecret = "secret"
	h := a.routes()
	b := `{"action":"opened","number":10,"repository":{"full_name":"caddyserver/caddy"},"installation":{"id":12}}`
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(b))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	for _, signature := range []string{"invalid", sig, sig} {
		r := httptest.NewRequest("POST", "/cla/webhooks/github", strings.NewReader(b))
		r.Header.Set("X-Hub-Signature-256", signature)
		r.Header.Set("X-GitHub-Delivery", "delivery")
		r.Header.Set("X-GitHub-Event", "pull_request")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 202
		if signature == "invalid" {
			want = 401
		}
		if w.Code != want {
			t.Fatalf("webhook: %d %s", w.Code, w.Body)
		}
	}
	var count int
	_ = a.s.QueryRow("SELECT count(*) FROM jobs").Scan(&count)
	if count != 1 {
		t.Fatalf("expected one job got %d", count)
	}
	if err := a.s.SignRepository(42, "alice", "caddyserver/caddy", "v1"); err != nil {
		t.Fatal(err)
	}
	var eligible int
	if err := a.s.QueryRow("SELECT count(*) FROM initial_pr_checks WHERE checked=0").Scan(&eligible); err != nil || eligible != 1 {
		t.Fatalf("opened webhook must authorize exactly one initial check: %d %v", eligible, err)
	}
	var generation int
	_ = a.s.QueryRow("SELECT generation FROM jobs").Scan(&generation)
	if generation != 1 {
		t.Fatalf("signing did not refresh pending work: %d", generation)
	}
}

// TestAdminRequiresWritePermission verifies admin requires write permission.
func TestAdminRequiresWritePermission(t *testing.T) {
	a := fixture(t)
	cookie := loginFixture(t, a, 99)
	h := a.routes()
	r := httptest.NewRequest("GET", "/cla/admin/export", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("non-admin export: %d", w.Code)
	}
}

// appKey generates a test-only application signing key without using production credentials.
func appKey(t *testing.T, a *App) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "app.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err = os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	a.c.AppID = "123"
	a.c.PrivateKey = file
	a.gh.c = a.c
}

// TestGitHubReconcileAndDynamicAdmin verifies git hub reconcile and dynamic admin.
func TestGitHubReconcileAndDynamicAdmin(t *testing.T) {
	a := fixture(t)
	appKey(t, a)
	var statuses, comments int
	state := ""
	message := "test"
	linkedAuthor := true
	locked := false
	commentBody := ""
	refreshDuringStatus := false
	permission := "write"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/caddyserver/caddy/installation":
			fmt.Fprint(w, `{"id":12}`)
		case "/app/installations/12/access_tokens":
			fmt.Fprint(w, `{"token":"installation-token"}`)
		case "/repos/caddyserver/caddy/collaborators/alice/permission":
			fmt.Fprintf(w, `{"permission":%q,"user":{"id":42}}`, permission)
		case "/repos/caddyserver/caddy/pulls/10":
			fmt.Fprintf(w, `{"state":"open","locked":%t,"commits":1,"user":{"id":42,"login":"alice"},"head":{"sha":"abc"}}`, locked)
		case "/repos/caddyserver/caddy/pulls/10/commits":
			if linkedAuthor {
				fmt.Fprintf(w, `[{"sha":"abc123def4567890","author":{"id":42,"login":"alice"},"committer":{"id":42,"login":"alice"},"commit":{"message":%q}}]`, message)
			} else {
				fmt.Fprint(w, `[{"sha":"abc123def4567890","author":null,"commit":{"message":"test","author":{"email":"unlinked@example.test"}}}]`)
			}
		case "/repos/caddyserver/caddy/statuses/abc":
			statuses++
			if refreshDuringStatus {
				refreshDuringStatus = false
				if err := a.enqueue("caddyserver/caddy", 10, 12); err != nil {
					t.Error(err)
				}
			}
			var v map[string]string
			_ = json.NewDecoder(r.Body).Decode(&v)
			state = v["state"]
			fmt.Fprint(w, `{}`)
		case "/repos/caddyserver/caddy/issues/comments/99":
			comments++
			var comment map[string]string
			if err := json.NewDecoder(r.Body).Decode(&comment); err != nil {
				t.Error(err)
			}
			commentBody = comment["body"]
			fmt.Fprint(w, `{}`)
		case "/repos/caddyserver/caddy/issues/10/comments":
			if r.Method == "GET" {
				if commentBody == "" {
					fmt.Fprint(w, `[]`)
				} else {
					_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 99, "body": commentBody, "performed_via_github_app": map[string]int{"id": 123}}})
				}
			} else {
				comments++
				var comment map[string]string
				if err := json.NewDecoder(r.Body).Decode(&comment); err != nil {
					t.Error(err)
				}
				commentBody = comment["body"]
				fmt.Fprint(w, `{}`)
			}
		default:
			http.Error(w, "unexpected "+r.URL.String(), 404)
		}
	}))
	defer server.Close()
	a.gh.api = server.URL
	if !a.gh.canAdminRepo(context.Background(), User{ID: 42, Login: "alice"}, "caddyserver/caddy") {
		t.Fatal("repo writer not recognized")
	}
	permission = "read"
	if a.gh.canAdminRepo(context.Background(), User{ID: 42, Login: "alice"}, "caddyserver/caddy") {
		t.Fatal("reader granted admin")
	}
	if _, err := a.s.Exec("INSERT INTO initial_pr_checks(repo,number) VALUES('caddyserver/caddy',10)"); err != nil {
		t.Fatal(err)
	}
	permission = "write"
	if a.gh.canAdminRepo(context.Background(), User{ID: 43, Login: "alice"}, "caddyserver/caddy") {
		t.Fatal("username/ID mismatch accepted")
	}
	if err := a.gh.reconcile(context.Background(), a.s, "caddyserver/caddy", 10, 12); err != nil {
		t.Fatal(err)
	}
	if state != "failure" {
		t.Fatal("unsigned author passed")
	}
	if err := a.s.SignRepository(42, "alice", "caddyserver/caddy", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := a.gh.reconcile(context.Background(), a.s, "caddyserver/caddy", 10, 12); err != nil {
		t.Fatal(err)
	}
	if state != "success" || statuses != 2 || comments != 2 {
		t.Fatalf("signed author: %s statuses=%d comments=%d", state, statuses, comments)
	}
	if strings.Contains(commentBody, "[Recheck this PR]") {
		t.Fatal("resolved reminder retains recheck link")
	}
	locked = true
	previousComments := comments
	if err := a.gh.reconcile(context.Background(), a.s, "caddyserver/caddy", 10, 12); err != nil {
		t.Fatal(err)
	}
	if state != "success" || comments != previousComments {
		t.Fatal("locked PR must receive a status without a comment")
	}
	locked = false
	linkedAuthor = false
	if err := a.gh.reconcile(context.Background(), a.s, "caddyserver/caddy", 10, 12); err != nil {
		t.Fatal(err)
	}
	if state != "failure" || !strings.Contains(commentBody, "https://github.com/settings/emails") || !strings.Contains(commentBody, "abc123def456") {
		t.Fatalf("unlinked email warning missing: %s", commentBody)
	}
	linkedAuthor = true
	message = "test\n\nCo-authored-by: Unknown <unknown@example.test>"
	if err := a.gh.reconcile(context.Background(), a.s, "caddyserver/caddy", 10, 12); err != nil {
		t.Fatal(err)
	}
	if state != "success" {
		t.Fatal("co-author trailers must not affect signed authors")
	}
	message = "test"
	if err := a.enqueue("caddyserver/caddy", 10, 12); err != nil {
		t.Fatal(err)
	}
	refreshDuringStatus = true
	a.runJob(context.Background())
	var remaining int
	if err := a.s.QueryRow("SELECT count(*) FROM jobs").Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("lost concurrent recheck: count=%d error=%v", remaining, err)
	}

}

// TestOAuthNoScopesAndSingleUseState verifies o auth no scopes and single use state.
func TestOAuthNoScopesAndSingleUseState(t *testing.T) {
	a := fixture(t)
	a.c.OAuthClientID = "client"
	a.c.OAuthSecret = "secret"
	r := httptest.NewRequest("GET", "/cla/auth/github", nil)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "github.com" || u.Query().Get("scope") != "" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("unexpected OAuth parameters", u)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != "/cla/" {
		t.Fatal("cookie is not scoped to subpath")
	}
	state := u.Query().Get("state")
	for range 2 {
		r = httptest.NewRequest("GET", "/cla/auth/github/callback?state="+state, nil)
		r.AddCookie(cookies[0])
		w = httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("invalid callback accepted: %d", w.Code)
		}
	}
}

// TestAdminPolicyAndHistory verifies admin policy and history.
func TestAdminPolicyAndHistory(t *testing.T) {
	a := fixture(t)
	cookie := loginFixture(t, a, 7)
	if err := a.s.SignRepository(42, "alice", "caddyserver/caddy", "v1"); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf": {"csrf-test"}, "users": {"*[bot], trusted"}, "orgs": {"github"}}
	r := httptest.NewRequest("POST", "/cla/admin/settings", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	cfg, err := a.s.Repository("caddyserver/caddy")
	p := cfg.Policy
	if err != nil || len(p.Users) != 2 {
		t.Fatalf("policy: %+v %v", p, err)
	}
	for _, path := range []string{
		"/cla/admin",
		"/cla/admin/history?q=alice",
		"/cla/admin/export",
		"/cla/admin/export?format=csv",
	} {
		r = httptest.NewRequest("GET", path, nil)
		r.AddCookie(cookie)
		w = httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
}

// TestLegacyRepositoryAndIdentityPreservation verifies legacy repository and identity preservation.
func TestLegacyRepositoryAndIdentityPreservation(t *testing.T) {
	a := fixture(t)
	path := filepath.Join(t.TempDir(), "legacy.json")
	raw := `[{"userId":"42","user":"alice","owner":"mholt","repo":"caddy","repoId":"29207621","gist_version":"v1","created_at":"2016-01-01T00:00:00Z"},{"user":"historical","owner":"mholt","repo":"caddy","repoId":"29207621","created_at":"2015-01-01T00:00:00Z","revoked":false}]`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.s.ImportFile(path, "v1", "caddyserver/caddy", a.c.AgreementSource); err == nil {
		t.Fatal("repository alias accepted without ID verification")
	}
	for range 2 {
		n, err := a.s.ImportFile(path, "v1", "caddyserver/caddy", a.c.AgreementSource, "29207621")
		if err != nil || n != 2 {
			t.Fatalf("legacy import: %d %v", n, err)
		}
	}
	xs, err := a.s.Legacy()
	if err != nil || len(xs) != 1 || xs[0].ResolvedID != 0 || !strings.Contains(string(xs[0].Raw), "historical") {
		t.Fatalf("legacy evidence lost: %+v %v", xs, err)
	}
	if ok, _ := a.s.Signed(99, "v1"); ok {
		t.Fatal("unresolved legacy identity authorized")
	}
	cookie := loginFixture(t, a, 7)
	r := httptest.NewRequest("GET", "/cla/admin/legacy", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "historical") {
		t.Fatalf("legacy admin view: %d %s", w.Code, w.Body)
	}
}

// TestLatestRevocationSupersedesEarlierSignature verifies latest revocation supersedes earlier signature.
func TestLatestRevocationSupersedesEarlierSignature(t *testing.T) {
	a := fixture(t)
	tx, err := a.s.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []storage.Signature{
		{ID: 42, Login: "alice", Version: "v1", SignedAt: "2020-01-01T00:00:00Z", Origin: "test", Raw: json.RawMessage(`{}`)},
		{ID: 42, Login: "alice", Version: "v1", SignedAt: "2021-01-01T00:00:00Z", RevokedAt: "2021-02-01T00:00:00Z", Origin: "test", Raw: json.RawMessage(`{}`)},
	} {
		if err = storage.InsertSignature(tx, x); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.s.Signed(42, "v1"); err != nil || ok {
		t.Fatal("older signature bypassed revocation")
	}
}

// TestSQLiteBackup verifies s q lite backup.
func TestSQLiteBackup(t *testing.T) {
	a := fixture(t)
	if err := a.s.SignRepository(42, "alice", "caddyserver/caddy", "v1"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "backup.db")
	if _, err := a.s.Exec("VACUUM INTO ?", path); err != nil {
		t.Fatal(err)
	}
	restored, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if ok, err := restored.Signed(42, "v1"); err != nil || !ok {
		t.Fatal("backup did not preserve signature")
	}
}

// TestRootHosting verifies the agreement, OAuth redirects and cookies work without a route prefix.
func TestRootHosting(t *testing.T) {
	a := fixture(t)
	a.c.BasePath = ""
	a.c.BaseURL = "http://localhost:8080"
	a.c.OAuthClientID = "test-client"
	a.c.OAuthSecret = "test-secret"
	h := a.routes()
	for _, path := range []string{"/", "/healthz"} {
		req := httptest.NewRequest("GET", path, nil)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, response.Code)
		}
		if path == "/" && !strings.Contains(response.Body.String(), `href="/auth/github?next=`) {
			t.Fatal("root page contains an incorrect sign-in link")
		}
	}
	req := httptest.NewRequest("GET", "/auth/github", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("redirect_uri") != "http://localhost:8080/auth/github/callback" {
		t.Fatal("incorrect root OAuth callback", location)
	}
	if cookies := response.Result().Cookies(); len(cookies) != 1 || cookies[0].Path != "/" {
		t.Fatal("incorrect root cookie path")
	}
}

// TestFormOriginPolicy preserves same-site browser origins and rejects null or foreign origins.
func TestFormOriginPolicy(t *testing.T) {
	a := fixture(t)
	cookie := loginFixture(t, a, 7)
	req := httptest.NewRequest("GET", "/cla/", nil)
	res := httptest.NewRecorder()
	a.routes().ServeHTTP(res, req)
	if res.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("form pages must preserve same-origin POST origins")
	}
	for _, origin := range []string{"null", "https://untrusted.example", "http://localhost:8080"} {
		form := url.Values{"csrf": {"csrf-test"}, "accept": {"yes"}, "version": {"v1"}, "repo": {"caddyserver/caddy"}}
		req = httptest.NewRequest("POST", "/cla/sign", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		req.AddCookie(cookie)
		res = httptest.NewRecorder()
		a.routes().ServeHTTP(res, req)
		want := 403
		if origin == "http://localhost:8080" {
			want = 303
		}
		if res.Code != want {
			t.Fatalf("origin %s: got %d want %d", origin, res.Code, want)
		}
	}
}
