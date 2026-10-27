package app

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestLegacyRevocationForm requires an authorized session, CSRF, confirmation and a reason.
func TestLegacyRevocationForm(t *testing.T) {
	a := fixture(t)
	if _, err := a.s.ImportJSON([]byte(`[{"user":"old-name","created_at":"2016-01-01T00:00:00Z"}]`), "v1", "caddyserver/caddy", ""); err != nil {
		t.Fatal(err)
	}
	records, _ := a.s.ScopedLegacy("caddyserver/caddy")
	cookie := loginFixture(t, a, 7)
	for _, tc := range []struct {
		csrf, confirm, reason string
		want                  int
	}{
		{"bad", "yes", "unverified", 403},
		{"csrf-test", "", "unverified", 400},
		{"csrf-test", "yes", "", 409},
		{"csrf-test", "yes", "Cannot verify identity", 303},
	} {
		form := url.Values{"csrf": {tc.csrf}, "confirm": {tc.confirm}, "reason": {tc.reason}, "repo": {"caddyserver/caddy"}, "key": {records[0].Key}}
		req := httptest.NewRequest("POST", "/cla/admin/legacy/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("got %d want %d: %s", w.Code, tc.want, w.Body)
		}
	}
	req := httptest.NewRequest("GET", "/cla/admin/legacy?repo=caddyserver%2Fcaddy", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "Cannot verify identity") || strings.Contains(w.Body.String(), "Link verified identity") {
		t.Fatal("revoked record still linkable in UI")
	}
}

// TestLegacyFieldsAreNotCredentialInputs verifies the form avoids login naming and requests password-manager exclusion.
func TestLegacyFieldsAreNotCredentialInputs(t *testing.T) {
	a := fixture(t)
	if _, err := a.s.ImportJSON([]byte(`[{"user":"old-name","created_at":"2016-01-01T00:00:00Z"}]`), "v1", "caddyserver/caddy", ""); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/cla/admin/legacy?repo=caddyserver%2Fcaddy", nil)
	req.AddCookie(loginFixture(t, a, 7))
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, req)
	body := w.Body.String()
	if strings.Contains(body, `name="login"`) || !strings.Contains(body, `name="github_account"`) || !strings.Contains(body, `autocomplete="off" data-1p-ignore="true" data-lpignore="true"`) {
		t.Fatal("legacy identity field looks like a credential input")
	}
	if !strings.Contains(body, "Revoke historical evidence") {
		t.Fatal("missing revocation action")
	}
}
