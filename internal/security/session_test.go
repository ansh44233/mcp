package security

import (
	"net/http"\n\t"net/http/httptest"
	"testing"
	"time"

	"github.com/ansh44233/mcp/internal/tools"
)

func testSessionPrincipal() Principal {
	return Principal{
		ID: "subject-1", TenantID: "tenant-1", Authenticated: true,
		Authentication: "oidc", MaxRisk: tools.RiskRead,
		AllowedTools: map[string]struct{}{"github_repository_get": {}},
		AllowedProviders: map[string]struct{}{"github": {}},
		AllowedResources: map[string]map[string]struct{}{"github": {"acme/project": {}}},
	}
}

func TestSessionStoreCreateGetAndDefensiveCopies(t *testing.T) {
	store, err := NewSessionStore(2, time.Minute)
	if err != nil { t.Fatal(err) }
	session, err := store.Create(testSessionPrincipal())
	if err != nil { t.Fatal(err) }
	if !validOpaqueToken(session.ID, sessionIDBytes) || !validOpaqueToken(session.CSRFToken, csrfTokenBytes) {
		t.Fatal("session and CSRF identifiers must be cryptographically random opaque tokens")
	}
	session.Principal.AllowedTools["injected"] = struct{}{}
	got, err := store.Get(session.ID)
	if err != nil { t.Fatal(err) }
	if _, ok := got.Principal.AllowedTools["injected"]; ok {
		t.Fatal("mutating returned session changed stored principal")
	}
	if err := ValidateCSRF(got, got.CSRFToken); err != nil { t.Fatalf("valid CSRF token rejected: %v", err) }
	if err := ValidateCSRF(got, "wrong"); err == nil { t.Fatal("invalid CSRF token accepted") }
}

func TestSessionStoreExpiresAndDeletes(t *testing.T) {
	store, err := NewSessionStore(2, time.Minute)
	if err != nil { t.Fatal(err) }
	now := time.Now()
	store.now = func() time.Time { return now }
	session, err := store.Create(testSessionPrincipal())
	if err != nil { t.Fatal(err) }
	now = now.Add(time.Minute)
	if _, err := store.Get(session.ID); err != ErrSessionExpired { t.Fatalf("expected expired session, got %v", err) }
	if _, err := store.Get(session.ID); err != ErrSessionNotFound { t.Fatalf("expired session should be removed, got %v", err) }
	store.Delete(session.ID)
}

func TestSessionStoreCapacityAndAuthentication(t *testing.T) {
	store, err := NewSessionStore(1, time.Minute)
	if err != nil { t.Fatal(err) }
	if _, err := store.Create(LocalPrincipal()); err == nil { t.Fatal("unauthenticated principal created browser session") }
	if _, err := store.Create(testSessionPrincipal()); err != nil { t.Fatal(err) }
	if _, err := store.Create(testSessionPrincipal()); err == nil { t.Fatal("session capacity was not enforced") }
}

func TestSessionCookieSecurityAttributes(t *testing.T) {
	store, err := NewSessionStore(1, time.Minute)
	if err != nil { t.Fatal(err) }
	session, err := store.Create(testSessionPrincipal())
	if err != nil { t.Fatal(err) }
	recorder := httptest.NewRecorder()
	SetSessionCookie(recorder, session, true)
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 { t.Fatalf("expected one cookie, got %d", len(cookies)) }
	cookie := cookies[0]
	if cookie.Name != SessionCookieName() || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("unsafe session cookie attributes: %#v", cookie)
	}
	clear := httptest.NewRecorder()
	ClearSessionCookie(clear, true)
	cleared := clear.Result().Cookies()[0]
	if cleared.MaxAge >= 0 || cleared.Value != "" { t.Fatalf("cookie was not expired: %#v", cleared) }
}
