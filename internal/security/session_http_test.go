package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionMiddlewareRequiresSessionAndCSRFForWrites(t *testing.T) {
	store, err := NewSessionStore(4, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Create(testSessionPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	middleware, err := NewSessionMiddleware(store, "https://console.example")
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.ID != "subject-1" {
			t.Error("session principal was not attached to request context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "https://console.example/api/v1/status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || called != 0 {
		t.Fatalf("request without cookie: status=%d called=%d", response.Code, called)
	}

	request = httptest.NewRequest(http.MethodPost, "https://console.example/api/v1/approvals/123/decision", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName(), Value: session.ID})
	request.Header.Set("Origin", "https://console.example")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || called != 0 {
		t.Fatalf("write without CSRF token: status=%d called=%d", response.Code, called)
	}

	request = httptest.NewRequest(http.MethodPost, "https://console.example/api/v1/approvals/123/decision", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName(), Value: session.ID})
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("X-CSRF-Token", session.CSRFToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || called != 0 {
		t.Fatalf("cross-origin write: status=%d called=%d", response.Code, called)
	}

	request = httptest.NewRequest(http.MethodPost, "https://console.example/api/v1/approvals/123/decision", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName(), Value: session.ID})
	request.Header.Set("Origin", "https://console.example")
	request.Header.Set("X-CSRF-Token", session.CSRFToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || called != 1 {
		t.Fatalf("valid write: status=%d called=%d", response.Code, called)
	}
}
