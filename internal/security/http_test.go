package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ansh44233/mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

func TestBearerMiddlewareAttachesVerifiedPrincipal(t *testing.T) {
	verifier := func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		if token != "valid-token" {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{
			UserID:     "user-42",
			Scopes:     []string{"tools:read"},
			Expiration: time.Now().Add(time.Hour),
		}, nil
	}
	middleware, err := NewBearerMiddleware(verifier, nil, func(_ context.Context, info *auth.TokenInfo) (Principal, error) {
		return Principal{
			ID: info.UserID, TenantID: "tenant-7", MaxRisk: tools.RiskRead,
			AllowedProviders: map[string]struct{}{"github": {}},
		}, nil
	})
	if err != nil {
		t.Fatalf("create middleware: %v", err)
	}

	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			t.Fatal("principal missing from request context")
		}
		if !principal.Authenticated || principal.Authentication != "bearer" || principal.ID != "user-42" || principal.TenantID != "tenant-7" {
			t.Fatalf("unexpected principal: %+v", principal)
		}
		if err := (Authorizer{}).Authorize(r.Context(), tools.Definition{ID: "github_repo_read", Provider: "github", Risk: tools.RiskRead}); err != nil {
			t.Fatalf("verified principal rejected: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("handler status=%d called=%v body=%s", rec.Code, called, rec.Body.String())
	}
}

func TestBearerMiddlewareRejectsInvalidToken(t *testing.T) {
	verifier := func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return nil, auth.ErrInvalidToken
	}
	middleware, err := NewBearerMiddleware(verifier, nil, func(context.Context, *auth.TokenInfo) (Principal, error) {
		t.Fatal("resolver must not run for invalid token")
		return Principal{}, nil
	})
	if err != nil {
		t.Fatalf("create middleware: %v", err)
	}
	called := false
	handler := middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("status=%d handler called=%v", rec.Code, called)
	}
}

func TestBearerMiddlewareRejectsMissingUserIdentity(t *testing.T) {
	verifier := func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return &auth.TokenInfo{Expiration: time.Now().Add(time.Hour)}, nil
	}
	middleware, err := NewBearerMiddleware(verifier, nil, func(context.Context, *auth.TokenInfo) (Principal, error) {
		t.Fatal("resolver must not run without token user ID")
		return Principal{}, nil
	})
	if err != nil {
		t.Fatalf("create middleware: %v", err)
	}
	handler := middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run without user identity")
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", rec.Code)
	}
}

func TestBearerMiddlewareRequiresDependencies(t *testing.T) {
	if _, err := NewBearerMiddleware(nil, nil, func(context.Context, *auth.TokenInfo) (Principal, error) {
		return Principal{}, nil
	}); err == nil {
		t.Fatal("expected missing verifier error")
	}
	if _, err := NewBearerMiddleware(func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return nil, nil
	}, nil, nil); err == nil {
		t.Fatal("expected missing resolver error")
	}
}
