package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ansh44233/mcp/internal/security"
)

func TestMountDashboardProtectsAPIRoutesWhenBearerAuthIsConfigured(t *testing.T) {
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux := http.NewServeMux()
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer verified" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	mountDashboard(mux, dashboard, middleware)

	api := httptest.NewRecorder()
	mux.ServeHTTP(api, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if api.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated dashboard API returned %d, want 401", api.Code)
	}

	authenticatedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	authenticatedRequest.Header.Set("Authorization", "Bearer verified")
	authenticated := httptest.NewRecorder()
	mux.ServeHTTP(authenticated, authenticatedRequest)
	if authenticated.Code != http.StatusNoContent {
		t.Fatalf("authenticated dashboard API returned %d, want 204", authenticated.Code)
	}

	// Static UI delivery is separate from API authorization; it contains no
	// privileged data and can load before the operator obtains an access token.
	ui := httptest.NewRecorder()
	mux.ServeHTTP(ui, httptest.NewRequest(http.MethodGet, "/", nil))
	if ui.Code != http.StatusNoContent {
		t.Fatalf("dashboard root returned %d, want 204", ui.Code)
	}
}

func TestMountDashboardKeepsLocalLoopbackAPIsAvailableWithoutOIDC(t *testing.T) {
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux := http.NewServeMux()
	mountDashboard(mux, dashboard, nil)

	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("local dashboard API returned %d, want 204", response.Code)
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"0.0.0.0:8080", false},
		{"192.0.2.10:8080", false},
		{"invalid", false},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			if got := isLoopbackAddress(tt.address); got != tt.want {
				t.Fatalf("isLoopbackAddress(%q) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}

func TestNewHTTPBearerMiddlewareRequiresCompleteConfiguration(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	middleware, configured, err := newHTTPBearerMiddleware(context.Background(), lookup)
	if err != nil || configured || middleware != nil {
		t.Fatalf("empty configuration should preserve local mode: middleware=%v configured=%v err=%v", middleware != nil, configured, err)
	}

	partial := map[string]string{"MCP_OIDC_ISSUER": "https://issuer.example"}
	_, _, err = newHTTPBearerMiddleware(context.Background(), func(key string) (string, bool) {
		value, ok := partial[key]
		return value, ok
	})
	if err == nil {
		t.Fatal("partial OIDC configuration must fail closed")
	}
}

func TestHTTPBearerMiddlewareUsesOIDCAndTrustedPrincipalGrants(t *testing.T) {
	issuer := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 issuer,
				"introspection_endpoint": issuer + "/introspect",
			})
		case "/introspect":
			user, password, ok := r.BasicAuth()
			if !ok || user != "mcp-client" || password != "test-secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			active := r.Form.Get("token") == "access-token"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": active,
				"iss":    issuer,
				"sub":    "subject-123",
				"aud":    "universal-mcp",
				"exp":    time.Now().Add(time.Hour).Unix(),
				"scope":  "mcp:invoke",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL

	grantsPath := filepath.Join(t.TempDir(), "grants.json")
	grants := `{
		"subject-123": {
			"tenant_id": "tenant-a",
			"max_risk": "read",
			"allowed_tools": ["github_repository_get"],
			"allowed_providers": ["github"],
			"allowed_resources": {"github": ["acme/demo"]}
		}
	}`
	if err := os.WriteFile(grantsPath, []byte(grants), 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"MCP_OIDC_ISSUER":        issuer,
		"MCP_OIDC_AUDIENCE":      "universal-mcp",
		"MCP_OIDC_CLIENT_ID":     "mcp-client",
		"MCP_OIDC_CLIENT_SECRET": "test-secret",
		"MCP_AUTHZ_GRANTS_FILE":  grantsPath,
	}
	middleware, configured, err := newHTTPBearerMiddleware(context.Background(), func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatalf("configure HTTP OIDC middleware: %v", err)
	}
	if !configured || middleware == nil {
		t.Fatal("expected configured OIDC middleware")
	}

	var resolved security.Principal
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		resolved, ok = security.PrincipalFromContext(r.Context())
		if !ok {
			t.Error("verified principal missing from request context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("valid bearer token returned HTTP %d: %s", response.Code, response.Body.String())
	}
	if resolved.ID != "subject-123" || resolved.TenantID != "tenant-a" || !resolved.Authenticated {
		t.Fatalf("unexpected resolved principal: %#v", resolved)
	}
	if _, ok := resolved.AllowedResources["github"]["acme/demo"]; !ok {
		t.Fatal("expected trusted GitHub resource scope")
	}

	invalidRequest := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	invalidRequest.Header.Set("Authorization", "Bearer invalid-token")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalidRequest)
	if invalidResponse.Code != http.StatusUnauthorized {
		t.Fatalf("inactive token should return HTTP 401, got %d", invalidResponse.Code)
	}
}
