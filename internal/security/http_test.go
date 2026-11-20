package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ansh44233/mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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


type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// This exercises the complete Streamable HTTP path: bearer verification,
// principal resolution, request-context propagation and tool authorization.
func TestBearerPrincipalReachesMCPToolExecution(t *testing.T) {
	ctx := context.Background()
	verifier := func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		if token != "integration-token" {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: "user-42", Expiration: time.Now().Add(time.Hour)}, nil
	}
	middleware, err := NewBearerMiddleware(verifier, nil, func(_ context.Context, info *auth.TokenInfo) (Principal, error) {
		return Principal{
			ID: info.UserID, TenantID: "tenant-7", MaxRisk: tools.RiskRead,
			AllowedProviders: map[string]struct{}{"github": {}},
			AllowedResources: map[string]map[string]struct{}{"github": {"acme/demo": {}}},
		}, nil
	})
	if err != nil {
		t.Fatalf("create bearer middleware: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "security-integration-test", Version: "0.0.1"}, nil)
	registry := tools.NewRegistry()
	definition := tools.Definition{
		ID: "github_repository_get", Provider: "github", Name: "repository_get",
		Description: "Read repository metadata.", Risk: tools.RiskRead,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"}},"required":["owner","repo"],"additionalProperties":false}`),
	}
	if err := registry.Register(definition); err != nil {
		t.Fatalf("register tool definition: %v", err)
	}
	executions := 0
	executor := func(_ context.Context, _ tools.Definition, _ json.RawMessage) (any, error) {
		executions++
		return map[string]any{"ok": true}, nil
	}
	authorize := (Authorizer{}).AuthorizeRequest
	if err := tools.RegisterMCPWithAuthorization(server, registry, executor, tools.ReadOnlyPolicy(), authorize); err != nil {
		t.Fatalf("register MCP tool: %v", err)
	}

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
	httpServer := httptest.NewServer(middleware(mcpHandler))
	defer httpServer.Close()

	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		request = request.Clone(request.Context())
		request.Header.Set("Authorization", "Bearer integration-token")
		return http.DefaultTransport.RoundTrip(request)
	})}
	client := mcp.NewClient(&mcp.Implementation{Name: "security-integration-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: httpClient, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatalf("connect MCP client: %v", err)
	}
	defer session.Close()

	allowed, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "github_repository_get",
		Arguments: map[string]any{"owner": "acme", "repo": "demo"},
	})
	if err != nil {
		t.Fatalf("call allowed repository: %v", err)
	}
	if allowed.IsError {
		t.Fatalf("allowed repository call returned MCP error: %+v", allowed)
	}
	if executions != 1 {
		t.Fatalf("executor called %d times, want 1", executions)
	}

	denied, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "github_repository_get",
		Arguments: map[string]any{"owner": "other", "repo": "private"},
	})
	if err != nil {
		t.Fatalf("call out-of-scope repository: %v", err)
	}
	if !denied.IsError {
		t.Fatal("out-of-scope repository call was not denied")
	}
	if executions != 1 {
		t.Fatalf("out-of-scope call reached executor; executions=%d", executions)
	}
}
