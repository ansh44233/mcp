package security

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ansh44233/mcp/internal/tools"
)

func TestAuthorizerRequiresPrincipal(t *testing.T) {
	err := (Authorizer{}).Authorize(context.Background(), tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskRead})
	if err == nil || !strings.Contains(err.Error(), "missing request principal") {
		t.Fatalf("expected missing-principal denial, got %v", err)
	}
}

func TestAuthorizerRequiresAuthenticatedPrincipalByDefault(t *testing.T) {
	ctx := WithPrincipal(context.Background(), Principal{
		ID: "local", TenantID: "local", Authentication: "local", MaxRisk: tools.RiskRead,
	})
	err := (Authorizer{}).Authorize(ctx, tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskRead})
	if err == nil || !strings.Contains(err.Error(), "unauthenticated principal") {
		t.Fatalf("expected unauthenticated denial, got %v", err)
	}
}

func TestAuthorizerAllowsExplicitLocalReadOnlyPrincipal(t *testing.T) {
	ctx := WithPrincipal(context.Background(), Principal{
		ID: "local", TenantID: "local", Authentication: "local", MaxRisk: tools.RiskRead,
	})
	err := (Authorizer{AllowLocalPrincipal: true}).Authorize(ctx, tools.Definition{
		ID: "repo_read", Provider: "github", Risk: tools.RiskRead,
	})
	if err != nil {
		t.Fatalf("explicit local read principal rejected: %v", err)
	}
}

func TestAuthorizerEnforcesToolProviderAndRiskScopes(t *testing.T) {
	principal := Principal{ID: "user-1", TenantID: "tenant-a", Authenticated: true, Authentication: "test", MaxRisk: tools.RiskRead, AllowedTools: map[string]struct{}{"repo_read": {}}, AllowedProviders: map[string]struct{}{"github": {}}, AllowedResources: map[string]map[string]struct{}{"github": {"owner/repo": {}}}}
	ctx := WithPrincipal(context.Background(), principal)
	authorizer := Authorizer{}

	tests := []struct {
		name       string
		definition tools.Definition
		want       string
	}{
		{"allowed", tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskRead}, ""},
		{"tool scope", tools.Definition{ID: "other_read", Provider: "github", Risk: tools.RiskRead}, "tool scope"},
		{"provider scope", tools.Definition{ID: "repo_read", Provider: "gitlab", Risk: tools.RiskRead}, "provider scope"},
		{"risk ceiling", tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskWrite}, "exceeds principal maximum"},
		{"unknown risk", tools.Definition{ID: "repo_read", Provider: "github", Risk: "unknown"}, "unknown risk"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := authorizer.AuthorizeRequest(ctx, test.definition, json.RawMessage(`{"owner":"owner","repo":"repo"}`))
			if test.want == "" && err != nil {
				t.Fatalf("unexpected denial: %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("expected %q denial, got %v", test.want, err)
			}
		})
	}
}

func TestAuthorizerRequiresExplicitResourceScopeForAuthenticatedPrincipal(t *testing.T) {
	ctx := WithPrincipal(context.Background(), Principal{
		ID: "user-1", TenantID: "tenant-a", Authenticated: true,
		Authentication: "test", MaxRisk: tools.RiskRead,
	})
	err := (Authorizer{}).AuthorizeRequest(ctx,
		tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskRead},
		json.RawMessage(`{"owner":"owner","repo":"repo"}`))
	if err == nil || !strings.Contains(err.Error(), "no explicit resource scope") {
		t.Fatalf("expected fail-closed resource-scope denial, got %v", err)
	}
}

func TestWithPrincipalCopiesScopeMaps(t *testing.T) {
	toolsScope := map[string]struct{}{"repo_read": {}}
	ctx := WithPrincipal(context.Background(), Principal{ID: "user-1", TenantID: "tenant-a", Authenticated: true, Authentication: "test", MaxRisk: tools.RiskRead, AllowedTools: toolsScope})
	toolsScope["other_read"] = struct{}{}
	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("principal missing from context")
	}
	if _, ok := principal.AllowedTools["other_read"]; ok {
		t.Fatal("context principal scope changed after caller mutation")
	}
	principal.AllowedTools["mutated"] = struct{}{}
	again, _ := PrincipalFromContext(ctx)
	if _, ok := again.AllowedTools["mutated"]; ok {
		t.Fatal("returned principal exposed internal scope map")
	}
}

func TestPrincipalValidation(t *testing.T) {
	err := (Principal{ID: "user-1", TenantID: "tenant-a", Authenticated: true, MaxRisk: tools.RiskRead}).Validate()
	if err == nil || !strings.Contains(err.Error(), "authentication method") {
		t.Fatalf("expected missing authentication method error, got %v", err)
	}
}

func TestLocalPrincipalIsExplicitlyReadOnly(t *testing.T) {
	principal := LocalPrincipal()
	if principal.ID != "local" || principal.TenantID != "local" || principal.Authenticated {
		t.Fatalf("unexpected local identity: %#v", principal)
	}
	if principal.MaxRisk != tools.RiskRead {
		t.Fatalf("local principal max risk = %q, want read", principal.MaxRisk)
	}
	if err := principal.Validate(); err != nil {
		t.Fatalf("local principal should validate: %v", err)
	}

	ctx := WithPrincipal(context.Background(), principal)
	authorizer := Authorizer{AllowLocalPrincipal: true}
	if err := authorizer.Authorize(ctx, tools.Definition{
		ID: "repo_read", Provider: "github", Risk: tools.RiskRead,
	}); err != nil {
		t.Fatalf("local read should be allowed: %v", err)
	}
	if err := authorizer.Authorize(ctx, tools.Definition{
		ID: "repo_write", Provider: "github", Risk: tools.RiskWrite,
	}); err == nil {
		t.Fatal("local principal must not authorize write tools")
	}
}

func TestAuthorizerEnforcesGitHubRepositoryScopes(t *testing.T) {
	principal := Principal{
		ID: "user-1", TenantID: "tenant-a", Authenticated: true,
		Authentication: "test", MaxRisk: tools.RiskRead,
		AllowedResources: map[string]map[string]struct{}{
			"github": {"ansh44233/mcp": {}},
		},
	}
	ctx := WithPrincipal(context.Background(), principal)
	authorizer := Authorizer{}
	definition := tools.Definition{ID: "github_repository_get", Provider: "github", Risk: tools.RiskRead}

	tests := []struct {
		name string
		args string
		want string
	}{
		{"allowed repository", `{"owner":"Ansh44233","repo":"MCP"}`, ""},
		{"different repository", `{"owner":"someone","repo":"private"}`, "outside principal resource scope"},
		{"missing repository", `{"owner":"ansh44233"}`, "invalid GitHub resource identity"},
		{"malformed arguments", `not-json`, "cannot determine GitHub resource"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := authorizer.AuthorizeRequest(ctx, definition, json.RawMessage(test.args))
			if test.want == "" && err != nil {
				t.Fatalf("unexpected denial: %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("expected %q denial, got %v", test.want, err)
			}
		})
	}
}

func TestAuthorizerFailsClosedForUnscopedProvider(t *testing.T) {
	ctx := WithPrincipal(context.Background(), Principal{
		ID: "user-1", TenantID: "tenant-a", Authenticated: true,
		Authentication: "test", MaxRisk: tools.RiskRead,
		AllowedResources: map[string]map[string]struct{}{"github": {"owner/repo": {}}},
	})
	err := (Authorizer{}).AuthorizeRequest(ctx,
		tools.Definition{ID: "repo_read", Provider: "gitlab", Risk: tools.RiskRead},
		json.RawMessage(`{"owner":"owner","repo":"repo"}`))
	if err == nil || !strings.Contains(err.Error(), "resource scoping is not implemented") {
		t.Fatalf("expected unsupported provider resource scope denial, got %v", err)
	}
}

func TestWithPrincipalCopiesResourceScopes(t *testing.T) {
	resources := map[string]map[string]struct{}{"github": {"owner/repo": {}}}
	ctx := WithPrincipal(context.Background(), Principal{
		ID: "user-1", TenantID: "tenant-a", Authenticated: true,
		Authentication: "test", MaxRisk: tools.RiskRead, AllowedResources: resources,
	})
	resources["github"]["other/repo"] = struct{}{}
	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("principal missing from context")
	}
	if _, ok := principal.AllowedResources["github"]["other/repo"]; ok {
		t.Fatal("context resource scope changed after caller mutation")
	}
	principal.AllowedResources["github"]["mutated/repo"] = struct{}{}
	again, _ := PrincipalFromContext(ctx)
	if _, ok := again.AllowedResources["github"]["mutated/repo"]; ok {
		t.Fatal("returned principal exposed internal resource scope map")
	}
}
