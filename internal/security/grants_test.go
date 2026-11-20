package security

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ansh44233/mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

func TestStaticPrincipalResolverUsesTrustedSubjectGrants(t *testing.T) {
	grants := map[string]PrincipalGrant{
		"issuer|subject-123": {
			TenantID:         "tenant-a",
			MaxRisk:          tools.RiskRead,
			AllowedTools:     []string{"github_repository_get", "platform_status"},
			AllowedProviders: []string{"github", "platform"},
			AllowedResources: map[string][]string{
				"github":  {"acme/demo"},
				"platform": {"platform"},
			},
		},
	}
	resolve, err := NewStaticPrincipalResolver(grants)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	principal, err := resolve(context.Background(), &auth.TokenInfo{UserID: "issuer|subject-123"})
	if err != nil {
		t.Fatalf("resolve provisioned subject: %v", err)
	}
	if principal.ID != "issuer|subject-123" || principal.TenantID != "tenant-a" || !principal.Authenticated {
		t.Fatalf("unexpected principal identity: %#v", principal)
	}
	if _, ok := principal.AllowedResources["github"]["acme/demo"]; !ok {
		t.Fatal("expected explicit GitHub repository scope")
	}

	delete(principal.AllowedTools, "github_repository_get")
	delete(principal.AllowedResources["github"], "acme/demo")
	again, err := resolve(context.Background(), &auth.TokenInfo{UserID: "issuer|subject-123"})
	if err != nil {
		t.Fatalf("resolve subject again: %v", err)
	}
	if _, ok := again.AllowedTools["github_repository_get"]; !ok {
		t.Fatal("resolver leaked mutable tool scopes between requests")
	}
	if _, ok := again.AllowedResources["github"]["acme/demo"]; !ok {
		t.Fatal("resolver leaked mutable resource scopes between requests")
	}

	if _, err := resolve(context.Background(), &auth.TokenInfo{UserID: "unprovisioned"}); err == nil {
		t.Fatal("unprovisioned subject must be denied")
	}
	if _, err := resolve(context.Background(), nil); err == nil {
		t.Fatal("missing token identity must be denied")
	}
}

func TestStaticPrincipalResolverRequiresExplicitLeastPrivilegeScopes(t *testing.T) {
	base := PrincipalGrant{
		TenantID:         "tenant-a",
		MaxRisk:          tools.RiskRead,
		AllowedTools:     []string{"github_repository_get"},
		AllowedProviders: []string{"github"},
		AllowedResources: map[string][]string{"github": {"acme/demo"}},
	}
	tests := map[string]PrincipalGrant{
		"missing tools": {
			TenantID: "tenant-a", MaxRisk: tools.RiskRead,
			AllowedProviders: []string{"github"},
			AllowedResources: map[string][]string{"github": {"acme/demo"}},
		},
		"missing providers": {
			TenantID: "tenant-a", MaxRisk: tools.RiskRead,
			AllowedTools: []string{"github_repository_get"},
			AllowedResources: map[string][]string{"github": {"acme/demo"}},
		},
		"missing resources": {
			TenantID: "tenant-a", MaxRisk: tools.RiskRead,
			AllowedTools: []string{"github_repository_get"},
			AllowedProviders: []string{"github"},
		},
		"empty resource list": {
			TenantID: "tenant-a", MaxRisk: tools.RiskRead,
			AllowedTools: []string{"github_repository_get"},
			AllowedProviders: []string{"github"},
			AllowedResources: map[string][]string{"github": {}},
		},
	}
	for name, grant := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewStaticPrincipalResolver(map[string]PrincipalGrant{"subject": grant}); err == nil {
				t.Fatal("expected incomplete grant to be rejected")
			}
		})
	}
	if _, err := NewStaticPrincipalResolver(map[string]PrincipalGrant{"subject": base}); err != nil {
		t.Fatalf("valid grant rejected: %v", err)
	}
}

func TestLoadPrincipalGrantsRejectsUnknownAndTrailingFields(t *testing.T) {
	dir := t.TempDir()
	valid := `{
		"subject-123": {
			"tenant_id": "tenant-a",
			"max_risk": "read",
			"allowed_tools": ["github_repository_get"],
			"allowed_providers": ["github"],
			"allowed_resources": {"github": ["acme/demo"]}
		}
	}`
	path := filepath.Join(dir, "grants.json")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	grants, err := LoadPrincipalGrants(path)
	if err != nil {
		t.Fatalf("load valid grants: %v", err)
	}
	if len(grants) != 1 || grants["subject-123"].TenantID != "tenant-a" {
		t.Fatalf("unexpected loaded grants: %#v", grants)
	}

	for name, data := range map[string]string{
		"unknown field": strings.Replace(valid, `"tenant_id": "tenant-a"`, `"tenant_id": "tenant-a", "is_admin": true`, 1),
		"trailing JSON": valid + `{}`,
		"empty":         `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPrincipalGrants(path); err == nil {
				t.Fatal("expected invalid grant document to be rejected")
			}
		})
	}
}

func TestPrincipalGrantJSONShape(t *testing.T) {
	var grant PrincipalGrant
	if err := json.Unmarshal([]byte(`{"tenant_id":"tenant-a","max_risk":"read","allowed_tools":["platform_status"],"allowed_providers":["platform"],"allowed_resources":{"platform":["platform"]}}`), &grant); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStaticPrincipalResolver(map[string]PrincipalGrant{"subject": grant}); err != nil {
		t.Fatalf("JSON grant rejected: %v", err)
	}
}
