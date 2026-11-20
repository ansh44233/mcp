package security

import (
	"context"
	"fmt"
	"strings"

	"github.com/ansh44233/mcp/internal/tools"
)

// Principal is identity established by trusted server-side authentication.
// Never construct one from MCP tool arguments or other client-controlled data.
type Principal struct {
	ID               string
	TenantID         string
	Authenticated    bool
	Authentication   string
	MaxRisk          tools.Risk
	AllowedTools     map[string]struct{}
	AllowedProviders map[string]struct{}
}

type principalContextKey struct{}

// WithPrincipal attaches a server-established principal to a request context.
// The principal's scope maps are copied to prevent mutation by the caller.
func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	principal.AllowedTools = cloneSet(principal.AllowedTools)
	principal.AllowedProviders = cloneSet(principal.AllowedProviders)
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// PrincipalFromContext returns a defensive copy of the principal in ctx.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	if !ok {
		return Principal{}, false
	}
	principal.AllowedTools = cloneSet(principal.AllowedTools)
	principal.AllowedProviders = cloneSet(principal.AllowedProviders)
	return principal, true
}

// Validate rejects incomplete identities and untrusted or malformed scopes.
func (p Principal) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("principal ID is required")
	}
	if strings.TrimSpace(p.TenantID) == "" {
		return fmt.Errorf("principal tenant ID is required")
	}
	if p.Authenticated && strings.TrimSpace(p.Authentication) == "" {
		return fmt.Errorf("authentication method is required for authenticated principal")
	}
	if p.MaxRisk != tools.RiskRead && p.MaxRisk != tools.RiskWrite && p.MaxRisk != tools.RiskDestructive {
		return fmt.Errorf("principal has invalid maximum risk %q", p.MaxRisk)
	}
	for id := range p.AllowedTools {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("principal contains an empty tool scope")
		}
	}
	for provider := range p.AllowedProviders {
		if strings.TrimSpace(provider) == "" {
			return fmt.Errorf("principal contains an empty provider scope")
		}
	}
	return nil
}

func cloneSet(input map[string]struct{}) map[string]struct{} {
	if input == nil {
		return nil
	}
	output := make(map[string]struct{}, len(input))
	for key := range input {
		output[key] = struct{}{}
	}
	return output
}
